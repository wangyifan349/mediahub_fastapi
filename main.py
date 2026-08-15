from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import BigInteger, Boolean, Column, DateTime, ForeignKey, Integer, String, Text, create_engine, desc, func, inspect, select, text
from sqlalchemy.orm import Session, declarative_base, joinedload, relationship, sessionmaker
from starlette.middleware.sessions import SessionMiddleware


# ==================== 基础配置 ====================
APP_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = APP_DIR / "uploads"
IMAGE_DIR = UPLOAD_DIR / "images"
VIDEO_DIR = UPLOAD_DIR / "videos"
IMAGE_DIR.mkdir(parents=True, exist_ok=True)
VIDEO_DIR.mkdir(parents=True, exist_ok=True)

MAX_UPLOAD_BYTES = 1024 * 1024 * 1024
MAX_COMMENT_LENGTH = 1000
PBKDF2_ITERATIONS = 310_000

ALLOWED_IMAGES = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".webp": "image/webp",
}
ALLOWED_VIDEOS = {
    ".mp4": "video/mp4",
    ".webm": "video/webm",
    ".mov": "video/quicktime",
    ".m4v": "video/x-m4v",
}


# ==================== 数据库与模型 ====================
# 项目规模不大，数据库配置和 3 个模型直接放在 main.py，避免来回切文件。
DATABASE_URL = f"sqlite:///{(APP_DIR / 'media.db').as_posix()}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    media_items = relationship("Media", back_populates="owner", cascade="all, delete-orphan")
    comments = relationship("Comment", back_populates="author", cascade="all, delete-orphan")


class Media(Base):
    __tablename__ = "media"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    title = Column(String(120), index=True, nullable=False)
    description = Column(Text, default="", nullable=False)
    stored_filename = Column(String(255), unique=True, nullable=False)
    original_filename = Column(String(255), nullable=False)
    media_type = Column(String(20), index=True, nullable=False)
    mime_type = Column(String(100), nullable=False)
    file_size = Column(BigInteger, default=0, nullable=False)
    views = Column(Integer, default=0, nullable=False)
    downloads = Column(Integer, default=0, nullable=False)
    is_visible = Column(Boolean, default=True, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)

    owner = relationship("User", back_populates="media_items")
    comments = relationship("Comment", back_populates="media", cascade="all, delete-orphan")


class Comment(Base):
    __tablename__ = "comments"

    id = Column(Integer, primary_key=True)
    media_id = Column(Integer, ForeignKey("media.id"), index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)

    media = relationship("Media", back_populates="comments")
    author = relationship("User", back_populates="comments")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ==================== FastAPI ====================
app = FastAPI(title="MediaHub", version="1.5.0")
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("MEDIAHUB_SECRET_KEY", "dev-" + secrets.token_hex(32)),
    same_site="lax",
    https_only=False,
)
app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")
templates = Jinja2Templates(directory=APP_DIR / "templates")


# ==================== 密码 ====================
# 密码不限制输入长度；数据库只保存固定长度的 PBKDF2 哈希结果。
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITERATIONS,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(derived).decode("ascii"),
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_b64, hash_b64 = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            base64.b64decode(salt_b64),
            int(iterations),
        )
        return hmac.compare_digest(actual, base64.b64decode(hash_b64))
    except (ValueError, TypeError):
        return False


# ==================== 首次启动 / 旧数据库兼容 ====================
Base.metadata.create_all(bind=engine)

# create_all 不会给旧表自动增加字段，所以保留这一小段兼容旧版 media.db。
media_columns = {column["name"] for column in inspect(engine).get_columns("media")}
if "is_visible" not in media_columns:
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE media ADD COLUMN is_visible BOOLEAN NOT NULL DEFAULT 1"))

admin_username = os.getenv("MEDIAHUB_ADMIN_USER")
admin_password = os.getenv("MEDIAHUB_ADMIN_PASSWORD")
if admin_username and admin_password:
    with SessionLocal() as db:
        if not db.scalar(select(User).where(User.username == admin_username)):
            db.add(User(username=admin_username, password_hash=hash_password(admin_password), is_admin=True))
            db.commit()


# ==================== 少量公共函数 ====================
# 这里只保留多个路由都会重复使用的基础逻辑，不再拆 service / manager / repository。
def flash(request: Request, message: str, category: str = "info"):
    request.session["flash"] = {"message": message, "category": category}


def current_user(request: Request, db: Session) -> User | None:
    user_id = request.session.get("user_id")
    return db.get(User, user_id) if user_id else None


def template_context(request: Request, db: Session, **kwargs):
    return {
        "request": request,
        "current_user": current_user(request, db),
        "flash": request.session.pop("flash", None),
        **kwargs,
    }


def media_path(item: Media) -> Path:
    return (IMAGE_DIR if item.media_type == "image" else VIDEO_DIR) / item.stored_filename


def can_view_media(item: Media, user: User | None) -> bool:
    return item.is_visible or bool(user and (user.id == item.user_id or user.is_admin))


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def verify_csrf(request: Request, token: str):
    expected = request.session.get("csrf_token")
    if not expected or not secrets.compare_digest(expected, token):
        raise HTTPException(status_code=403, detail="CSRF token invalid")


templates.env.globals["csrf_token"] = csrf_token


def lcs_length(left: str, right: str) -> int:
    """最长公共子序列长度；实时搜索和完整搜索共用。"""
    left = left.casefold().strip()
    right = right.casefold().strip()
    if not left or not right:
        return 0
    if len(left) > len(right):
        left, right = right, left

    previous = [0] * (len(left) + 1)
    for char_right in right:
        current = [0]
        for index, char_left in enumerate(left, start=1):
            if char_left == char_right:
                current.append(previous[index - 1] + 1)
            else:
                current.append(max(current[-1], previous[index]))
        previous = current
    return previous[-1]


@app.get("/", response_class=HTMLResponse)
def index(
    request: Request,
    q: str = "",
    kind: str = "all",
    db: Session = Depends(get_db),
):
    query = q.strip()
    stmt = (
        select(Media)
        .options(joinedload(Media.owner))
        .where(Media.is_visible.is_(True))
    )
    if kind in {"image", "video"}:
        stmt = stmt.where(Media.media_type == kind)

    items = db.scalars(stmt.order_by(desc(Media.created_at))).unique().all()
    user_results = []
    if query:
        # 直接在搜索路由里计算 LCS，不再额外封装“搜索排序类/函数”。
        media_matches = []
        for item in items:
            owner_name = item.owner.username if item.owner else ""
            title_score = lcs_length(query, item.title)
            owner_score = lcs_length(query, owner_name)
            score = max(title_score, owner_score)
            if score > 0:
                normalized = max(
                    title_score / max(len(item.title), 1),
                    owner_score / max(len(owner_name), 1),
                )
                media_matches.append((score, normalized, item.created_at.timestamp(), item))
        media_matches.sort(key=lambda row: row[:3], reverse=True)
        items = [row[3] for row in media_matches]

        users = db.scalars(select(User).order_by(desc(User.created_at))).all()
        user_matches = []
        for user in users:
            score = lcs_length(query, user.username)
            if score > 0:
                normalized = score / max(len(user.username), 1)
                user_matches.append((score, normalized, user.created_at.timestamp(), user))
        user_matches.sort(key=lambda row: row[:3], reverse=True)
        user_results = [row[3] for row in user_matches[:12]]

    public_count = db.scalar(select(func.count(Media.id)).where(Media.is_visible.is_(True))) or 0
    video_count = db.scalar(select(func.count(Media.id)).where(Media.is_visible.is_(True), Media.media_type == "video")) or 0
    image_count = db.scalar(select(func.count(Media.id)).where(Media.is_visible.is_(True), Media.media_type == "image")) or 0
    return templates.TemplateResponse(
        "index.html",
        template_context(
            request, db, items=items, q=query, kind=kind, user_results=user_results,
            public_count=public_count, video_count=video_count, image_count=image_count,
        ),
    )


@app.get("/api/search")
def live_search(q: str = "", db: Session = Depends(get_db)):
    """顶部实时搜索：作品和用户都按 LCS 长度降序。"""
    query = q.strip()
    if not query:
        return {"query": "", "media": [], "users": []}

    media_items = db.scalars(
        select(Media)
        .options(joinedload(Media.owner))
        .where(Media.is_visible.is_(True))
        .order_by(desc(Media.created_at))
    ).unique().all()

    media_matches = []
    for item in media_items:
        owner_name = item.owner.username if item.owner else ""
        title_score = lcs_length(query, item.title)
        owner_score = lcs_length(query, owner_name)
        score = max(title_score, owner_score)
        if score > 0:
            normalized = max(
                title_score / max(len(item.title), 1),
                owner_score / max(len(owner_name), 1),
            )
            media_matches.append((score, normalized, item.created_at.timestamp(), item))
    media_matches.sort(key=lambda row: row[:3], reverse=True)

    users = db.scalars(select(User).order_by(desc(User.created_at))).all()
    user_matches = []
    for user in users:
        score = lcs_length(query, user.username)
        if score > 0:
            normalized = score / max(len(user.username), 1)
            user_matches.append((score, normalized, user.created_at.timestamp(), user))
    user_matches.sort(key=lambda row: row[:3], reverse=True)

    return {
        "query": query,
        "media": [
            {
                "id": row[3].id,
                "title": row[3].title,
                "owner": row[3].owner.username,
                "media_type": row[3].media_type,
                "views": row[3].views,
                "score": row[0],
            }
            for row in media_matches[:8]
        ],
        "users": [
            {"id": row[3].id, "username": row[3].username, "score": row[0]}
            for row in user_matches[:6]
        ],
    }


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse("register.html", template_context(request, db))


@app.post("/register")
def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)

    username = username.strip()
    if not (3 <= len(username) <= 50):
        flash(request, "用户名长度必须为 3-50 个字符。", "danger")
        return RedirectResponse("/register", status_code=303)

    if db.scalar(select(User).where(User.username == username)):
        flash(request, "用户名已经存在。", "warning")
        return RedirectResponse("/register", status_code=303)

    user = User(username=username, password_hash=hash_password(password))
    db.add(user)
    db.commit()
    db.refresh(user)

    request.session["user_id"] = user.id
    flash(request, "注册成功，已经自动登录。", "success")
    return RedirectResponse("/", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse("login.html", template_context(request, db))


@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = db.scalar(select(User).where(User.username == username.strip()))

    if not user or not verify_password(password, user.password_hash):
        flash(request, "用户名或密码错误。", "danger")
        return RedirectResponse("/login", status_code=303)

    request.session["user_id"] = user.id
    flash(request, f"欢迎回来，{user.username}！", "success")
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
def logout(request: Request, csrf: str = Form(...)):
    verify_csrf(request, csrf)
    request.session.clear()
    return RedirectResponse("/", status_code=303)


@app.get("/upload", response_class=HTMLResponse)
def upload_page(request: Request, db: Session = Depends(get_db)):
    if not current_user(request, db):
        flash(request, "请先登录。", "warning")
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse("upload.html", template_context(request, db))


@app.post("/upload")
async def upload(
    request: Request,
    title: str = Form(...),
    description: str = Form(""),
    is_visible: bool = Form(False),
    csrf: str = Form(...),
    media_file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)

    user = current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in")

    title = title.strip()
    description = description.strip()

    if not (1 <= len(title) <= 120):
        flash(request, "标题长度必须为 1-120 个字符。", "danger")
        return RedirectResponse("/upload", status_code=303)

    original_name = Path(media_file.filename or "unnamed").name
    ext = Path(original_name).suffix.lower()

    if ext in ALLOWED_IMAGES:
        media_type = "image"
        expected_mime = ALLOWED_IMAGES[ext]
        target_dir = IMAGE_DIR
    elif ext in ALLOWED_VIDEOS:
        media_type = "video"
        expected_mime = ALLOWED_VIDEOS[ext]
        target_dir = VIDEO_DIR
    else:
        flash(
            request,
            "不支持的文件类型。图片：jpg/jpeg/png/gif/webp；视频：mp4/webm/mov/m4v。",
            "danger",
        )
        return RedirectResponse("/upload", status_code=303)

    if media_file.content_type and media_file.content_type != "application/octet-stream":
        if media_type == "image" and not media_file.content_type.startswith("image/"):
            flash(request, "文件扩展名与实际媒体类型不一致。", "danger")
            return RedirectResponse("/upload", status_code=303)
        if media_type == "video" and not media_file.content_type.startswith("video/"):
            flash(request, "文件扩展名与实际媒体类型不一致。", "danger")
            return RedirectResponse("/upload", status_code=303)

    stored_name = f"{uuid.uuid4().hex}{ext}"
    destination = target_dir / stored_name
    size = 0

    try:
        with destination.open("wb") as output:
            while True:
                chunk = await media_file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    output.close()
                    destination.unlink(missing_ok=True)
                    flash(request, "文件超过 1 GiB 限制。", "danger")
                    return RedirectResponse("/upload", status_code=303)
                output.write(chunk)
    finally:
        await media_file.close()

    item = Media(
        user_id=user.id,
        title=title,
        description=description,
        stored_filename=stored_name,
        original_filename=original_name,
        media_type=media_type,
        mime_type=expected_mime,
        file_size=size,
        is_visible=is_visible,
    )
    db.add(item)
    db.commit()
    db.refresh(item)

    flash(request, "上传成功。" if is_visible else "上传成功，当前作品未公开展示。", "success")
    return RedirectResponse(f"/media/{item.id}", status_code=303)


@app.get("/media/{media_id}", response_class=HTMLResponse)
def media_detail(media_id: int, request: Request, db: Session = Depends(get_db)):
    item = db.scalar(
        select(Media)
        .options(joinedload(Media.owner))
        .where(Media.id == media_id)
    )
    user = current_user(request, db)

    if not item or not can_view_media(item, user):
        raise HTTPException(status_code=404, detail="Media not found")

    comments = db.scalars(
        select(Comment)
        .options(joinedload(Comment.author))
        .where(Comment.media_id == item.id)
        .order_by(desc(Comment.created_at))
    ).all()

    related_items = db.scalars(
        select(Media)
        .options(joinedload(Media.owner))
        .where(Media.is_visible.is_(True), Media.id != item.id)
        .order_by(desc(Media.created_at))
        .limit(8)
    ).all()

    item.views += 1
    db.commit()

    return templates.TemplateResponse(
        "media_detail.html",
        template_context(request, db, item=item, comments=comments, related_items=related_items),
    )


@app.get("/content/{media_id}")
def media_content(media_id: int, request: Request, db: Session = Depends(get_db)):
    item = db.get(Media, media_id)
    user = current_user(request, db)
    if not item or not can_view_media(item, user):
        raise HTTPException(status_code=404, detail="Media not found")

    path = media_path(item)
    if not path.exists():
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(
        path,
        media_type=item.mime_type,
        filename=item.original_filename,
        content_disposition_type="inline",
    )


@app.get("/download/{media_id}")
def download_media(media_id: int, request: Request, db: Session = Depends(get_db)):
    item = db.get(Media, media_id)
    user = current_user(request, db)
    if not item or not can_view_media(item, user):
        raise HTTPException(status_code=404, detail="Media not found")

    path = media_path(item)
    if not path.exists():
        raise HTTPException(status_code=404, detail="File not found")

    item.downloads += 1
    db.commit()

    return FileResponse(path, media_type=item.mime_type, filename=item.original_filename)


@app.post("/media/{media_id}/comments")
def add_comment(
    media_id: int,
    request: Request,
    content: str = Form(...),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = current_user(request, db)
    if not user:
        flash(request, "登录后才能发表评论。", "warning")
        return RedirectResponse("/login", status_code=303)

    item = db.get(Media, media_id)
    if not item or not can_view_media(item, user):
        raise HTTPException(status_code=404, detail="Media not found")

    content = content.strip()
    if not content:
        flash(request, "评论内容不能为空。", "warning")
        return RedirectResponse(f"/media/{media_id}", status_code=303)
    if len(content) > MAX_COMMENT_LENGTH:
        flash(request, f"评论最多 {MAX_COMMENT_LENGTH} 个字符。", "danger")
        return RedirectResponse(f"/media/{media_id}", status_code=303)

    db.add(Comment(media_id=media_id, user_id=user.id, content=content))
    db.commit()
    flash(request, "评论已发布。", "success")
    return RedirectResponse(f"/media/{media_id}#comments", status_code=303)


@app.post("/comments/{comment_id}/delete")
def delete_comment(
    comment_id: int,
    request: Request,
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in")

    comment = db.scalar(
        select(Comment)
        .options(joinedload(Comment.media))
        .where(Comment.id == comment_id)
    )
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")

    if user.id != comment.user_id and user.id != comment.media.user_id and not user.is_admin:
        raise HTTPException(status_code=403, detail="No permission")

    media_id = comment.media_id
    db.delete(comment)
    db.commit()
    flash(request, "评论已删除。", "success")
    return RedirectResponse(f"/media/{media_id}#comments", status_code=303)


@app.get("/my", response_class=HTMLResponse)
def my_media(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    if not user:
        flash(request, "请先登录。", "warning")
        return RedirectResponse("/login", status_code=303)

    items = db.scalars(
        select(Media)
        .where(Media.user_id == user.id)
        .order_by(desc(Media.created_at))
    ).all()

    total_views = sum(item.views for item in items)
    total_downloads = sum(item.downloads for item in items)
    visible_count = sum(1 for item in items if item.is_visible)
    return templates.TemplateResponse(
        "my_media.html",
        template_context(
            request, db, items=items, total_views=total_views,
            total_downloads=total_downloads, visible_count=visible_count,
        ),
    )


@app.post("/media/{media_id}/visibility")
def toggle_visibility(
    media_id: int,
    request: Request,
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in")

    item = db.get(Media, media_id)
    if not item:
        raise HTTPException(status_code=404, detail="Media not found")
    if item.user_id != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="No permission")

    item.is_visible = not item.is_visible
    db.commit()
    flash(request, "作品已公开展示。" if item.is_visible else "作品已停止公开展示。", "success")
    return RedirectResponse("/my", status_code=303)


@app.get("/user/{user_id}", response_class=HTMLResponse)
def profile(user_id: int, request: Request, db: Session = Depends(get_db)):
    profile_user = db.get(User, user_id)
    if not profile_user:
        raise HTTPException(status_code=404, detail="User not found")

    viewer = current_user(request, db)
    stmt = select(Media).where(Media.user_id == profile_user.id)
    if not viewer or (viewer.id != profile_user.id and not viewer.is_admin):
        stmt = stmt.where(Media.is_visible.is_(True))

    items = db.scalars(stmt.order_by(desc(Media.created_at))).all()

    total_views = sum(item.views for item in items)
    total_downloads = sum(item.downloads for item in items)
    return templates.TemplateResponse(
        "profile.html",
        template_context(
            request, db, profile_user=profile_user, items=items,
            total_views=total_views, total_downloads=total_downloads,
        ),
    )


@app.post("/media/{media_id}/delete")
def delete_media(
    media_id: int,
    request: Request,
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf)
    user = current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in")

    item = db.get(Media, media_id)
    if not item:
        raise HTTPException(status_code=404, detail="Media not found")
    if item.user_id != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="No permission")

    owner_id = item.user_id
    media_path(item).unlink(missing_ok=True)
    db.delete(item)
    db.commit()

    flash(request, "媒体已经删除。", "success")
    return RedirectResponse("/my" if owner_id == user.id else "/", status_code=303)


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")

    users = db.scalars(select(User).order_by(desc(User.created_at))).all()
    media_counts = dict(db.execute(select(Media.user_id, func.count(Media.id)).group_by(Media.user_id)).all())
    comment_counts = dict(db.execute(select(Comment.user_id, func.count(Comment.id)).group_by(Comment.user_id)).all())
    return templates.TemplateResponse(
        "admin_users.html",
        template_context(
            request, db, users=users, media_counts=media_counts, comment_counts=comment_counts,
        ),
    )


@app.post("/admin/users/{user_id}/role")
def toggle_admin_role(
    user_id: int, request: Request, csrf: str = Form(...), db: Session = Depends(get_db)
):
    verify_csrf(request, csrf)
    operator = current_user(request, db)
    if not operator or not operator.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == operator.id:
        flash(request, "不能在这里取消自己的管理员权限。", "warning")
        return RedirectResponse("/admin/users", status_code=303)
    target.is_admin = not target.is_admin
    db.commit()
    flash(request, f"已更新 {target.username} 的账号角色。", "success")
    return RedirectResponse("/admin/users", status_code=303)


@app.get("/health")
def health():
    return {"status": "ok", "version": "1.5.0"}

if __name__ == "__main__":
    import uvicorn

    # 固定监听所有网卡，局域网设备也可以访问。
    # 如需更换端口，直接修改下面的 8000。
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=False,
    )
