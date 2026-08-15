from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import threading
import uuid
import webbrowser
from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from jinja2 import DictLoader, Environment, select_autoescape
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
    # 兼容旧数据库；新版界面不展示，也不再累计这两个计数。
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




# ==================== 内嵌前端 ====================
# HTML、CSS、JavaScript 全部直接放在 main.py 中。
EMBEDDED_TEMPLATES = {
    'admin_users.html': '''{% extends "base.html" %}
{% block title %}用户管理 - MediaHub{% endblock %}
{% block content %}
<div class="creator-layout">
    <aside class="creator-side"><div class="creator-user"><div class="avatar-circle">{{ current_user.username[:1]|upper }}</div><div><strong>{{ current_user.username }}</strong><span>管理员</span></div></div><a href="/my">作品管理</a><a class="active" href="/admin/users">用户管理</a><a href="/user/{{ current_user.id }}">个人主页</a></aside>
    <section class="creator-main">
        <div class="section-heading"><div><h1>用户管理</h1><p>搜索账号、查看基础信息并管理角色</p></div><span class="result-count">{{ users|length }} 个账号</span></div>
        <form class="admin-search mt-3" action="/admin/users" method="get"><input class="form-control" name="q" value="{{ q }}" placeholder="按用户名搜索"><button class="btn btn-outline-primary" type="submit">搜索</button>{% if q %}<a class="btn btn-light" href="/admin/users">清除</a>{% endif %}</form>
        <div class="user-table-wrap">
            <table class="user-table"><thead><tr><th>用户</th><th>角色</th><th>作品</th><th>评论</th><th>注册时间</th><th>操作</th></tr></thead><tbody>{% for user in users %}<tr><td><a class="user-cell" href="/user/{{ user.id }}"><span class="tiny-avatar">{{ user.username[:1]|upper }}</span><div><strong>{{ user.username }}</strong><span>ID {{ user.id }}</span></div></a></td><td><span class="role-badge {{ 'admin' if user.is_admin else '' }}">{{ '管理员' if user.is_admin else '普通用户' }}</span></td><td>{{ media_counts.get(user.id, 0) }}</td><td>{{ comment_counts.get(user.id, 0) }}</td><td>{{ user.created_at.strftime("%Y-%m-%d %H:%M") }}</td><td>{% if user.id != current_user.id %}<div class="manage-actions"><form action="/admin/users/{{ user.id }}/role" method="post"><input type="hidden" name="csrf" value="{{ csrf_token(request) }}"><button class="mini-manage-btn" type="submit">{{ '取消管理员' if user.is_admin else '设为管理员' }}</button></form><form action="/admin/users/{{ user.id }}/delete" method="post" onsubmit="return confirm('确定删除用户 {{ user.username }} 吗？该用户的作品和评论也会删除。')"><input type="hidden" name="csrf" value="{{ csrf_token(request) }}"><button class="mini-manage-btn danger" type="submit">删除</button></form></div>{% else %}<span class="text-secondary small">当前账号</span>{% endif %}</td></tr>{% else %}<tr><td colspan="6" class="text-secondary">没有找到用户。</td></tr>{% endfor %}</tbody></table>
        </div>
    </section>
</div>
{% endblock %}
''',
    'base.html': '''<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{% block title %}MediaHub{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
:root {
    --accent: #e77700;
    --accent-dark: #a64f00;
    --accent-soft: rgba(231, 119, 0, .10);
    --success-zero-b: #5b7d00;
    --danger-zero-b: #bd3700;
    --surface: #f6f7f8;
    --card: #ffffff;
    --text: #1f2329;
    --muted: #777f89;
    --line: #e7e9ec;
}
* { box-sizing: border-box; }
html { background: var(--surface); }
body { margin: 0; background: var(--surface); color: var(--text); font-family: -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",Arial,sans-serif; }
a { color: inherit; }
a:hover { color: var(--accent-dark); }
.page-shell { width: 100%; max-width: 1900px; margin: 0 auto; }
.site-header { z-index: 1030; background: rgba(255,255,255,.96); border-bottom: 1px solid var(--line); backdrop-filter: blur(16px); }
.topbar { min-height: 66px; display: grid; grid-template-columns: auto auto minmax(280px, 720px) auto; gap: 22px; align-items: center; }
.brand { display: flex; align-items: center; gap: 8px; font-size: 1.25rem; font-weight: 800; text-decoration: none; white-space: nowrap; }
.brand-play { width: 34px; height: 34px; display: grid; place-items: center; border-radius: 10px; background: var(--accent); color: #fff; font-size: .82rem; }
.top-links { gap: 18px; }
.top-links a,.nav-action,.plain-button { color: #4e5661; text-decoration: none; font-size: .94rem; border: 0; background: transparent; padding: 0; }
.top-links a:hover,.nav-action:hover,.plain-button:hover { color: var(--accent-dark); }
.top-search { height: 42px; display: flex; border: 1px solid #d7dbe0; border-radius: 10px; background: #f3f5f6; overflow: hidden; }
.top-search:focus-within { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(231,119,0,.10); background: #fff; }
.top-search input { min-width: 0; flex: 1; border: 0; outline: 0; background: transparent; padding: 0 14px; }
.top-search button { width: 72px; border: 0; border-left: 1px solid #d7dbe0; background: #fff; font-weight: 600; }
.top-search button:hover { background: var(--accent-soft); color: var(--accent-dark); }
.top-actions { display: flex; align-items: center; justify-content: flex-end; gap: 13px; white-space: nowrap; }
.user-pill { display: flex; align-items: center; gap: 7px; text-decoration: none; font-weight: 600; }
.mini-avatar,.tiny-avatar { flex: 0 0 auto; display: inline-grid; place-items: center; border-radius: 50%; background: #6c4200; color: #fff; font-weight: 700; }
.mini-avatar { width: 34px; height: 34px; }
.tiny-avatar { width: 28px; height: 28px; font-size: .78rem; text-decoration: none; }
.upload-button { padding: 9px 18px; border-radius: 9px; background: var(--accent); color: #fff !important; text-decoration: none; font-weight: 700; }
.upload-button:hover { background: var(--accent-dark); }
.mobile-nav { display: flex; gap: 22px; overflow-x: auto; padding-bottom: 10px; }
.mobile-nav a,.mobile-nav button { color: #555d67; text-decoration: none; white-space: nowrap; font-size: .9rem; }
.mobile-nav form { margin: 0; }
.mobile-nav button { padding: 0; border: 0; background: transparent; }
.site-footer { max-width: 1900px; margin-left: auto; margin-right: auto; color: var(--muted); border-top: 1px solid var(--line); text-align: center; font-size: .86rem; }

.channel-strip { display: flex; align-items: center; justify-content: space-between; gap: 20px; padding: 12px 0 2px; }
.channel-title { display: flex; align-items: center; gap: 12px; min-width: 190px; }
.channel-logo { width: 46px; height: 46px; display: grid; place-items: center; border-radius: 14px; color: #fff; font-size: 1.2rem; font-weight: 800; background: linear-gradient(135deg,#9c4b00,#e77700); }
.channel-title strong { display: block; font-size: 1rem; }
.channel-title span { display: block; color: var(--muted); font-size: .78rem; margin-top: 2px; }
.channel-links { flex: 1; display: flex; justify-content: flex-end; gap: 10px; overflow-x: auto; }
.channel-links a { display: inline-flex; align-items: center; gap: 7px; padding: 9px 14px; border: 1px solid var(--line); background: #fff; border-radius: 8px; text-decoration: none; white-space: nowrap; font-size: .9rem; }
.channel-links a span { color: var(--muted); font-size: .78rem; }
.channel-links a:hover,.channel-links a.active { border-color: rgba(231,119,0,.45); color: var(--accent-dark); background: var(--accent-soft); }
.section-heading { display: flex; justify-content: space-between; gap: 16px; align-items: end; }
.section-heading h1,.section-heading h2 { font-size: 1.35rem; margin: 0; font-weight: 750; }
.section-heading p { color: var(--muted); margin: 5px 0 0; font-size: .87rem; }
.section-heading.compact { margin-top: 32px; margin-bottom: 14px; }
.result-count { color: var(--muted); font-size: .86rem; }
.media-grid { display: grid; grid-template-columns: repeat(5,minmax(0,1fr)); gap: 24px 18px; }
.media-card { min-width: 0; }
.media-thumb { position: relative; display: block; aspect-ratio: 16/9; overflow: hidden; border-radius: 10px; background: #111; }
.media-thumb img,.media-thumb video { width: 100%; height: 100%; display: block; object-fit: cover; transition: transform .25s ease; }
.media-card:hover .media-thumb img,.media-card:hover .media-thumb video { transform: scale(1.025); }
.video-badge,.hidden-badge { position: absolute; top: 9px; right: 9px; z-index: 2; color: #fff; background: rgba(0,0,0,.68); border-radius: 6px; padding: 3px 7px; font-size: .72rem; }
.hidden-badge { left: 9px; right: auto; background: rgba(166,79,0,.90); }
.media-card-body { padding: 9px 2px 0; }
.media-card-body h2 { margin: 0 0 8px; min-height: 42px; font-size: .96rem; font-weight: 650; line-height: 1.45; display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 2; overflow: hidden; }
.media-card-body h2 a { text-decoration: none; }
.card-meta { display: flex; align-items: center; justify-content: space-between; gap: 8px; color: var(--muted); font-size: .79rem; }
.owner-link { min-width: 0; display: flex; align-items: center; gap: 6px; text-decoration: none; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.quick-download { flex: 0 0 auto; text-decoration: none; color: var(--accent-dark); padding: 3px 7px; border-radius: 5px; }
.quick-download:hover { background: var(--accent-soft); }
.empty-panel { min-height: 300px; padding: 60px 20px; border: 1px dashed #d9dde2; border-radius: 14px; background: #fff; text-align: center; }
.empty-panel h2 { font-size: 1.2rem; }
.empty-panel p { color: var(--muted); }
.empty-icon { font-size: 2.4rem; color: var(--accent); margin-bottom: 12px; }

.watch-layout { width: min(100%,1200px); margin: 0 auto; }
.watch-main { min-width: 0; }
.viewer { width: 100%; min-height: 420px; display: grid; place-items: center; overflow: hidden; border-radius: 8px; background: #000; box-shadow: 0 7px 26px rgba(0,0,0,.12); }
.viewer video { width: 100%; max-height: calc(100vh - 120px); background: #000; }
.detail-image { display: block; max-width: 100%; max-height: calc(100vh - 120px); object-fit: contain; }
.watch-info { padding: 18px 0 14px; border-bottom: 1px solid var(--line); }
.watch-info h1 { margin: 0 0 9px; font-size: 1.5rem; font-weight: 700; line-height: 1.35; }
.watch-submeta { display: flex; flex-wrap: wrap; gap: 14px; color: var(--muted); font-size: .83rem; }
.action-row { display: flex; flex-wrap: wrap; gap: 9px; margin-top: 15px; }
.action-row form { margin: 0; }
.author-panel { display: flex; align-items: center; gap: 12px; margin-top: 18px; }
.avatar-circle { width: 64px; height: 64px; display: grid; place-items: center; border-radius: 50%; background: #6c4200; color: #fff; font-size: 1.6rem; font-weight: 800; }
.small-avatar { width: 48px; height: 48px; flex: 0 0 auto; font-size: 1.1rem; text-decoration: none; }
.author-copy { min-width: 0; }
.author-copy a { display: block; font-weight: 700; text-decoration: none; }
.author-copy span { display: block; color: var(--muted); font-size: .8rem; margin-top: 4px; overflow-wrap: anywhere; }
.description-box { margin-top: 16px; padding: 15px 16px; border-radius: 8px; background: #fff; border: 1px solid var(--line); white-space: pre-wrap; overflow-wrap: anywhere; }
.comment-form,.login-comment { padding: 15px; background: #fff; border: 1px solid var(--line); border-radius: 10px; }
.comment-submit { display: flex; justify-content: space-between; align-items: center; margin-top: 10px; color: var(--muted); font-size: .78rem; }
.comment-item { display: flex; gap: 12px; padding: 17px 4px; border-bottom: 1px solid var(--line); }
.comment-avatar { width: 36px; height: 36px; }
.comment-main { flex: 1; min-width: 0; }
.comment-head { display: flex; justify-content: space-between; gap: 12px; }
.comment-head a { font-weight: 650; text-decoration: none; }
.comment-head span { margin-left: 9px; color: var(--muted); font-size: .75rem; }
.comment-content { margin-top: 7px; white-space: pre-wrap; overflow-wrap: anywhere; line-height: 1.65; }
.comment-delete { border: 0; background: transparent; color: var(--danger-zero-b); font-size: .78rem; padding: 0; }

.creator-layout { display: grid; grid-template-columns: 220px minmax(0,1fr); gap: 22px; }
.creator-side { align-self: start; position: sticky; top: 88px; display: flex; flex-direction: column; gap: 4px; padding: 14px; border: 1px solid var(--line); border-radius: 12px; background: #fff; }
.creator-user { display: flex; align-items: center; gap: 10px; padding: 7px 5px 14px; margin-bottom: 4px; border-bottom: 1px solid var(--line); }
.creator-user .avatar-circle { width: 46px; height: 46px; font-size: 1.1rem; }
.creator-user strong,.creator-user span { display: block; }
.creator-user span { color: var(--muted); font-size: .75rem; margin-top: 2px; }
.creator-side > a { padding: 10px 12px; border-radius: 8px; text-decoration: none; color: #4f5761; }
.creator-side > a:hover,.creator-side > a.active { color: var(--accent-dark); background: var(--accent-soft); }
.creator-main { min-width: 0; }
.manage-list { border: 1px solid var(--line); border-radius: 12px; background: #fff; overflow: hidden; }
.manage-item { display: grid; grid-template-columns: 180px minmax(0,1fr) auto; gap: 15px; align-items: center; padding: 14px; border-bottom: 1px solid var(--line); }
.manage-item:last-child { border-bottom: 0; }
.manage-thumb { display: block; aspect-ratio: 16/9; border-radius: 7px; overflow: hidden; background: #111; }
.manage-thumb img,.manage-thumb video { width: 100%; height: 100%; object-fit: cover; display: block; }
.manage-copy h2 { margin: 0 0 9px; font-size: .98rem; }
.manage-copy h2 a { text-decoration: none; }
.manage-meta { display: flex; flex-wrap: wrap; gap: 11px; color: var(--muted); font-size: .78rem; }
.status-dot { color: #756000; }
.status-dot.public { color: var(--success-zero-b); }
.manage-actions { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 6px; }
.manage-actions form { margin: 0; }

.profile-banner { min-height: 160px; display: flex; align-items: end; gap: 20px; padding: 30px; border-radius: 14px 14px 0 0; color: #fff; background: linear-gradient(120deg,#6d3900,#a65900 50%,#725d00); }
.profile-main { display: flex; align-items: center; gap: 15px; }
.profile-avatar { width: 78px; height: 78px; border: 3px solid rgba(255,255,255,.82); background: #5b3500; }
.profile-main h1 { margin: 0; font-size: 1.55rem; }
.profile-main p { margin: 5px 0 0; opacity: .82; font-size: .84rem; }
.profile-tabs { display: flex; gap: 28px; margin-bottom: 22px; padding: 0 24px; background: #fff; border: 1px solid var(--line); border-top: 0; border-radius: 0 0 12px 12px; }
.profile-tabs span,.profile-tabs a { padding: 14px 0 12px; text-decoration: none; color: #4f5761; border-bottom: 2px solid transparent; }
.profile-tabs .active { color: var(--accent-dark); border-bottom-color: var(--accent); }

.user-table-wrap { margin-top: 20px; overflow: auto; border: 1px solid var(--line); border-radius: 12px; background: #fff; }
.user-table { width: 100%; min-width: 850px; border-collapse: collapse; }
.user-table th,.user-table td { padding: 13px 15px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: middle; }
.user-table th { color: var(--muted); background: #fafafa; font-size: .78rem; font-weight: 650; }
.user-table tbody tr:last-child td { border-bottom: 0; }
.user-cell { display: flex; align-items: center; gap: 9px; text-decoration: none; }
.user-cell strong,.user-cell span { display: block; }
.user-cell span { color: var(--muted); font-size: .72rem; margin-top: 2px; }
.role-badge { display: inline-block; padding: 4px 8px; border-radius: 999px; background: #f1f2f3; color: #6a717b; font-size: .74rem; }
.role-badge.admin { color: #fff; background: var(--danger-zero-b); }

.auth-wrap { max-width: 560px; margin: 5vh auto; }
.hidden-notice { color: #6e3900; background: var(--accent-soft); border-color: rgba(231,119,0,.42); }
.visibility-public { background: var(--success-zero-b); color: #fff; }
.visibility-hidden { background: #735d00; color: #fff; }
.form-control:focus,.form-check-input:focus { border-color: var(--accent); box-shadow: 0 0 0 .25rem rgba(231,119,0,.14); }
.form-check-input:checked { background-color: var(--accent); border-color: var(--accent); }
.btn-primary { --bs-btn-bg: var(--accent); --bs-btn-border-color: var(--accent); --bs-btn-hover-bg: var(--accent-dark); --bs-btn-hover-border-color: var(--accent-dark); --bs-btn-active-bg: var(--accent-dark); --bs-btn-active-border-color: var(--accent-dark); }
.btn-outline-primary { --bs-btn-color: var(--accent-dark); --bs-btn-border-color: var(--accent); --bs-btn-hover-bg: var(--accent); --bs-btn-hover-border-color: var(--accent); --bs-btn-active-bg: var(--accent-dark); --bs-btn-active-border-color: var(--accent-dark); }
.btn-outline-danger { --bs-btn-color: var(--danger-zero-b); --bs-btn-border-color: var(--danger-zero-b); --bs-btn-hover-bg: var(--danger-zero-b); --bs-btn-hover-border-color: var(--danger-zero-b); }
.text-bg-danger { background-color: var(--danger-zero-b)!important; }
.alert-success { color: #365000; background: rgba(91,125,0,.12); border-color: rgba(91,125,0,.4); }
.alert-warning,.alert-info { color: #6b3900; background: rgba(220,150,0,.12); border-color: rgba(220,150,0,.4); }
.alert-danger { color: #742000; background: rgba(189,55,0,.12); border-color: rgba(189,55,0,.4); }

@media (max-width: 1500px) { .media-grid { grid-template-columns: repeat(4,minmax(0,1fr)); } }
@media (max-width: 1180px) { .topbar { grid-template-columns: auto minmax(240px,1fr) auto; } .top-links { display:none!important; } .media-grid { grid-template-columns: repeat(3,minmax(0,1fr)); } }
@media (max-width: 991.98px) { .topbar { min-height: 58px; grid-template-columns: auto minmax(0,1fr) auto; gap: 12px; } .brand { font-size: 1rem; } .brand-play { width: 30px; height: 30px; } .top-search { height: 38px; } .top-search button { width: 58px; } .creator-layout { grid-template-columns: 1fr; } .creator-side { position: static; flex-direction: row; overflow-x: auto; align-items: center; } .creator-user { border: 0; border-right: 1px solid var(--line); padding: 3px 14px 3px 2px; margin: 0 5px 0 0; min-width: 180px; } .creator-side > a { white-space: nowrap; } }
@media (max-width: 767.98px) { .page-shell { padding-left: 12px!important; padding-right: 12px!important; } .topbar { grid-template-columns: auto minmax(0,1fr) auto; padding-left: 12px!important; padding-right: 12px!important; } .brand { width: 34px; overflow: hidden; gap: 10px; } .top-actions .user-pill,.top-actions .nav-action { display:none!important; } .upload-button { padding: 8px 12px; } .top-search input { padding: 0 9px; font-size: .85rem; } .channel-strip { align-items: flex-start; flex-direction: column; } .channel-links { width: 100%; justify-content: flex-start; } .media-grid { grid-template-columns: repeat(2,minmax(0,1fr)); gap: 18px 10px; } .media-card-body h2 { font-size: .88rem; min-height: 39px; } .viewer { min-height: 230px; border-radius: 5px; } .watch-info h1 { font-size: 1.22rem; } .manage-item { grid-template-columns: 120px minmax(0,1fr); } .manage-actions { grid-column: 1/-1; justify-content: flex-start; } .profile-banner { padding: 20px; align-items: flex-start; flex-direction: column; } }
@media (max-width: 480px) { .media-grid { grid-template-columns: 1fr 1fr; } .channel-title { display:none; } .channel-strip { padding-top: 2px; } .manage-item { grid-template-columns: 100px minmax(0,1fr); gap: 10px; } .manage-meta span:nth-child(n+4) { display:none; } }
.upload-panel { display:grid; grid-template-columns:minmax(320px,.8fr) minmax(420px,1.2fr); gap:20px; margin-top:20px; }
.upload-drop,.upload-fields { background:#fff; border:1px solid var(--line); border-radius:12px; padding:24px; }
.upload-drop { min-height:360px; display:flex; flex-direction:column; justify-content:center; text-align:center; border-style:dashed; }
.upload-symbol { width:68px; height:68px; display:grid; place-items:center; margin:0 auto 14px; border-radius:18px; color:#fff; background:var(--accent); font-size:2rem; }
.upload-drop h2 { font-size:1.15rem; }
.upload-drop p { color:var(--muted); font-size:.82rem; margin-bottom:20px; }
.upload-fields { display:flex; flex-direction:column; gap:20px; }
.upload-submit { align-self:flex-start; min-width:150px; }
@media (max-width:991.98px){ .upload-panel{grid-template-columns:1fr;} .upload-drop{min-height:250px;} }

/* v1.5：更扁平的顶部导航、实时搜索、居中认证页和轻量作品操作 */
.site-header { box-shadow: 0 1px 7px rgba(20,24,28,.035); }
.topbar { min-height: 52px; grid-template-columns: auto auto minmax(260px,680px) auto; gap: 16px; }
.brand { gap: 7px; font-size: 1.08rem; }
.brand-play { width: 28px; height: 28px; border-radius: 8px; font-size: .68rem; }
.top-links { gap: 15px; }
.top-links a,.nav-action,.plain-button { font-size: .87rem; }
.search-shell { position: relative; min-width: 0; }
.top-search { width: 100%; height: 34px; border-radius: 8px; }
.top-search input { padding: 0 11px; font-size: .86rem; }
.top-search button { width: 58px; font-size: .82rem; }
.top-actions { gap: 10px; }
.mini-avatar { width: 29px; height: 29px; font-size: .78rem; }
.upload-button { padding: 6px 13px; border-radius: 7px; font-size: .86rem; }
.mobile-nav { gap: 19px; padding-top: 1px; padding-bottom: 7px; }
.mobile-nav a,.mobile-nav button { font-size: .82rem; }
.search-suggest { position: absolute; top: calc(100% + 7px); left: 0; right: 0; z-index: 1060; max-height: min(66vh,560px); overflow-y: auto; padding: 7px; border: 1px solid var(--line); border-radius: 10px; background: rgba(255,255,255,.99); box-shadow: 0 12px 32px rgba(20,24,28,.13); }
.search-suggest[hidden] { display: none !important; }
.suggest-title { padding: 7px 9px 5px; color: var(--muted); font-size: .72rem; font-weight: 700; }
.suggest-item { display: flex; align-items: center; gap: 9px; padding: 8px 9px; border-radius: 7px; text-decoration: none; }
.suggest-item:hover { background: var(--accent-soft); color: inherit; }
.suggest-icon,.suggest-avatar { width: 29px; height: 29px; flex: 0 0 29px; display: grid; place-items: center; border-radius: 7px; background: #f0f1f2; color: var(--accent-dark); font-size: .72rem; font-weight: 800; }
.suggest-avatar { border-radius: 50%; background: #6c4200; color: #fff; }
.suggest-copy { min-width: 0; }
.suggest-copy strong,.suggest-copy small { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.suggest-copy strong { font-size: .84rem; font-weight: 650; }
.suggest-copy small { margin-top: 2px; color: var(--muted); font-size: .69rem; }
.suggest-all { display: block; margin-top: 5px; padding: 8px 9px; border-top: 1px solid var(--line); color: var(--accent-dark); text-align: center; text-decoration: none; font-size: .79rem; }
.suggest-empty { padding: 18px 10px; color: var(--muted); text-align: center; font-size: .82rem; }
.creator-side { top: 68px; }

.auth-page { min-height: calc(100vh - 165px); display: grid; place-items: center; padding: 22px 0 34px; }
.auth-card { width: min(100%,420px); padding: 30px 32px 25px; border: 1px solid var(--line); border-radius: 14px; background: #fff; box-shadow: 0 14px 38px rgba(28,31,35,.07); }
.auth-brand { width: max-content; display: flex; align-items: center; gap: 7px; margin: 0 auto 20px; color: var(--text); text-decoration: none; font-size: 1.04rem; font-weight: 800; }
.auth-brand span { width: 28px; height: 28px; display: grid; place-items: center; border-radius: 8px; background: var(--accent); color: #fff; font-size: .68rem; }
.auth-heading { margin-bottom: 22px; text-align: center; }
.auth-heading h1 { margin: 0; font-size: 1.45rem; font-weight: 750; }
.auth-heading p { max-width: 310px; margin: 7px auto 0; color: var(--muted); font-size: .82rem; line-height: 1.55; }
.auth-form { display: grid; gap: 15px; }
.auth-form label { display: grid; gap: 7px; color: #4d545e; font-size: .82rem; font-weight: 600; }
.auth-form .form-control { min-height: 42px; border-radius: 8px; font-size: .91rem; }
.auth-form small { color: var(--muted); font-size: .72rem; font-weight: 400; }
.auth-form .btn { min-height: 42px; margin-top: 2px; border-radius: 8px; font-size: .92rem; font-weight: 700; }
.auth-foot { margin-top: 19px; padding-top: 17px; border-top: 1px solid var(--line); color: var(--muted); text-align: center; font-size: .8rem; }
.auth-foot a { color: var(--accent-dark); text-decoration: none; font-weight: 650; }

.search-users { padding: 14px 15px; border: 1px solid var(--line); border-radius: 11px; background: #fff; }
.search-users .section-heading h2 { font-size: 1rem; }
.user-result-row { display: flex; gap: 9px; overflow-x: auto; padding: 3px 0 1px; }
.user-result-card { min-width: 150px; display: flex; align-items: center; gap: 9px; padding: 9px 11px; border: 1px solid var(--line); border-radius: 9px; text-decoration: none; background: #fff; }
.user-result-card:hover { border-color: rgba(231,119,0,.4); background: var(--accent-soft); color: inherit; }
.user-result-card strong,.user-result-card small { display: block; }
.user-result-card strong { max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: .84rem; }
.user-result-card small { margin-top: 2px; color: var(--muted); font-size: .68rem; }

.manage-actions { gap: 5px; }
.mini-manage-btn { height: 30px; display: inline-flex; align-items: center; justify-content: center; gap: 4px; padding: 0 8px; border: 1px solid #dfe2e5; border-radius: 6px; background: #fff; color: #555d66; text-decoration: none; font-size: .76rem; line-height: 1; cursor: pointer; }
.mini-manage-btn:hover { border-color: var(--accent); background: var(--accent-soft); color: var(--accent-dark); }
.mini-manage-btn.visibility-btn { color: var(--accent-dark); }
.mini-manage-btn.danger { color: var(--danger-zero-b); }
.mini-manage-btn.danger:hover { border-color: var(--danger-zero-b); background: rgba(189,55,0,.08); color: var(--danger-zero-b); }

@media (max-width: 1180px) { .topbar { grid-template-columns: auto minmax(240px,1fr) auto; } }
@media (max-width: 991.98px) { .topbar { min-height: 48px; grid-template-columns: auto minmax(0,1fr) auto; gap: 10px; } .brand { font-size: .98rem; } .brand-play { width: 27px; height: 27px; } .top-search { height: 33px; } .top-search button { width: 54px; } }
@media (max-width: 767.98px) { .brand { width: 29px; } .brand-text { display: none; } .topbar { padding-left: 10px!important; padding-right: 10px!important; } .top-actions { gap: 7px; } .upload-button { padding: 6px 9px; } .register-button { display: none; } .search-suggest { position: fixed; top: 51px; left: 8px; right: 8px; max-height: 68vh; } .auth-page { min-height: calc(100vh - 135px); padding: 13px 0 24px; } .auth-card { padding: 25px 21px 21px; border-radius: 12px; } .manage-actions { grid-column: 1/-1; } }
@media (max-width: 480px) { .mini-manage-btn span { display: none; } .mini-manage-btn { width: 31px; padding: 0; } .auth-heading h1 { font-size: 1.3rem; } }

.admin-search { display:flex; gap:8px; max-width:560px; }
.admin-search .form-control { min-width:0; }
@media (max-width:575.98px){ .admin-search{max-width:none;} }

</style>
</head>
<body>
<header class="site-header sticky-top">
    <div class="topbar px-3 px-xl-4">
        <a class="brand" href="/"><span class="brand-play">▶</span><span class="brand-text">MediaHub</span></a>
        <nav class="top-links d-none d-lg-flex"><a href="/">首页</a><a href="/?kind=video">视频</a><a href="/?kind=image">图片</a></nav>
        <div class="search-shell">
            <form class="top-search" action="/" method="get" autocomplete="off">
                <input id="liveSearchInput" name="q" value="{{ q|default('') }}" placeholder="搜索视频、图片或用户" aria-label="搜索">
                <button type="submit" aria-label="搜索">搜索</button>
            </form>
            <div id="searchSuggest" class="search-suggest" hidden></div>
        </div>
        <div class="top-actions">
            {% if current_user %}
                <a class="nav-action d-none d-md-inline" href="/my">创作中心</a>
                {% if current_user.is_admin %}<a class="nav-action d-none d-xl-inline" href="/admin/users">用户</a>{% endif %}
                <a class="user-pill" href="/user/{{ current_user.id }}" title="个人主页"><span class="mini-avatar">{{ current_user.username[:1]|upper }}</span><span class="d-none d-xxl-inline">{{ current_user.username }}</span></a>
                <a class="upload-button" href="/upload">+ 投稿</a>
                <form action="/logout" method="post" class="m-0 d-none d-lg-block"><input type="hidden" name="csrf" value="{{ csrf_token(request) }}"><button class="plain-button" type="submit">退出</button></form>
            {% else %}
                <a class="nav-action" href="/login">登录</a><a class="upload-button register-button" href="/register">注册</a>
            {% endif %}
        </div>
    </div>
    <div class="mobile-nav d-lg-none px-3">
        <a href="/">首页</a><a href="/?kind=video">视频</a><a href="/?kind=image">图片</a>
        {% if current_user %}
            <a href="/user/{{ current_user.id }}">我的主页</a><a href="/my">创作中心</a><a href="/upload">投稿</a>
            <form action="/logout" method="post"><input type="hidden" name="csrf" value="{{ csrf_token(request) }}"><button type="submit">退出</button></form>
        {% else %}
            <a href="/login">登录</a><a href="/register">注册</a>
        {% endif %}
    </div>
</header>
<main class="page-shell px-3 px-xl-4 py-3 py-lg-4">
    {% if flash %}<div class="alert alert-{{ flash.category }} alert-dismissible fade show mb-3" role="alert">{{ flash.message }}<button type="button" class="btn-close" data-bs-dismiss="alert"></button></div>{% endif %}
    {% block content %}{% endblock %}
</main>
<footer class="site-footer px-3 px-xl-4 py-4 mt-4">MediaHub · 图片与视频上传、展示与下载</footer>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>
<script>
(() => {
    const input = document.getElementById('liveSearchInput');
    const panel = document.getElementById('searchSuggest');
    if (!input || !panel) return;
    let timer = null;
    let controller = null;
    const escapeHtml = value => String(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
    const closePanel = () => { panel.hidden = true; panel.innerHTML = ''; };
    const render = data => {
        const media = data.media || [];
        const users = data.users || [];
        if (!media.length && !users.length) {
            panel.innerHTML = '<div class="suggest-empty">没有找到相近结果</div>';
            panel.hidden = false;
            return;
        }
        let html = '';
        if (media.length) {
            html += '<div class="suggest-title">作品</div>';
            html += media.map(item => `<a class="suggest-item" href="/media/${item.id}"><span class="suggest-icon">${item.media_type === 'video' ? '▶' : '▧'}</span><span class="suggest-copy"><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml(item.owner)}</small></span></a>`).join('');
        }
        if (users.length) {
            html += '<div class="suggest-title">用户</div>';
            html += users.map(user => `<a class="suggest-item" href="/user/${user.id}"><span class="suggest-avatar">${escapeHtml(user.username.slice(0,1).toUpperCase())}</span><span class="suggest-copy"><strong>${escapeHtml(user.username)}</strong><small>用户</small></span></a>`).join('');
        }
        html += `<a class="suggest-all" href="/?q=${encodeURIComponent(data.query)}">查看全部搜索结果</a>`;
        panel.innerHTML = html;
        panel.hidden = false;
    };
    const refresh = () => {
        const query = input.value.trim();
        if (!query) return closePanel();
        if (controller) controller.abort();
        controller = new AbortController();
        fetch(`/api/search?q=${encodeURIComponent(query)}`, {signal: controller.signal})
            .then(response => response.ok ? response.json() : Promise.reject())
            .then(render).catch(error => { if (error && error.name !== 'AbortError') closePanel(); });
    };
    input.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(refresh, 140); });
    input.addEventListener('focus', () => { if (input.value.trim()) refresh(); });
    document.addEventListener('click', event => { if (!event.target.closest('.search-shell')) closePanel(); });
    document.addEventListener('keydown', event => { if (event.key === 'Escape') closePanel(); });
})();
</script>
</body>
</html>
''',
    'index.html': '''{% extends "base.html" %}
{% block title %}MediaHub - 首页{% endblock %}
{% block content %}
<section class="channel-strip mb-4">
    <div class="channel-title"><div class="channel-logo">M</div><div><strong>公开作品</strong><span>按最新上传时间展示</span></div></div>
    <div class="channel-links"><a class="{% if kind == 'all' %}active{% endif %}" href="/?q={{ q }}">全部 <span>{{ public_count }}</span></a><a class="{% if kind == 'video' %}active{% endif %}" href="/?kind=video&q={{ q }}">视频 <span>{{ video_count }}</span></a><a class="{% if kind == 'image' %}active{% endif %}" href="/?kind=image&q={{ q }}">图片 <span>{{ image_count }}</span></a>{% if current_user %}<a href="/upload">+ 上传</a>{% endif %}</div>
</section>
{% if q and user_results %}
<section class="search-users mb-4">
    <div class="section-heading mb-2"><div><h2>相关用户</h2><p>用户名中包含“{{ q }}”</p></div><span class="result-count">{{ user_results|length }} 个</span></div>
    <div class="user-result-row">{% for user in user_results %}<a class="user-result-card" href="/user/{{ user.id }}"><span class="mini-avatar">{{ user.username[:1]|upper }}</span><span><strong>{{ user.username }}</strong><small>查看主页</small></span></a>{% endfor %}</div>
</section>
{% endif %}
<div class="section-heading mb-3"><div><h1>{% if q %}“{{ q }}”的搜索结果{% else %}最新作品{% endif %}</h1><p>{% if q %}搜索作品标题和作者用户名{% else %}只展示当前公开的图片和视频{% endif %}</p></div><span class="result-count">共 {{ items|length }} 个</span></div>
{% if items %}
<div class="media-grid">{% for item in items %}<article class="media-card"><a href="/media/{{ item.id }}" class="media-thumb">{% if item.media_type == "image" %}<img src="/content/{{ item.id }}" alt="{{ item.title }}" loading="lazy">{% else %}<video muted preload="metadata"><source src="/content/{{ item.id }}" type="{{ item.mime_type }}"></video><span class="video-badge">▶ 视频</span>{% endif %}</a><div class="media-card-body"><h2><a href="/media/{{ item.id }}">{{ item.title }}</a></h2><div class="card-meta"><a class="owner-link" href="/user/{{ item.owner.id }}"><span class="tiny-avatar">{{ item.owner.username[:1]|upper }}</span>{{ item.owner.username }}</a><a class="quick-download" href="/download/{{ item.id }}" title="下载原文件">下载</a></div></div></article>{% endfor %}</div>
{% else %}<div class="empty-panel"><div class="empty-icon">⌕</div><h2>没有找到内容</h2><p>可以尝试其他作品标题或用户名。</p>{% if current_user %}<a href="/upload" class="btn btn-primary">上传作品</a>{% endif %}</div>{% endif %}
{% endblock %}
''',
    'login.html': '''{% extends "base.html" %}
{% block title %}登录 - MediaHub{% endblock %}
{% block content %}
<div class="auth-page">
    <section class="auth-card">
        <a class="auth-brand" href="/"><span>▶</span> MediaHub</a>
        <div class="auth-heading"><h1>登录</h1><p>登录后即可投稿、评论和管理自己的作品。</p></div>
        <form method="post" action="/login" class="auth-form">
            <input type="hidden" name="csrf" value="{{ csrf_token(request) }}">
            <label>用户名<input class="form-control" name="username" autocomplete="username" required autofocus></label>
            <label>密码<input class="form-control" type="password" name="password" autocomplete="current-password" required></label>
            <button class="btn btn-primary w-100" type="submit">登录</button>
        </form>
        <div class="auth-foot">还没有账号？<a href="/register">立即注册</a></div>
    </section>
</div>
{% endblock %}
''',
    'media_detail.html': '''{% extends "base.html" %}
{% block title %}{{ item.title }} - MediaHub{% endblock %}
{% block content %}
{% if not item.is_visible %}<div class="alert hidden-notice mb-3">此作品当前<strong>未公开展示</strong>，只有作者本人和管理员可以查看。</div>{% endif %}
<div class="watch-layout">
    <section class="watch-main">
        <div class="viewer">
            {% if item.media_type == "video" %}<video controls preload="metadata"><source src="/content/{{ item.id }}" type="{{ item.mime_type }}">浏览器不支持该视频格式。</video>{% else %}<img class="detail-image" src="/content/{{ item.id }}" alt="{{ item.title }}">{% endif %}
        </div>
        <div class="watch-info">
            <h1>{{ item.title }}</h1>
            <div class="watch-submeta"><span>{{ item.created_at.strftime("%Y-%m-%d %H:%M") }}</span><span>{{ '图片' if item.media_type == 'image' else '视频' }}</span><span>{{ "%.2f"|format(item.file_size / 1024 / 1024) }} MB</span></div>
            <div class="action-row"><a href="/download/{{ item.id }}" class="btn btn-primary">下载原文件</a><a href="/user/{{ item.owner.id }}" class="btn btn-outline-primary">查看作者</a>{% if current_user and (current_user.id == item.user_id or current_user.is_admin) %}<form action="/media/{{ item.id }}/visibility" method="post"><input type="hidden" name="csrf" value="{{ csrf_token(request) }}"><button class="btn btn-outline-primary">{{ "隐藏作品" if item.is_visible else "公开作品" }}</button></form><form action="/media/{{ item.id }}/delete" method="post" onsubmit="return confirm('确定删除这个媒体文件吗？此操作不可恢复。')"><input type="hidden" name="csrf" value="{{ csrf_token(request) }}"><button class="btn btn-outline-danger">删除</button></form>{% endif %}</div>
        </div>
        <div class="author-panel"><a href="/user/{{ item.owner.id }}" class="avatar-circle small-avatar">{{ item.owner.username[:1]|upper }}</a><div class="author-copy"><a href="/user/{{ item.owner.id }}">{{ item.owner.username }}</a><span>{{ "公开作品" if item.is_visible else "未公开作品" }} · 原文件：{{ item.original_filename }}</span></div></div>
        {% if item.description %}<div class="description-box">{{ item.description }}</div>{% endif %}
        <section id="comments" class="comments-section">
            <div class="section-heading compact"><div><h2>评论</h2><p>{{ comments|length }} 条</p></div></div>
            {% if current_user %}<form action="/media/{{ item.id }}/comments" method="post" class="comment-form"><input type="hidden" name="csrf" value="{{ csrf_token(request) }}"><textarea class="form-control" name="content" rows="3" maxlength="1000" placeholder="写下评论……" required></textarea><div class="comment-submit"><span>最多 1000 个字符</span><button class="btn btn-primary">发表评论</button></div></form>{% else %}<div class="login-comment">请先 <a href="/login">登录</a> 后发表评论。</div>{% endif %}
            <div class="comment-list">{% for comment in comments %}<article class="comment-item"><a href="/user/{{ comment.author.id }}" class="tiny-avatar comment-avatar">{{ comment.author.username[:1]|upper }}</a><div class="comment-main"><div class="comment-head"><div><a href="/user/{{ comment.author.id }}">{{ comment.author.username }}</a><span>{{ comment.created_at.strftime("%Y-%m-%d %H:%M") }}</span></div>{% if current_user and (current_user.id == comment.user_id or current_user.id == item.user_id or current_user.is_admin) %}<form action="/comments/{{ comment.id }}/delete" method="post" onsubmit="return confirm('删除这条评论吗？')"><input type="hidden" name="csrf" value="{{ csrf_token(request) }}"><button class="comment-delete">删除</button></form>{% endif %}</div><div class="comment-content">{{ comment.content }}</div></div></article>{% else %}<div class="text-secondary py-4">还没有评论。</div>{% endfor %}</div>
        </section>
    </section>
</div>
{% endblock %}
''',
    'my_media.html': '''{% extends "base.html" %}
{% block title %}作品管理 - MediaHub{% endblock %}
{% block content %}
<div class="creator-layout">
    <aside class="creator-side"><div class="creator-user"><div class="avatar-circle">{{ current_user.username[:1]|upper }}</div><div><strong>{{ current_user.username }}</strong><span>{% if current_user.is_admin %}管理员{% else %}普通用户{% endif %}</span></div></div><a class="active" href="/my">作品管理</a><a href="/upload">上传作品</a><a href="/user/{{ current_user.id }}">个人主页</a>{% if current_user.is_admin %}<a href="/admin/users">用户管理</a>{% endif %}</aside>
    <section class="creator-main">
        <div class="section-heading"><div><h1>作品管理</h1><p>{{ items|length }} 个作品，其中 {{ visible_count }} 个公开展示</p></div><a href="/upload" class="btn btn-primary btn-sm">+ 上传作品</a></div>
        {% if items %}<div class="manage-list mt-3">{% for item in items %}<article class="manage-item"><a class="manage-thumb" href="/media/{{ item.id }}">{% if item.media_type == "image" %}<img src="/content/{{ item.id }}" alt="{{ item.title }}">{% else %}<video muted preload="metadata"><source src="/content/{{ item.id }}" type="{{ item.mime_type }}"></video>{% endif %}</a><div class="manage-copy"><h2><a href="/media/{{ item.id }}">{{ item.title }}</a></h2><div class="manage-meta"><span class="status-dot {{ 'public' if item.is_visible else 'hidden' }}">{{ '公开展示' if item.is_visible else '已隐藏' }}</span><span>{{ '图片' if item.media_type == 'image' else '视频' }}</span><span>{{ item.created_at.strftime("%Y-%m-%d") }}</span></div></div><div class="manage-actions"><a href="/download/{{ item.id }}" class="mini-manage-btn" title="下载原文件">↓ <span>下载</span></a><form action="/media/{{ item.id }}/visibility" method="post"><input type="hidden" name="csrf" value="{{ csrf_token(request) }}"><button class="mini-manage-btn visibility-btn" type="submit" title="{{ '隐藏作品' if item.is_visible else '显示作品' }}">{{ '◉' if item.is_visible else '○' }} <span>{{ '隐藏' if item.is_visible else '显示' }}</span></button></form><form action="/media/{{ item.id }}/delete" method="post" onsubmit="return confirm('确定永久删除这个作品吗？此操作无法恢复。')"><input type="hidden" name="csrf" value="{{ csrf_token(request) }}"><button class="mini-manage-btn danger" type="submit" title="删除作品">× <span>删除</span></button></form></div></article>{% endfor %}</div>{% else %}<div class="empty-panel mt-3"><h2>还没有作品</h2><p>上传图片或视频后，可以在这里统一下载、隐藏或删除。</p><a href="/upload" class="btn btn-primary">上传第一个作品</a></div>{% endif %}
    </section>
</div>
{% endblock %}
''',
    'profile.html': '''{% extends "base.html" %}
{% block title %}{{ profile_user.username }} - MediaHub{% endblock %}
{% block content %}
<section class="profile-banner"><div class="profile-main"><div class="avatar-circle profile-avatar">{{ profile_user.username[:1]|upper }}</div><div><h1>{{ profile_user.username }}</h1><p>加入于 {{ profile_user.created_at.strftime("%Y-%m-%d") }}{% if profile_user.is_admin %} · 管理员{% endif %} · {{ items|length }} 个可见作品</p></div></div></section>
<div class="profile-tabs"><span class="active">作品</span>{% if current_user and current_user.id == profile_user.id %}<a href="/my">作品管理</a><a href="/upload">上传</a>{% endif %}</div>
{% if items %}<div class="media-grid">{% for item in items %}<article class="media-card"><a href="/media/{{ item.id }}" class="media-thumb">{% if item.media_type == "image" %}<img src="/content/{{ item.id }}" alt="{{ item.title }}" loading="lazy">{% else %}<video muted preload="metadata"><source src="/content/{{ item.id }}" type="{{ item.mime_type }}"></video><span class="video-badge">▶ 视频</span>{% endif %}{% if not item.is_visible %}<span class="hidden-badge">未公开</span>{% endif %}</a><div class="media-card-body"><h2><a href="/media/{{ item.id }}">{{ item.title }}</a></h2><div class="card-meta"><span>{{ item.created_at.strftime("%Y-%m-%d") }}</span><a class="quick-download" href="/download/{{ item.id }}">下载</a></div></div></article>{% endfor %}</div>{% else %}<div class="empty-panel"><h2>暂无作品</h2><p>这个用户暂时没有可展示的内容。</p></div>{% endif %}
{% endblock %}
''',
    'register.html': '''{% extends "base.html" %}
{% block title %}注册 - MediaHub{% endblock %}
{% block content %}
<div class="auth-page">
    <section class="auth-card">
        <a class="auth-brand" href="/"><span>▶</span> MediaHub</a>
        <div class="auth-heading"><h1>创建账号</h1><p>注册后可以上传作品、评论并管理展示状态。</p></div>
        <form method="post" action="/register" class="auth-form">
            <input type="hidden" name="csrf" value="{{ csrf_token(request) }}">
            <label>用户名<input class="form-control" name="username" minlength="3" maxlength="50" autocomplete="username" required></label>
            <label>密码<input class="form-control" type="password" name="password" autocomplete="new-password" required><small>密码不设置长度限制。</small></label>
            <button class="btn btn-primary w-100" type="submit">注册</button>
        </form>
        <div class="auth-foot">已经有账号？<a href="/login">直接登录</a></div>
    </section>
</div>
{% endblock %}
''',
    'upload.html': '''{% extends "base.html" %}
{% block title %}上传 - MediaHub{% endblock %}
{% block content %}
<div class="creator-layout">
    <aside class="creator-side">
        <div class="creator-user"><div class="avatar-circle">{{ current_user.username[:1]|upper }}</div><div><strong>{{ current_user.username }}</strong><span>{% if current_user.is_admin %}管理员{% else %}普通用户{% endif %}</span></div></div>
        <a href="/my">作品管理</a><a class="active" href="/upload">上传作品</a><a href="/user/{{ current_user.id }}">个人主页</a>{% if current_user.is_admin %}<a href="/admin/users">用户管理</a>{% endif %}
    </aside>
    <section class="creator-main">
        <div class="section-heading"><div><h1>上传作品</h1><p>上传图片或视频，并选择是否公开展示</p></div></div>
        <form action="/upload" method="post" enctype="multipart/form-data" class="upload-panel">
            <input type="hidden" name="csrf" value="{{ csrf_token(request) }}">
            <div class="upload-drop">
                <div class="upload-symbol">＋</div>
                <h2>选择图片或视频</h2>
                <p>JPG / PNG / GIF / WebP · MP4 / WebM / MOV / M4V · 单文件最大 1 GiB</p>
                <input class="form-control" type="file" name="media_file" accept="image/jpeg,image/png,image/gif,image/webp,video/mp4,video/webm,video/quicktime" required>
            </div>
            <div class="upload-fields">
                <div><label class="form-label">作品标题</label><input class="form-control form-control-lg" name="title" maxlength="120" placeholder="给作品起一个清晰的标题" required></div>
                <div><label class="form-label">作品简介</label><textarea class="form-control" name="description" rows="7" placeholder="介绍一下这个作品……"></textarea></div>
                <div class="form-check form-switch"><input class="form-check-input" type="checkbox" role="switch" id="isVisible" name="is_visible" value="true" checked><label class="form-check-label" for="isVisible">上传后公开展示</label><div class="form-text">关闭后只有你和管理员可查看，之后可以在创作中心重新公开。</div></div>
                <button class="btn btn-primary btn-lg upload-submit">开始上传</button>
            </div>
        </form>
    </section>
</div>
{% endblock %}
'''
}

# ==================== FastAPI ====================
app = FastAPI(title="MediaHub", version="1.7.0")
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("MEDIAHUB_SECRET_KEY", "dev-" + secrets.token_hex(32)),
    same_site="lax",
    https_only=False,
)
template_env = Environment(loader=DictLoader(EMBEDDED_TEMPLATES), autoescape=select_autoescape(["html", "xml"]))
templates = Jinja2Templates(env=template_env)


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



@app.get("/", response_class=HTMLResponse)
def index(
    request: Request,
    q: str = "",
    kind: str = "all",
    db: Session = Depends(get_db),
):
    query = q.strip()
    stmt = select(Media).options(joinedload(Media.owner)).where(Media.is_visible.is_(True))
    if kind in {"image", "video"}:
        stmt = stmt.where(Media.media_type == kind)

    items = db.scalars(stmt.order_by(desc(Media.created_at))).unique().all()
    user_results = []
    if query:
        keyword = query.casefold()
        items = [
            item for item in items
            if keyword in item.title.casefold()
            or (item.owner and keyword in item.owner.username.casefold())
        ]
        users = db.scalars(select(User).order_by(desc(User.created_at))).all()
        user_results = [user for user in users if keyword in user.username.casefold()][:12]

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
    """顶部实时搜索：按标题、作者名和用户名做直接包含匹配。"""
    query = q.strip()
    if not query:
        return {"query": "", "media": [], "users": []}

    keyword = query.casefold()
    media_items = db.scalars(
        select(Media)
        .options(joinedload(Media.owner))
        .where(Media.is_visible.is_(True))
        .order_by(desc(Media.created_at))
    ).unique().all()
    media_items = [
        item for item in media_items
        if keyword in item.title.casefold()
        or (item.owner and keyword in item.owner.username.casefold())
    ][:8]
    users = db.scalars(select(User).order_by(desc(User.created_at))).all()
    users = [user for user in users if keyword in user.username.casefold()][:6]

    return {
        "query": query,
        "media": [
            {"id": item.id, "title": item.title, "owner": item.owner.username, "media_type": item.media_type}
            for item in media_items
        ],
        "users": [{"id": user.id, "username": user.username} for user in users],
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


    return templates.TemplateResponse(
        "media_detail.html",
        template_context(request, db, item=item, comments=comments),
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

    visible_count = sum(1 for item in items if item.is_visible)
    return templates.TemplateResponse(
        "my_media.html",
        template_context(request, db, items=items, visible_count=visible_count),
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

    return templates.TemplateResponse(
        "profile.html",
        template_context(request, db, profile_user=profile_user, items=items),
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
def admin_users(request: Request, q: str = "", db: Session = Depends(get_db)):
    user = current_user(request, db)
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")

    query = q.strip()
    users = db.scalars(select(User).order_by(desc(User.created_at))).all()
    if query:
        keyword = query.casefold()
        users = [item for item in users if keyword in item.username.casefold()]
    media_counts = dict(db.execute(select(Media.user_id, func.count(Media.id)).group_by(Media.user_id)).all())
    comment_counts = dict(db.execute(select(Comment.user_id, func.count(Comment.id)).group_by(Comment.user_id)).all())
    return templates.TemplateResponse(
        "admin_users.html",
        template_context(
            request, db, users=users, q=query, media_counts=media_counts, comment_counts=comment_counts,
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


@app.post("/admin/users/{user_id}/delete")
def delete_user(
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
        flash(request, "不能删除当前登录的管理员账号。", "warning")
        return RedirectResponse("/admin/users", status_code=303)

    for item in list(target.media_items):
        media_path(item).unlink(missing_ok=True)
    username = target.username
    db.delete(target)
    db.commit()
    flash(request, f"用户 {username} 已删除。", "success")
    return RedirectResponse("/admin/users", status_code=303)


@app.get("/health")
def health():
    return {"status": "ok", "version": "1.7.0"}

if __name__ == "__main__":
    import uvicorn
    threading.Timer(1.0, lambda: webbrowser.open("http://127.0.0.1:8000")).start()
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
