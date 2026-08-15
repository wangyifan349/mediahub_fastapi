@echo off
chcp 65001 >nul
cd /d "%~dp0"
title MediaHub Server

echo ========================================
echo MediaHub 正在启动
echo 本机访问: http://127.0.0.1:8000
echo 局域网访问: http://本机IP:8000
echo 监听地址: 0.0.0.0:8000
echo ========================================
echo.

python main.py

echo.
echo MediaHub 已停止，或启动时发生错误。
pause
