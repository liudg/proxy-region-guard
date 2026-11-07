@echo off
chcp 65001 >nul
cd /d "%~dp0"
set ELECTRON_RUN_AS_NODE=

:: 检测是否具备管理员权限（强杀 Session 0 系统服务 cowork-svc.exe 需要管理员权限）
fltmc >nul 2>&1
if %errorlevel% neq 0 (
  powershell -NoProfile -WindowStyle Hidden -Command "Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0' -Verb RunAs"
  exit /b
)

set NEED_BUILD=0
if not exist "%~dp0dist\index.html" set NEED_BUILD=1
if not exist "%~dp0dist-electron\main.js" set NEED_BUILD=1

if "%NEED_BUILD%"=="1" (
  echo 检测到构建产物缺失，正在编译前后端资源...
  call npm run build
)

start "" "%~dp0node_modules\electron\dist\electron.exe" "%~dp0"
exit
