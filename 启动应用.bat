@echo off
chcp 65001 >nul
cd /d "%~dp0"
set ELECTRON_RUN_AS_NODE=

if not exist "%~dp0dist\index.html" (
  echo 首次启动，正在构建前端资源...
  call npm run build
)

start "" "%~dp0node_modules\electron\dist\electron.exe" "%~dp0"
exit
