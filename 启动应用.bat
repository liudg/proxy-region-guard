@echo off
chcp 65001 >nul
cd /d "%~dp0"
set ELECTRON_RUN_AS_NODE=

set NEED_BUILD=0
if not exist "%~dp0dist\index.html" set NEED_BUILD=1
if not exist "%~dp0dist-electron\main.js" set NEED_BUILD=1

if "%NEED_BUILD%"=="1" (
  echo 检测到构建产物缺失，正在编译前后端资源...
  call npm run build
)

start "" "%~dp0node_modules\electron\dist\electron.exe" "%~dp0"
exit
