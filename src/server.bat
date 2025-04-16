@echo off
chcp 65001 > nul
title SecureChat - Servidor
cls
cd /d %~dp0
echo [.] Ejecutando desde: %cd%
..\bin\server.exe --config=server.xml
pause
