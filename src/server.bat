@echo off
chcp 65001 > nul
title SecureChat - Servidor
cls
cd /d %~dp0
..\bin\server.exe --config=server.xml
pause
