@echo off
chcp 65001 > nul
title SecureChat - Cliente
cls
cd /d %~dp0
..\bin\client.exe --config=..\src\client.xml
pause
