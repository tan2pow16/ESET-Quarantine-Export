@echo off
windres.exe -O coff -o %~dp0cache\export.res %~dp0res\export.rc
gcc.exe -o %~dp0bin\export.exe %~dp0src\export.c %~dp0cache\export.res -lz -s
pause
