@echo off
setlocal
for %%I in ("%~dp0..\..") do set "ROOT=%%~fI"
set "OUT=%ROOT%\out\terminal-runtime-e2e"
if not exist "%OUT%" mkdir "%OUT%"
if not exist "%OUT%\" exit /b 1
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 exit /b 1
pushd "%OUT%"
if errorlevel 1 exit /b 1
cl /nologo /std:c11 /W4 /WX /I"%ROOT%\port\x64_ported" "%ROOT%\tests\terminal_runtime\main.c" "%ROOT%\port\x64_ported\ported_100edd70_terminal_transcript.c" /Fe:terminal_runner.exe
if errorlevel 1 (popd & exit /b 1)
python "%ROOT%\tests\terminal_runtime\test_runner.py" "%OUT%\terminal_runner.exe"
set "RESULT=%ERRORLEVEL%"
popd
exit /b %RESULT%
