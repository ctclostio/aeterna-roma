@echo off
REM test_compile.bat - compile N sample decompiled files with MSVC x64
set JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-25.0.4.101-hotspot
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
set INC=X:\decompilation\src\include
set OUTDIR=X:\decompilation\build_test
if not exist %OUTDIR% mkdir %OUTDIR%
cd /d X:\decompilation

set /a COUNT=0
set /a OK=0
set /a FAIL=0
for /f "tokens=1 delims=" %%F in ('python scripts/pick_samples.py') do (
  set /a COUNT+=1
  cl /nologo /c /W0 /EHsc /I "%INC%" "%%F" /Fo"%OUTDIR%\\" >nul 2>%OUTDIR%\last_err.txt
  if errorlevel 1 (set /a FAIL+=1) else (set /a OK+=1)
)
echo RESULT: compiled=!OK! failed=!FAIL! of !COUNT!
