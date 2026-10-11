@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "TASK_ROOT=%~dp0.."
for %%I in ("%TASK_ROOT%") do set "TASK_ROOT=%%~fI"
set "TASK_SNAPSHOT=!TASK_ROOT!\src_canonical_out\empire.retail.dll\canonical_snapshot.tsv"
set "TASK_VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "TASK_VS_ROOT=%ROME2_VS_ROOT%"

if not exist "!TASK_SNAPSHOT!" goto missing_snapshot
for /f "usebackq skip=1 tokens=3" %%I in ("!TASK_SNAPSHOT!") do if not defined TASK_FINGERPRINT set "TASK_FINGERPRINT=%%I"
if not defined TASK_FINGERPRINT goto malformed_snapshot
set "TASK_STAGE=!TASK_ROOT!\generated\canonical\!TASK_FINGERPRINT!"
if not exist "!TASK_STAGE!\validation_summary.json" goto missing_stage

if defined TASK_VS_ROOT goto have_vs_root
if not exist "!TASK_VSWHERE!" goto use_default_vs_root
for /f "usebackq delims=" %%I in (`"!TASK_VSWHERE!" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "TASK_VS_ROOT=%%I"
if defined TASK_VS_ROOT goto have_vs_root

:use_default_vs_root
set "TASK_VS_ROOT=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools"

:have_vs_root
set "TASK_VCVARS=!TASK_VS_ROOT!\VC\Auxiliary\Build\vcvars64.bat"
if defined ROME2_VCVARS64 set "TASK_VCVARS=%ROME2_VCVARS64%"
if not exist "!TASK_VCVARS!" goto missing_vcvars

call "!TASK_VCVARS!" >nul 2>&1
if not "!ERRORLEVEL!"=="0" goto vcvars_failed

pushd "!TASK_ROOT!" >nul
python -B scripts\gen_compile_island.py "!TASK_STAGE!" --compiler cl.exe ^
  --base-compat src\include\ghidra_compat.h %*
set "TASK_RC=!ERRORLEVEL!"
popd >nul
exit /b !TASK_RC!

:missing_snapshot
echo Canonical snapshot not found: !TASK_SNAPSHOT!
exit /b 2

:malformed_snapshot
echo Canonical snapshot does not contain a mapping fingerprint: !TASK_SNAPSHOT!
exit /b 2

:missing_stage
echo Immutable canonical stage not found: !TASK_STAGE!
exit /b 2

:missing_vcvars
echo MSVC x64 environment script not found: !TASK_VCVARS!
exit /b 2

:vcvars_failed
echo Failed to initialize the MSVC x64 environment.
exit /b 1
