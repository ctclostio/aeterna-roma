@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "TASK_ROOT=%~dp0.."
for %%I in ("%TASK_ROOT%") do set "TASK_ROOT=%%~fI"
set "TASK_OUT=%TASK_ROOT%\out\x64-bootstrap"
if defined ROME2_BUILD_DIR set "TASK_OUT=%ROME2_BUILD_DIR%"
for %%I in ("!TASK_OUT!") do set "TASK_OUT=%%~fI"
set "TASK_BUILD_TESTING=ON"
if defined ROME2_BUILD_TESTING set "TASK_BUILD_TESTING=%ROME2_BUILD_TESTING%"
if /I not "!TASK_BUILD_TESTING!"=="ON" if /I not "!TASK_BUILD_TESTING!"=="OFF" goto invalid_build_testing
set "TASK_VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "TASK_VS_ROOT=%ROME2_VS_ROOT%"

if defined TASK_VS_ROOT goto have_vs_root
if not exist "!TASK_VSWHERE!" goto use_default_vs_root
for /f "usebackq delims=" %%I in (`"!TASK_VSWHERE!" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "TASK_VS_ROOT=%%I"
if defined TASK_VS_ROOT goto have_vs_root

:use_default_vs_root
set "TASK_VS_ROOT=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools"

:have_vs_root
set "TASK_VCVARS=!TASK_VS_ROOT!\VC\Auxiliary\Build\vcvars64.bat"
set "TASK_CMAKE_EXE=!TASK_VS_ROOT!\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
set "TASK_CTEST_EXE=!TASK_VS_ROOT!\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe"
set "TASK_NINJA_EXE=!TASK_VS_ROOT!\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"
if defined ROME2_VCVARS64 set "TASK_VCVARS=%ROME2_VCVARS64%"
if defined ROME2_CMAKE_EXE set "TASK_CMAKE_EXE=%ROME2_CMAKE_EXE%"
if defined ROME2_CTEST_EXE set "TASK_CTEST_EXE=%ROME2_CTEST_EXE%"
if defined ROME2_NINJA_EXE set "TASK_NINJA_EXE=%ROME2_NINJA_EXE%"

for %%I in ("!TASK_CMAKE_EXE!") do set "TASK_CMAKE_BIN=%%~dpI"
for %%I in ("!TASK_NINJA_EXE!") do set "TASK_NINJA_BIN=%%~dpI"

if not exist "!TASK_VCVARS!" goto missing_vcvars
if not exist "!TASK_CMAKE_EXE!" goto missing_cmake
if not exist "!TASK_CTEST_EXE!" goto missing_ctest
if not exist "!TASK_NINJA_EXE!" goto missing_ninja

call "!TASK_VCVARS!" >nul 2>&1
if not "%ERRORLEVEL%"=="0" goto vcvars_failed

set "PATH=!TASK_CMAKE_BIN!;!TASK_NINJA_BIN!;!PATH!"

"!TASK_CMAKE_EXE!" -S "!TASK_ROOT!" -B "!TASK_OUT!" ^
  -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=!TASK_BUILD_TESTING!
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%

"!TASK_CMAKE_EXE!" --build "!TASK_OUT!" --config Release
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%

if /I "!TASK_BUILD_TESTING!"=="OFF" goto build_without_tests_succeeded

"!TASK_CTEST_EXE!" --test-dir "!TASK_OUT!" -C Release ^
  --output-on-failure --no-tests=error
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%

echo CMake bootstrap build and load smoke test passed: !TASK_OUT!\empire.retail64.dll
exit /b 0

:build_without_tests_succeeded
echo CMake release build passed with BUILD_TESTING=OFF: !TASK_OUT!\empire.retail64.dll
exit /b 0

:missing_vcvars
echo MSVC x64 environment script not found: !TASK_VCVARS!
exit /b 2

:missing_cmake
echo CMake not found: !TASK_CMAKE_EXE!
exit /b 2

:missing_ctest
echo CTest not found: !TASK_CTEST_EXE!
exit /b 2

:missing_ninja
echo Ninja not found: !TASK_NINJA_EXE!
exit /b 2

:vcvars_failed
echo Failed to initialize the MSVC x64 environment.
exit /b 1

:invalid_build_testing
echo ROME2_BUILD_TESTING must be ON or OFF; got: !TASK_BUILD_TESTING!
exit /b 2
