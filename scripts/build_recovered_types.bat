@echo off
setlocal EnableExtensions
set "TASK_ROOT=%~dp0.."
for %%I in ("%TASK_ROOT%") do set "TASK_ROOT=%%~fI"
set "TASK_MODE=analyze"
set "TASK_ASAN=OFF"
if "%~1"=="" goto mode_ready
if /I not "%~1"=="--asan" goto invalid_args
set "TASK_MODE=asan"
set "TASK_ASAN=ON"
:mode_ready
set "TASK_VS_ROOT=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools"
if defined ROME2_VS_ROOT set "TASK_VS_ROOT=%ROME2_VS_ROOT%"
set "TASK_CMAKE=%TASK_VS_ROOT%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
set "TASK_CTEST=%TASK_VS_ROOT%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe"
set "TASK_NINJA=%TASK_VS_ROOT%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"
set "TASK_OUT=%TASK_ROOT%\out\recovered-types-%TASK_MODE%"
if not exist "%TASK_CMAKE%" goto missing_toolchain
if not exist "%TASK_CTEST%" goto missing_toolchain
if not exist "%TASK_NINJA%" goto missing_toolchain
call "%TASK_VS_ROOT%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 exit /b 1
set "CL="
set "_CL_="
"%TASK_CMAKE%" -S "%TASK_ROOT%\port\recovered_types" -B "%TASK_OUT%" -G Ninja -DCMAKE_MAKE_PROGRAM="%TASK_NINJA%" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -DROME2_TYPES_ASAN=%TASK_ASAN%
if errorlevel 1 exit /b 1
"%TASK_CMAKE%" --build "%TASK_OUT%"
if errorlevel 1 exit /b 1
"%TASK_CTEST%" --test-dir "%TASK_OUT%" --output-on-failure --no-tests=error
exit /b %ERRORLEVEL%
:missing_toolchain
echo The Visual Studio 2026 x64 CMake and Ninja toolchain was not found at "%TASK_VS_ROOT%".
exit /b 2
:invalid_args
echo Usage: scripts\build_recovered_types.bat [--asan]
exit /b 2
