@echo off
setlocal EnableExtensions EnableDelayedExpansion
set "ROOT=X:\decompilation"
set "GHIDRA=%ROOT%\ghidra_12.1.3_PUBLIC\support\analyzeHeadless.bat"
set "PROJECT=%ROOT%\workspace"
set "SCRIPT_DIR=%ROOT%\scripts"
set "OUT=%ROOT%\src_canonical_out"
set "STATUS=%OUT%\empire.retail.dll\canonical_export_status.tsv"
set "ROLLBACK_STATUS=%OUT%\empire.retail.dll\canonical_rollback_status.tsv"

if not "%~5"=="" goto :usage
if "%~1"=="" (
  if not "%~2"=="" goto :usage
  if not "%~3"=="" goto :usage
  if not "%~4"=="" goto :usage
) else (
  if "%~2"=="" goto :usage
  if "%~3"=="" if not "%~4"=="" goto :usage
)
goto :arguments_valid

:usage
echo Usage: %~nx0 [batchStart batchEnd [timeoutSeconds retryTimeoutSeconds]]
exit /b 2

:arguments_valid
if exist "%STATUS%" del /q "%STATUS%"
if exist "%ROLLBACK_STATUS%" del /q "%ROLLBACK_STATUS%"

if "%~1"=="" (
  call "%GHIDRA%" "%PROJECT%" TW2 -process empire.retail.dll -noanalysis ^
    -scriptPath "%SCRIPT_DIR%" -postScript ExportCanonicalDecompiled.java "%OUT%"
  set "EXPORT_RC=!ERRORLEVEL!"
) else (
  if "%~3"=="" (
    call "%GHIDRA%" "%PROJECT%" TW2 -process empire.retail.dll -noanalysis ^
      -scriptPath "%SCRIPT_DIR%" -postScript ExportCanonicalDecompiled.java "%OUT%" "%~1" "%~2"
  ) else (
    call "%GHIDRA%" "%PROJECT%" TW2 -process empire.retail.dll -noanalysis ^
      -scriptPath "%SCRIPT_DIR%" -postScript ExportCanonicalDecompiled.java "%OUT%" ^
      "%~1" "%~2" "%~3" "%~4"
  )
  set "EXPORT_RC=!ERRORLEVEL!"
)

rem Always verify rollback, including after exporter errors/cancellation.
call "%GHIDRA%" "%PROJECT%" TW2 -process empire.retail.dll -noanalysis ^
  -scriptPath "%SCRIPT_DIR%" -postScript VerifyCanonicalRollback.java "%OUT%"
set "VERIFY_RC=!ERRORLEVEL!"

set "EXPORT_STATE=missing"
set "FAILED_COUNT=unknown"
if exist "%STATUS%" (
  for /f "usebackq skip=1 tokens=1,9" %%A in ("%STATUS%") do (
    set "EXPORT_STATE=%%A"
    set "FAILED_COUNT=%%B"
  )
)

set "ROLLBACK_STATE=missing"
if exist "%ROLLBACK_STATUS%" (
  for /f "usebackq skip=1 tokens=1" %%A in ("%ROLLBACK_STATUS%") do set "ROLLBACK_STATE=%%A"
)

set "FINAL_RC=0"
if not "!EXPORT_RC!"=="0" (
  echo Canonical exporter process failed with exit code !EXPORT_RC!.
  set "FINAL_RC=1"
)
if not "!EXPORT_STATE!"=="export_ok" (
  echo Canonical exporter did not complete successfully. State=!EXPORT_STATE!.
  set "FINAL_RC=1"
)
if not "!FAILED_COUNT!"=="0" (
  echo Canonical exporter has !FAILED_COUNT! failed decompilations in this batch.
  set "FINAL_RC=1"
)
if not "!VERIFY_RC!"=="0" (
  echo Canonical rollback verifier process failed with exit code !VERIFY_RC!.
  set "FINAL_RC=1"
)
if not "!ROLLBACK_STATE!"=="ok" (
  echo Canonical rollback verification failed or is missing. State=!ROLLBACK_STATE!.
  set "FINAL_RC=1"
)
if not exist "%ROLLBACK_STATUS%" (
  echo Canonical rollback verifier did not write a status file.
  set "FINAL_RC=1"
)

exit /b !FINAL_RC!
