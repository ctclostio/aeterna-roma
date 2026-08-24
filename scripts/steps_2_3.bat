@echo off
REM steps_2_3.bat - run inventory + decompile export on already-analyzed DLL
set JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-25.0.4.101-hotspot
set PATH=%JAVA_HOME%\bin;%PATH%
set _JAVA_OPTIONS=-Xmx24g -Xms4g
set AH=X:\decompilation\ghidra_12.1.3_PUBLIC\support\analyzeHeadless.bat
set SP=X:\decompilation\scripts

echo === STEP 2: class/RTTI/function-name inventory ===
call %AH% X:\decompilation\workspace TW2 -process "empire.retail.dll" -noanalysis -scriptPath "%SP%" -postScript ExportClassInventory.java "X:\decompilation\src_out" || goto :fail

echo === STEP 3: full decompilation export (resumable) ===
call %AH% X:\decompilation\workspace TW2 -process "empire.retail.dll" -noanalysis -scriptPath "%SP%" -postScript ExportAllDecompiled.java "X:\decompilation\src_out" || goto :fail

echo === PIPELINE COMPLETE ===
exit /b 0
:fail
echo === PIPELINE FAILED at step above ===
exit /b 1
