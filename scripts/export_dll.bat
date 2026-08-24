@echo off
REM export_dll.bat - decompile-export all functions from analyzed empire.retail.dll
REM Resumable: skips functions already exported successfully. Re-run after interruption.
set JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-25.0.4.101-hotspot
set PATH=%JAVA_HOME%\bin;%PATH%
X:\decompilation\ghidra_12.1.3_PUBLIC\support\analyzeHeadless.bat X:\decompilation\workspace TW2 -process "empire.retail.dll" -noanalysis -scriptPath "X:\decompilation\scripts" -postScript ExportAllDecompiled.java "X:\decompilation\src_out"
