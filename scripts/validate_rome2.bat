@echo off
REM validate_rome2.bat - import + analyze + decompile-export Rome2.exe
set JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-25.0.4.101-hotspot
set PATH=%JAVA_HOME%\bin;%PATH%
cd /d X:\decompilation
X:\decompilation\ghidra_12.1.3_PUBLIC\support\analyzeHeadless.bat X:\decompilation\workspace TW2 -import "X:\decompilation\Total War Rome II\Rome2.exe" -overwrite -scriptPath "X:\decompilation\scripts" -postScript ExportAllDecompiled.java "X:\decompilation\src_out"
