@echo off
REM analyze_dll.bat - import + full auto-analysis of empire.retail.dll (long-running)
set JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-25.0.4.101-hotspot
set PATH=%JAVA_HOME%\bin;%PATH%
X:\decompilation\ghidra_12.1.3_PUBLIC\support\analyzeHeadless.bat X:\decompilation\workspace TW2 -import "X:\decompilation\Total War Rome II\empire.retail.dll" -overwrite -processor x86:LE:32:default -analysisTimeoutPerFile 28800
