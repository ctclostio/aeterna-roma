@echo off
set JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-25.0.4.101-hotspot
set PATH=%JAVA_HOME%\bin;%PATH%
X:\decompilation\ghidra_12.1.3_PUBLIC\support\analyzeHeadless.bat %*
