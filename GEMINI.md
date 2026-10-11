# Antigravity Project Instructions: Total War Rome II Decompilation

## Project Overview
This repository (`X:\decompilation`) is a long-horizon project to decompile and reconstruct Total War: Rome II (specifically `empire.retail.dll` - 28 MB x86 PE32) into a native, modern 64-bit C/C++ codebase.

## Approved Tools & Command Execution Allowlist
The agent is authorized and encouraged to execute the following toolchains without interactive interruptions:

### 1. Reverse Engineering & Decompilation (REA & Ghidra)
- `rea <command>`: REA CLI (v6.4.0) configured with the `ghidra` provider.
- `npx -y rea-agents@latest <command>`: Fallback REA invocation.
- `java`: Eclipse Adoptium OpenJDK 25 (`C:\Program Files\Eclipse Adoptium\jdk-25.0.4.101-hotspot`).
- `analyzeHeadless.bat`: Ghidra 12.1.3 headless batch runner in `ghidra_12.1.3_PUBLIC\support`.
- Python scripts in `scripts/` and `work/` for metadata parsing and function classification.

### 2. Compilation, Build & Test
- `cmake` and `ninja`: x64 build configuration and test harnesses.
- `cl.exe`, `link.exe`, `dumpbin.exe`: MSVC Hostx64/x64 compiler toolset.
- `ctest`: Automated unit and ABI regression testing.

### 3. File System & Automation
- PowerShell (`pwsh` / `powershell`): File search, string extraction, data pipelines.
- `git`: Version control and patch tracking.

## Reverse Engineering Guidelines with REA
1. **Evidence-First Reconstruction**:
   - Always verify assumptions using REA evidence (`rea decompile`, `rea function`, `rea xrefs`, `rea inspect-native-api`, `rea trace-native-values`).
   - Every semantic claim about binary behavior must link back to recovered addresses, string anchors, or call xrefs.
2. **x86 to x64 Porting Rules**:
   - Normalize x86 `__thiscall` (ECX as this) to standard x64 calling convention (`RCX`).
   - Abstract 32-bit pointer arithmetic and serialized struct layouts cleanly.
   - Validate against the 522-export contract in `docs/x64_export_contract.md`.
3. **Strict Syntax & Compile Gate**:
   - All ported routines must compile cleanly under the strict x64 syntax gate before integration into core modules.
