[CmdletBinding()]
param(
    [ValidateSet('Start', 'Status', 'Collect', 'Stop')]
    [string]$Action = 'Status',
    [string]$RunId = '20260824-x64-wave1'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$taskSpecPath = Join-Path $PSScriptRoot 'pi_swarm_wave1.json'
$workerScript = Join-Path $PSScriptRoot 'pi_swarm_worker.ps1'
$runRoot = Join-Path $repositoryRoot (Join-Path 'out\pi-swarm' $RunId)
$promptRoot = Join-Path $runRoot 'prompts'
$reportRoot = Join-Path $runRoot 'reports'
$sessionRoot = Join-Path $runRoot 'sessions'
$statePath = Join-Path $runRoot 'workers.json'
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function Write-Utf8NoBom([string]$Path, [string]$Text) {
    [System.IO.File]::WriteAllText($Path, $Text, $utf8NoBom)
}

function Get-TaskPrompt($task) {
    $fingerprint = '0a7281990e144bc4ed54d432c4fd59aaa98b32c7bb9711e565bae2a304c2ff70'
    $policy = '8afc796a13d6959beac0d1a34370f4a071b25f2bc4f7d1cef17307d39afeb592'
    $common = @"
You are Pi swarm worker $($task.id), reporting to a Codex supervisor in X:\decompilation.
The project is a provenance-preserving decompilation of Total War: ROME II for a native x64 rebuild.

This first wave is STRICTLY READ-ONLY. Do not edit, create, delete, rename, or format repository files. Do not invent types, prototypes, object layouts, behavior, or ABI facts. Treat the original PE, immutable canonical stage, manifests, and compiler diagnostics as evidence. The current bootstrap is intentionally inert and gameplay is not linked.

Canonical fingerprint: $fingerprint
Current compile-island policy: $policy
Current island root: out/canonical-compile-islands/$fingerprint/$policy

Return a concrete engineering report with these headings:
1. Conclusion
2. Evidence (exact files, symbols, addresses, warning codes, and line numbers)
3. Risks and unknowns
4. Proposed implementation patch (file-by-file; do not apply it)
5. Verification plan
6. Recommended next owner/task

Be concise but technically complete. Explicitly distinguish proven facts from inference.
"@

    switch ($task.kind) {
        'tu' {
            $address = [string]$task.address
            return $common + @"

Your assigned translation unit is decomp_fn_$address.

Inspect its current island source, exact deps header, compiler log/response file, its joined_manifest.tsv row, references.tsv edges, and directly referenced canonical functions/data. Explain the recovered behavior and signature conservatively. Classify every x64 warning and every 32-bit assumption in this TU: integer-to-pointer, pointer-to-integer, parameter mismatch, truncation, sentinel, packed data, or likely decompiler artifact. Determine whether the TU can become a first genuinely ported source without widening guest 32-bit address cells. Propose the smallest explicit x64-safe rewrite and focused behavioral/unit tests. If evidence is insufficient, specify the exact Ghidra/PE query needed rather than guessing.
"@
        }
        'warning_triage' {
            return $common + @"

Audit all 16 current compile-island sources and logs as a set. Reproduce the 228-warning taxonomy, group warnings by root cause rather than code alone, identify shared fixes versus TU-local fixes, and rank the 16 roots for safest first admission into an x64 runtime target. Recommend a dependency-aware implementation order and acceptance gates that prevent warning suppression or blanket casts.
"@
        }
        'data_model' {
            return $common + @"

Design the narrow data model needed to port canonical x86 decompiler output into a native x64 process. Inspect ghidra_compat.h, compile-island policy/docs, representative sources/logs, and canonical metadata. Propose explicit types and APIs for guest_address32, guest_pointer32 storage, host pointers, handles, offsets, pointer translation, checked truncation, and packed layouts. Define what must remain 32-bit, what may become uintptr_t, and how tests/static assertions should prove the boundary. Avoid a global search-and-replace strategy.
"@
        }
        'exports' {
            return $common + @"

Design the next lossless export-contract integration step. Inspect port/x64_exports, the bootstrap DEF/CMake/host, and canonical export targets. Determine how to link all 522 names and ordinals while preserving the 44 alias groups and 29 DATA exports, without generic callable stubs or accidental ICF. Separate typed executable exports that can be implemented now from FaceFX/libcurl/data boundaries requiring real implementations or adapters. Propose generator/build/test changes and an incremental acceptance sequence.
"@
        }
        'startup' {
            return $common + @"

Plan safe reconstruction of startup and external dependencies. Inspect existing startup audit evidence, PE metadata, canonical indexes/references, CMake bootstrap policy, and any initializer-related scripts/docs. Propose how to extract and classify the 9,865 recovered initializer entries, identify dependency clusters and pure/safe candidates, and admit them incrementally under the new x64 CRT. Include a concrete dependency-boundary plan for Steam, D3D, OpenGL, Bink, OpenSSL, Twitch, WinMM, and DInput without linking legacy x86 binaries.
"@
        }
        default { throw "Unknown task kind: $($task.kind)" }
    }
}

function Read-State {
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        throw "Swarm state does not exist: $statePath"
    }
    return @(Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json)
}

function Get-WorkerState($worker) {
    if (Test-Path -LiteralPath $worker.exit_file -PathType Leaf) {
        $code = [int](Get-Content -LiteralPath $worker.exit_file -Raw).Trim()
        if ($code -eq 0) { return 'completed' }
        return 'failed'
    }
    if (Get-Process -Id $worker.pid -ErrorAction SilentlyContinue) { return 'running' }
    return 'lost'
}

if ($Action -eq 'Start') {
    if (Test-Path -LiteralPath $statePath) {
        throw "Run already exists; choose another -RunId or inspect it with -Action Status: $runRoot"
    }
    $tasks = @(Get-Content -LiteralPath $taskSpecPath -Raw | ConvertFrom-Json)
    if ($tasks.Count -ne 20) { throw "Wave one must contain exactly 20 tasks; found $($tasks.Count)" }
    if (@($tasks.id | Sort-Object -Unique).Count -ne $tasks.Count) { throw 'Task IDs are not unique' }

    $piCommand = (Get-Command pi.cmd -ErrorAction Stop).Source
    $pwshCommand = (Get-Command pwsh.exe -ErrorAction Stop).Source
    New-Item -ItemType Directory -Force -Path $promptRoot, $reportRoot, $sessionRoot | Out-Null

    $workers = @()
    foreach ($task in $tasks) {
        $promptPath = Join-Path $promptRoot ($task.id + '.md')
        $outputPath = Join-Path $reportRoot ($task.id + '.md')
        $errorPath = Join-Path $reportRoot ($task.id + '.err.txt')
        $exitPath = Join-Path $reportRoot ($task.id + '.exit.txt')
        $sessionId = "$RunId-$($task.id)"
        $workerName = "$RunId-$($task.id)"
        Write-Utf8NoBom $promptPath (Get-TaskPrompt $task)

        $arguments = @(
            '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
            '-File', $workerScript,
            '-PiCommand', $piCommand,
            '-RepositoryRoot', $repositoryRoot,
            '-TaskFile', $promptPath,
            '-OutputFile', $outputPath,
            '-ErrorFile', $errorPath,
            '-ExitFile', $exitPath,
            '-SessionDirectory', $sessionRoot,
            '-SessionId', $sessionId,
            '-WorkerName', $workerName
        )
        $process = Start-Process -FilePath $pwshCommand -ArgumentList $arguments `
            -WorkingDirectory $repositoryRoot -WindowStyle Hidden -PassThru
        $workers += [pscustomobject]@{
            id = [string]$task.id
            kind = [string]$task.kind
            title = [string]$task.title
            address = if ($task.address) { [string]$task.address } else { $null }
            pid = $process.Id
            session_id = $sessionId
            prompt_file = $promptPath
            output_file = $outputPath
            error_file = $errorPath
            exit_file = $exitPath
        }
        Write-Utf8NoBom $statePath (($workers | ConvertTo-Json -Depth 5) + "`n")
    }
    Write-Output "started=$($workers.Count) run=$runRoot model=openrouter/stealth/ox-alpha"
    $workers | Select-Object id, kind, address, pid | Format-Table -AutoSize
    exit 0
}

$workers = Read-State
if ($Action -eq 'Status') {
    $statusRows = foreach ($worker in $workers) {
        [pscustomobject]@{
            id = $worker.id
            kind = $worker.kind
            address = $worker.address
            pid = $worker.pid
            status = Get-WorkerState $worker
            output_bytes = if (Test-Path -LiteralPath $worker.output_file) {
                (Get-Item -LiteralPath $worker.output_file).Length
            } else { 0 }
            error_bytes = if (Test-Path -LiteralPath $worker.error_file) {
                (Get-Item -LiteralPath $worker.error_file).Length
            } else { 0 }
        }
    }
    $statusRows | Format-Table -AutoSize
    $statusRows | Group-Object status | Sort-Object Name | Select-Object Name, Count | Format-Table -AutoSize
    exit $(if (@($statusRows | Where-Object status -in @('failed', 'lost')).Count) { 1 } else { 0 })
}

if ($Action -eq 'Collect') {
    $incomplete = @($workers | Where-Object { (Get-WorkerState $_) -ne 'completed' })
    if ($incomplete.Count) {
        throw "Cannot collect: $($incomplete.Count) workers are not completed"
    }
    $collectedPath = Join-Path $runRoot 'collected_reports.md'
    $parts = @("# Pi swarm reports: $RunId", '')
    foreach ($worker in $workers) {
        $parts += "## $($worker.id): $($worker.title)"
        $parts += ''
        $parts += (Get-Content -LiteralPath $worker.output_file -Raw)
        $parts += ''
    }
    Write-Utf8NoBom $collectedPath (($parts -join "`n") + "`n")
    Write-Output "collected=$collectedPath workers=$($workers.Count)"
    exit 0
}

if ($Action -eq 'Stop') {
    $stopped = 0
    foreach ($worker in $workers) {
        if (-not (Test-Path -LiteralPath $worker.exit_file) -and
            (Get-Process -Id $worker.pid -ErrorAction SilentlyContinue)) {
            Stop-Process -Id $worker.pid -Force
            $stopped++
        }
    }
    Write-Output "stopped=$stopped run=$runRoot"
}
