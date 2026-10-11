[CmdletBinding()]
param(
    [ValidateSet('Start', 'Status', 'Collect', 'Stop', 'Retry')]
    [string]$Action = 'Status',
    [string]$RunId = '20260824-startup-code-bakeoff',
    [string]$WorkerId
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$workerScript = Join-Path $PSScriptRoot 'pi_swarm_worker.ps1'
$priorRunRoot = Join-Path $repositoryRoot 'out\pi-swarm\20260824-x64-wave1'
$priorSessionRoot = Join-Path $priorRunRoot 'sessions'
$specPath = Join-Path $repositoryRoot 'docs\startup_audit_spec.md'
$runRoot = Join-Path $repositoryRoot (Join-Path 'out\pi-swarm' $RunId)
$promptRoot = Join-Path $runRoot 'prompts'
$reportRoot = Join-Path $runRoot 'reports'
$candidateRoot = Join-Path $runRoot 'candidates'
$statePath = Join-Path $runRoot 'workers.json'
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$workerIds = 1..20 | ForEach-Object { 'w{0:d2}' -f $_ }

function Write-Utf8NoBom([string]$Path, [string]$Text) {
    [System.IO.File]::WriteAllText($Path, $Text, $utf8NoBom)
}

function Get-CandidatePrompt([string]$WorkerId, [string]$CandidatePath) {
    return @"
You are Pi ox-alpha worker $WorkerId in a supervised code-quality bake-off for
the Total War: ROME II x86-to-x64 decompilation at X:\decompilation.

Read docs/startup_audit_spec.md completely and implement that exact contract.
Your exclusive writable directory is:

$CandidatePath

Create exactly these submission files there:

1. gen_startup_audit.py
2. test_gen_startup_audit.py
3. README.md

You may read any repository evidence and use an OS temporary directory while
running tests. Do not create, edit, delete, rename, or format anything outside
your exclusive candidate directory. Do not edit canonical/generated inputs,
the shared specification, scripts, docs, build files, or another candidate.
Do not use git. Do not install packages. Do not make network requests.

Use only the Python standard library. Run your complete unittest suite and a
real-corpus generation followed by --check. Fix your own failures before
finishing. This is code, not a design report: do not stop after proposing an
implementation.

README.md must state the exact commands run, observed results, files produced,
known limitations, and any specification point you could not satisfy. Your
final response must concisely repeat test results and changed files. Never
claim a test passed unless you ran it and saw exit code zero.
"@
}

function Read-State {
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        throw "Bake-off state does not exist: $statePath"
    }
    return @(Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json)
}

function Get-WorkerState($worker) {
    if (Test-Path -LiteralPath $worker.exit_file -PathType Leaf) {
        $code = [int](Get-Content -LiteralPath $worker.exit_file -Raw).Trim()
        if ($code -eq 0) { return 'completed' }
        return 'failed'
    }
    if (Get-Process -Id $worker.pid -ErrorAction SilentlyContinue) {
        return 'running'
    }
    return 'lost'
}

if ($Action -eq 'Start') {
    if (Test-Path -LiteralPath $statePath) {
        throw "Run already exists; choose another -RunId or inspect it: $runRoot"
    }
    if (-not (Test-Path -LiteralPath $workerScript -PathType Leaf)) {
        throw "Missing worker script: $workerScript"
    }
    if (-not (Test-Path -LiteralPath $specPath -PathType Leaf)) {
        throw "Missing startup audit specification: $specPath"
    }
    if (-not (Test-Path -LiteralPath $priorSessionRoot -PathType Container)) {
        throw "Missing prior Pi sessions: $priorSessionRoot"
    }

    $piCommand = (Get-Command pi.cmd -ErrorAction Stop).Source
    $pwshCommand = (Get-Command pwsh.exe -ErrorAction Stop).Source
    New-Item -ItemType Directory -Force -Path $promptRoot, $reportRoot, $candidateRoot | Out-Null

    $workers = @()
    foreach ($workerId in $workerIds) {
        $candidatePath = Join-Path $candidateRoot $workerId
        $promptPath = Join-Path $promptRoot ($workerId + '.md')
        $outputPath = Join-Path $reportRoot ($workerId + '.md')
        $errorPath = Join-Path $reportRoot ($workerId + '.err.txt')
        $exitPath = Join-Path $reportRoot ($workerId + '.exit.txt')
        $sessionId = "20260824-x64-wave1-$workerId"
        New-Item -ItemType Directory -Force -Path $candidatePath | Out-Null
        Write-Utf8NoBom $promptPath (Get-CandidatePrompt $workerId $candidatePath)

        $arguments = @(
            '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
            '-File', $workerScript,
            '-PiCommand', $piCommand,
            '-RepositoryRoot', $repositoryRoot,
            '-TaskFile', $promptPath,
            '-OutputFile', $outputPath,
            '-ErrorFile', $errorPath,
            '-ExitFile', $exitPath,
            '-SessionDirectory', $priorSessionRoot,
            '-SessionId', $sessionId,
            '-WorkerName', "$RunId-$workerId",
            '-ToolAllowlist', 'read,grep,find,ls,write,edit,powershell'
        )
        $process = Start-Process -FilePath $pwshCommand -ArgumentList $arguments `
            -WorkingDirectory $repositoryRoot -WindowStyle Hidden -PassThru
        $workers += [pscustomobject]@{
            id = $workerId
            pid = $process.Id
            session_id = $sessionId
            candidate_dir = $candidatePath
            prompt_file = $promptPath
            output_file = $outputPath
            error_file = $errorPath
            exit_file = $exitPath
        }
        Write-Utf8NoBom $statePath (($workers | ConvertTo-Json -Depth 5) + "`n")
    }

    Write-Output "started=$($workers.Count) run=$runRoot model=openrouter/stealth/ox-alpha"
    $workers | Select-Object id, pid, candidate_dir | Format-Table -AutoSize
    exit 0
}

$workers = Read-State
if ($Action -eq 'Retry') {
    if (-not $WorkerId) { throw 'Retry requires -WorkerId' }
    $matches = @($workers | Where-Object id -eq $WorkerId)
    if ($matches.Count -ne 1) { throw "Unknown or duplicate worker ID: $WorkerId" }
    $worker = $matches[0]
    if ((Get-WorkerState $worker) -eq 'completed') {
        throw "Refusing to retry completed worker: $WorkerId"
    }

    $allProcesses = @(Get-CimInstance Win32_Process)
    $frontier = @([int]$worker.pid)
    $descendants = @()
    while ($frontier.Count) {
        $children = @($allProcesses | Where-Object ParentProcessId -in $frontier)
        $descendants += $children
        $frontier = @($children | ForEach-Object { [int]$_.ProcessId })
    }
    foreach ($processId in @($descendants | Select-Object -ExpandProperty ProcessId -Unique)) {
        Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
    }
    Stop-Process -Id $worker.pid -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500

    $attempt = 1
    while (Test-Path -LiteralPath ($worker.output_file + ".attempt$attempt")) { $attempt++ }
    foreach ($path in @($worker.output_file, $worker.error_file, $worker.exit_file)) {
        if (Test-Path -LiteralPath $path) {
            Move-Item -LiteralPath $path -Destination ($path + ".attempt$attempt")
        }
    }

    $piCommand = (Get-Command pi.cmd -ErrorAction Stop).Source
    $pwshCommand = (Get-Command pwsh.exe -ErrorAction Stop).Source
    $arguments = @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $workerScript,
        '-PiCommand', $piCommand,
        '-RepositoryRoot', $repositoryRoot,
        '-TaskFile', $worker.prompt_file,
        '-OutputFile', $worker.output_file,
        '-ErrorFile', $worker.error_file,
        '-ExitFile', $worker.exit_file,
        '-SessionDirectory', $priorSessionRoot,
        '-SessionId', $worker.session_id,
        '-WorkerName', "$RunId-$WorkerId-retry$attempt",
        '-ToolAllowlist', 'read,grep,find,ls,write,edit,powershell'
    )
    $process = Start-Process -FilePath $pwshCommand -ArgumentList $arguments `
        -WorkingDirectory $repositoryRoot -WindowStyle Hidden -PassThru
    $worker.pid = $process.Id
    Write-Utf8NoBom $statePath (($workers | ConvertTo-Json -Depth 5) + "`n")
    Write-Output "retried=$WorkerId attempt=$attempt pid=$($process.Id) session=$($worker.session_id)"
    exit 0
}

if ($Action -eq 'Status') {
    $rows = foreach ($worker in $workers) {
        [pscustomobject]@{
            id = $worker.id
            pid = $worker.pid
            status = Get-WorkerState $worker
            files = @(Get-ChildItem -LiteralPath $worker.candidate_dir -File -ErrorAction SilentlyContinue).Count
            candidate_bytes = @(
                Get-ChildItem -LiteralPath $worker.candidate_dir -File -ErrorAction SilentlyContinue |
                    Measure-Object -Property Length -Sum
            )[0].Sum
            report_bytes = if (Test-Path -LiteralPath $worker.output_file) {
                (Get-Item -LiteralPath $worker.output_file).Length
            } else { 0 }
            error_bytes = if (Test-Path -LiteralPath $worker.error_file) {
                (Get-Item -LiteralPath $worker.error_file).Length
            } else { 0 }
        }
    }
    $rows | Format-Table -AutoSize
    $rows | Group-Object status | Sort-Object Name | Select-Object Name, Count | Format-Table -AutoSize
    exit $(if (@($rows | Where-Object status -in @('failed', 'lost')).Count) { 1 } else { 0 })
}

if ($Action -eq 'Collect') {
    $incomplete = @($workers | Where-Object { (Get-WorkerState $_) -ne 'completed' })
    if ($incomplete.Count) {
        throw "Cannot collect: $($incomplete.Count) workers are not completed"
    }
    $collectedPath = Join-Path $runRoot 'collected_reports.md'
    $parts = @("# Pi startup code bake-off: $RunId", '')
    foreach ($worker in $workers) {
        $parts += "## $($worker.id)"
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
