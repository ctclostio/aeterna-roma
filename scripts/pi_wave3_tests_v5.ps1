#requires -Version 7.4

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$modulePath = Join-Path $PSScriptRoot 'pi_wave3_common_v2.psm1'
$schemaPath = Join-Path $PSScriptRoot 'pi_wave3_config_v3.schema.json'
$supervisorPath = Join-Path $PSScriptRoot 'pi_wave3_supervisor_v5.ps1'
$workerScriptPath = Join-Path $PSScriptRoot 'pi_swarm_worker_v5.ps1'
Import-Module -Name $modulePath -Force

$script:Passed = 0
$script:Failed = 0

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Invoke-Test([string]$Name, [scriptblock]$Body) {
    try {
        & $Body
        $script:Passed++
        Write-Output "PASS $Name"
    }
    catch {
        $script:Failed++
        Write-Output "FAIL $Name`: $($_.Exception.Message)"
    }
}

function New-Worker(
    [string]$Id,
    [string]$Stage,
    [int]$Tokens,
    [int]$Seconds,
    [int]$Tools,
    [string[]]$ReviewTargets
) {
    $sourceReadOnly = $Stage -in @('E', 'O', 'R')
    $schema = switch ($Stage) {
        'E' { 'scripts/pi_wave3_evidence.schema.json' }
        'O' { 'scripts/pi_wave3_oracle.schema.json' }
        'R' { 'scripts/pi_wave3_findings.schema.json' }
        'I' { 'scripts/pi_wave3_submission.schema.json' }
        'G' { 'scripts/pi_wave3_integration.schema.json' }
    }
    $outputName = switch ($Stage) {
        'E' { 'evidence' }
        'O' { 'oracle' }
        'R' { 'findings' }
        'I' { 'submission' }
        'G' { 'integration' }
    }
    $toolsList = if ($Stage -in @('E', 'O')) {
        @('read', 'grep', 'find', 'ls', 'write')
    }
    elseif ($Stage -eq 'R') {
        @('read', 'grep', 'find', 'ls', 'write', 'powershell')
    }
    else {
        @('read', 'grep', 'find', 'ls', 'write', 'edit', 'powershell')
    }
    $requiredOutput = [ordered]@{
        name = $outputName
        source = 'workspace'
        path = $outputName + '.json'
        format = 'json'
        schema = $schema
        max_bytes = 262144
    }
    return [ordered]@{
        id = $Id
        stage = $Stage
        role = ('role_' + $Id.ToLowerInvariant())
        task = "Bounded task for $Id"
        tools = $toolsList
        thinking = if ($Stage -in @('I', 'R')) { 'medium' } else { 'high' }
        budget = [ordered]@{
            max_tokens = $Tokens
            timeout_seconds = $Seconds
            max_tool_calls = $Tools
            max_output_bytes = 262144
        }
        writable_dir = "$Stage/$Id"
        context_files = @()
        review_targets = @($ReviewTargets)
        required_outputs = @($requiredOutput)
    }
}

function New-ValidConfig {
    $workers = @()
    foreach ($index in 1..4) { $workers += New-Worker ('E{0:d2}' -f $index) E 150000 480 30 @() }
    foreach ($index in 1..4) { $workers += New-Worker ('O{0:d2}' -f $index) O 225000 600 35 @() }
    foreach ($index in 1..6) { $workers += New-Worker ('I{0:d2}' -f $index) I 650000 1200 45 @() }
    $reviewMap = @(
        @('I01', 'I02', 'I03'),
        @('I03', 'I04', 'I05'),
        @('I05', 'I06', 'I01'),
        @('I02', 'I04', 'I06')
    )
    foreach ($index in 1..4) {
        $workers += New-Worker ('R{0:d2}' -f $index) R 225000 600 35 $reviewMap[$index - 1]
    }
    foreach ($index in 1..2) { $workers += New-Worker ('G{0:d2}' -f $index) G 600000 1500 50 @() }
    return [ordered]@{
        '$schema' = 'scripts/pi_wave3_config_v3.schema.json'
        schema_version = 1
        model = 'opencode-go/deepseek-v4-flash'
        prompt_preamble = 'Wave-3 test preamble.'
        stage_order = @('E', 'O', 'I', 'R', 'G')
        stages = @(
            [ordered]@{ id = 'E'; depends_on = @(); worker_count = 4 },
            [ordered]@{ id = 'O'; depends_on = @(); worker_count = 4 },
            [ordered]@{ id = 'I'; depends_on = @('E', 'O'); worker_count = 6 },
            [ordered]@{ id = 'R'; depends_on = @('I'); worker_count = 4 },
            [ordered]@{ id = 'G'; depends_on = @('E', 'O', 'I', 'R'); worker_count = 2 }
        )
        workers = @($workers)
    }
}

function Copy-JsonObject($Value) {
    return ($Value | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100)
}

function New-FrozenStateFixture($Validation, [string]$FixtureRunId, [string]$FixtureRunRoot) {
    return [ordered]@{
        state_version = 3
        run_id = $FixtureRunId
        repository_root = $repositoryRoot
        run_root = $FixtureRunRoot
        model = [string]$Validation.config.model
        config_path = [string]$Validation.config_path
        config_sha256 = [string]$Validation.config_sha256
        config_schema_sha256 = Get-Wave3Sha256 -LiteralPath $schemaPath
        total_token_budget = [int64]$Validation.total_token_budget
        actual_token_ceiling = [int64]$Validation.total_token_budget
        stages = @($Validation.config.stages | ForEach-Object {
            [ordered]@{ id = [string]$_.id; depends_on = @($_.depends_on); status = 'pending' }
        })
        workers = @($Validation.config.workers | ForEach-Object {
            [ordered]@{
                id = [string]$_.id
                stage = [string]$_.stage
                role = [string]$_.role
                budget = $_.budget
            }
        })
    }
}

function Write-JsonFile([string]$Path, $Value) {
    [System.IO.File]::WriteAllText(
        $Path,
        (($Value | ConvertTo-Json -Depth 100) + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
}

function Assert-ConfigRejected($Config, [string]$Needle, [string]$Path) {
    Write-JsonFile $Path $Config
    $caught = $null
    try {
        Read-Wave3Config -ConfigPath $Path -SchemaPath $schemaPath `
            -RepositoryRoot $repositoryRoot | Out-Null
    }
    catch { $caught = $_ }
    Assert-True ($null -ne $caught) 'Expected configuration rejection'
    Assert-True ($caught.Exception.Message -like "*$Needle*") `
        "Expected rejection containing '$Needle'; got '$($caught.Exception.Message)'"
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('pi-wave3-tests-' + [guid]::NewGuid().ToString('N'))
[System.IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
try {
    $validPath = Join-Path $temporaryRoot 'valid.json'
    $validConfig = New-ValidConfig
    Write-JsonFile $validPath $validConfig

    Invoke-Test 'PowerShell files parse without AST errors' {
        foreach ($path in @($modulePath, $supervisorPath, $workerScriptPath)) {
            $tokens = $null
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile(
                $path, [ref]$tokens, [ref]$errors
            ) | Out-Null
            Assert-True ($errors.Count -eq 0) "$path has parser errors"
        }
    }

    Invoke-Test 'v3 schema pins DeepSeek V4 Flash through OpenCode Go' {
        $result = Read-Wave3Config -ConfigPath $validPath -SchemaPath $schemaPath `
            -RepositoryRoot $repositoryRoot
        Assert-True ($result.config.model -eq 'opencode-go/deepseek-v4-flash') `
            'Expected the v3 schema to preserve the OpenCode Go DeepSeek model ID'

        foreach ($forbiddenModel in @(
            'openrouter/stealth/ox-alpha',
            'openrouter/z-ai/glm-5.3-flash',
            'openrouter/deepseek/deepseek-v4-flash'
        )) {
            $forbidden = Copy-JsonObject $validConfig
            $forbidden.model = $forbiddenModel
            $leaf = 'forbidden-model-' + ($forbiddenModel -replace '[^A-Za-z0-9]+', '-') + '.json'
            Assert-ConfigRejected $forbidden 'Expected' (Join-Path $temporaryRoot $leaf)
        }
    }

    Invoke-Test 'v5 production defaults to DeepSeek and withholds the E answer table' {
        $productionConfigPath = Join-Path $PSScriptRoot 'pi_wave3_startup_abi_v6.json'
        $production = Get-Content -LiteralPath $productionConfigPath -Raw |
            ConvertFrom-Json -Depth 100
        Assert-True ([string]$production.'$schema' -ceq `
            'scripts/pi_wave3_config_v3.schema.json') `
            'Production config does not select the v3 DeepSeek schema'
        Assert-True ([string]$production.model -ceq `
            'opencode-go/deepseek-v4-flash') `
            'Production config does not pin DeepSeek V4 Flash through OpenCode Go'

        $evidenceGate = 'scripts/pi_startup_abi_evidence_gate_v2.py'
        $publishedGate = @($production.semantic_gates | Where-Object stage -ceq 'E')
        Assert-True ($publishedGate.Count -eq 1 -and
            [string]$publishedGate[0].script -ceq $evidenceGate) `
            'Supervisor validation lost the authenticated E semantic gate'
        $eWorkers = @($production.workers | Where-Object stage -ceq 'E')
        Assert-True ($eWorkers.Count -eq 4) 'Production config must retain four E workers'
        foreach ($worker in $eWorkers) {
            Assert-True ($evidenceGate -notin @($worker.context_files)) `
                "Answer-bearing E gate leaked into worker context: $($worker.id)"
        }
        $e04 = @($eWorkers | Where-Object id -ceq 'E04')
        Assert-True ($e04.Count -eq 1 -and @($e04[0].context_files).Count -eq 8 -and
            [string]$e04[0].task -like '*Read all eight declared context files*') `
            'E04 context count and task instruction disagree after gate removal'

        $supervisorText = Get-Content -LiteralPath $supervisorPath -Raw
        Assert-True ($supervisorText.Contains(
            "Join-Path `$PSScriptRoot 'pi_wave3_startup_abi_v6.json'"
        )) 'v5 supervisor default config is not v6'
    }

    Invoke-Test 'v5 worker uses offline startup, records launch, and forwards the selected model' {
        $modelParameter = (Get-Command $workerScriptPath).Parameters['Model']
        Assert-True ($null -ne $modelParameter) 'Worker is missing its Model parameter'
        $mandatory = @($modelParameter.Attributes | Where-Object {
            $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory
        })
        Assert-True ($mandatory.Count -gt 0) 'Worker Model parameter must be mandatory'

        $fixtureRoot = Join-Path $temporaryRoot 'worker-model-forwarding'
        $sessionDirectory = Join-Path $fixtureRoot 'sessions'
        [System.IO.Directory]::CreateDirectory($sessionDirectory) | Out-Null
        $fakePi = Join-Path $fixtureRoot 'fake-pi.cmd'
        $taskFile = Join-Path $fixtureRoot 'task.md'
        $outputFile = Join-Path $fixtureRoot 'stdout.txt'
        $errorFile = Join-Path $fixtureRoot 'stderr.txt'
        $exitFile = Join-Path $fixtureRoot 'exit.txt'
        $launchReceiptFile = Join-Path $fixtureRoot 'launch.json'
        [System.IO.File]::WriteAllText(
            $fakePi,
            (@(
                '@echo off',
                "if not exist `"$launchReceiptFile`" exit /b 91",
                ':next',
                'if "%~1"=="" goto done',
                'echo %~1',
                'shift',
                'goto next',
                ':done',
                'exit /b 0'
            ) -join "`r`n") + "`r`n",
            [System.Text.UTF8Encoding]::new($false)
        )
        [System.IO.File]::WriteAllText(
            $taskFile,
            'fixture' + [Environment]::NewLine,
            [System.Text.UTF8Encoding]::new($false)
        )
        $pwsh = (Get-Command pwsh.exe -ErrorAction Stop).Source
        & $pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass `
            -File $workerScriptPath `
            -PiCommand $fakePi `
            -Model 'opencode-go/deepseek-v4-flash' `
            -RepositoryRoot $repositoryRoot `
            -TaskFile $taskFile `
            -OutputFile $outputFile `
            -ErrorFile $errorFile `
            -ExitFile $exitFile `
            -LaunchReceiptFile $launchReceiptFile `
            -SessionDirectory $sessionDirectory `
            -SessionId 'model-forwarding-fixture' `
            -WorkerName 'model-forwarding-fixture'
        Assert-True ($LASTEXITCODE -eq 0) 'Worker forwarding fixture failed'
        Assert-True ((Get-Content -LiteralPath $exitFile -Raw).Trim() -eq '0') `
            'Worker forwarding fixture did not record a zero exit code'
        $exitTemporaryFiles = @(Get-ChildItem -LiteralPath $fixtureRoot -Force | Where-Object {
            $_.Name -like '.exit.txt.tmp-*'
        })
        Assert-True ($exitTemporaryFiles.Count -eq 0) `
            'Worker left a temporary exit-publication file behind'
        $receiptTemporaryFiles = @(Get-ChildItem -LiteralPath $fixtureRoot -Force | Where-Object {
            $_.Name -like '.launch.json.tmp-*'
        })
        Assert-True ($receiptTemporaryFiles.Count -eq 0) `
            'Worker left a temporary launch-receipt file behind'
        $arguments = @(Get-Content -LiteralPath $outputFile)
        Assert-True (@($arguments | Where-Object { $_ -ceq '--offline' }).Count -eq 1) `
            'Worker did not forward exactly one --offline startup flag'
        $modelIndex = [array]::IndexOf($arguments, '--model')
        Assert-True ($modelIndex -ge 0) 'Worker did not forward --model'
        Assert-True ($arguments[$modelIndex + 1] -eq 'opencode-go/deepseek-v4-flash') `
            'Worker did not forward the exact config-selected model ID'
        $receipt = Get-Content -LiteralPath $launchReceiptFile -Raw |
            ConvertFrom-Json -Depth 20
        Assert-True ([int]$receipt.schema_version -eq 1 -and
            [string]$receipt.worker_name -ceq 'model-forwarding-fixture' -and
            [string]$receipt.model -ceq 'opencode-go/deepseek-v4-flash' -and
            [string]$receipt.session_id -ceq 'model-forwarding-fixture' -and
            [string]$receipt.task_file -ceq [System.IO.Path]::GetFullPath($taskFile) -and
            [string]$receipt.session_directory -ceq [System.IO.Path]::GetFullPath($sessionDirectory)) `
            'Worker launch receipt did not bind the exact invocation identity'
        Assert-True ([int]$receipt.pid -gt 0 -and
            -not [string]::IsNullOrWhiteSpace([string]$receipt.invoked_utc)) `
            'Worker launch receipt omitted its PID or timestamp'
    }

    Invoke-Test 'v5 assigns every Pi worker an isolated contained session directory' {
        & {
            param($SupervisorUnderTest, $SessionRoot)
            . $SupervisorUnderTest -Action Status -RunId 'unit-session-isolation-import'

            $paths = @(@('E01', 'E02', 'E03', 'E04') | ForEach-Object {
                Resolve-WorkerSessionDirectory -StageSessionRoot $SessionRoot `
                    -WorkerId $_
            })
            Assert-True (@($paths | Sort-Object -Unique).Count -eq 4) `
                'Workers did not receive unique session directories'
            foreach ($index in 0..3) {
                $expected = [System.IO.Path]::GetFullPath(
                    (Join-Path $SessionRoot ('E{0:d2}' -f ($index + 1)))
                )
                Assert-True ([string]$paths[$index] -ceq $expected) `
                    "Worker session directory escaped or changed: $($paths[$index])"
            }
            $caught = $null
            try {
                Resolve-WorkerSessionDirectory -StageSessionRoot $SessionRoot `
                    -WorkerId '../E01' | Out-Null
            }
            catch { $caught = $_ }
            Assert-True ($null -ne $caught) `
                'Worker session directory accepted a traversal identity'

            $source = Get-Content -LiteralPath $SupervisorUnderTest -Raw
            Assert-True ($source.Contains(
                '$workerState.session_directory = Resolve-WorkerSessionDirectory'
            )) 'StartStage does not use the isolated-session resolver'
        } $supervisorPath (Join-Path $temporaryRoot 'isolated-sessions')
    }

    Invoke-Test 'launch failure marks the current prepared worker and stage terminal' {
        & {
            param($SupervisorUnderTest)
            . $SupervisorUnderTest -Action Status -RunId 'unit-launch-failure-import'

            $worker = [pscustomobject]@{
                id = 'E01'; status = 'launching'; stopped_utc = $null
                stop_reason = $null; budget_exceeded = [pscustomobject]@{ kind = 'old' }
            }
            Set-WorkerLaunchFailure -WorkerState $worker `
                -Reason 'pi_command_not_found' -FailedUtc '2026-01-01T00:00:00Z'
            Assert-True ([string]$worker.status -ceq 'launch_failed' -and
                [string]$worker.stopped_utc -ceq '2026-01-01T00:00:00Z' -and
                [string]$worker.stop_reason -ceq `
                    'worker_launch_failed:pi_command_not_found' -and
                $null -eq $worker.budget_exceeded) `
                'Prepared worker did not receive a complete launch-failure record'

            $source = Get-Content -LiteralPath $SupervisorUnderTest -Raw
            Assert-True ($source.Contains('$currentLaunchingWorker = $workerState') -and
                $source.Contains('$affectedWorkers += $currentLaunchingWorker') -and
                $source.Contains('Set-WorkerLaunchFailure -WorkerState $started')) `
                'StartStage does not route the current prepared worker through launch-failure recording'
        } $supervisorPath
    }

    Invoke-Test 'running workers remain telemetry-pending until real metrics arrive' {
        & {
            param($SupervisorUnderTest, $FixtureRoot)
            . $SupervisorUnderTest -Action Status -RunId 'unit-telemetry-pending-import'

            $script:TelemetryFixtureMode = 'missing'
            function Get-Wave3SessionMetrics {
                param(
                    [string]$SessionDirectory,
                    [string]$SessionId,
                    [switch]$AllowIncompleteTail
                )
                if ($script:TelemetryFixtureMode -eq 'missing') {
                    throw "Expected one session JSONL for $SessionId; found 0"
                }
                return [pscustomobject]@{
                    total_tokens = [int64]41
                    input_tokens = [int64]30
                    output_tokens = [int64]11
                    cache_read_tokens = [int64]0
                    assistant_turns = [int64]1
                    tool_calls = [int64]1
                    completed_tool_calls = [int64]1
                }
            }

            $start = [datetimeoffset]::Parse('2026-01-01T00:00:00Z')
            $worker = [pscustomobject]@{
                id = 'E01'
                status = 'running'
                session_directory = $FixtureRoot
                session_id = 'telemetry-pending-fixture'
                process_start_utc = $start.ToString('o')
                last_metrics = $null
                metrics_stale_since_utc = $null
                metrics_stale_error = $null
            }
            foreach ($age in @(61.0, 300.0, 599.999)) {
                $observation = Get-WatchdogMetrics $worker running $start.AddSeconds($age)
                Assert-True ($null -eq $observation.metrics -and
                    -not $observation.fresh -and
                    $null -eq $observation.terminal_failure_reason) `
                    "Missing live telemetry was not pending at age $age"
            }
            Assert-True ([string]$worker.metrics_stale_since_utc -ceq $start.ToString('o')) `
                'Telemetry-pending age was not anchored to process start'

            $script:TelemetryFixtureMode = 'valid'
            $late = Get-WatchdogMetrics $worker running $start.AddSeconds(400)
            Assert-True ($late.fresh -and $late.metrics.total_tokens -eq 41 -and
                $null -eq $worker.metrics_stale_since_utc -and
                $null -eq $worker.metrics_stale_error) `
                'Late valid telemetry did not recover to a fresh observation'

            $worker.last_metrics = $late.metrics
            $script:TelemetryFixtureMode = 'missing'
            $caught = $null
            try {
                Get-WatchdogMetrics $worker running $start.AddSeconds(401) | Out-Null
            }
            catch { $caught = $_ }
            Assert-True ($null -ne $caught -and $caught.Exception.Message -like `
                'Expected one session JSONL for *; found 0') `
                'Previously observed session telemetry was allowed to disappear'

            $source = Get-Content -LiteralPath $SupervisorUnderTest -Raw
            Assert-True (-not $source.Contains(
                'Session JSONL was not created within'
            )) 'The obsolete session-file startup fatal remains in v5'
        } $supervisorPath (Join-Path $temporaryRoot 'telemetry-pending')
    }

    Invoke-Test 'telemetry-pending workers still stop at the exact wall-budget boundary' {
        & {
            param($SupervisorUnderTest, $FixtureRoot)
            . $SupervisorUnderTest -Action Status -RunId 'unit-pending-wall-import'

            function Get-LiveWorkerStatus($WorkerState) {
                return [string]$WorkerState.status
            }
            function Get-Wave3SessionMetrics {
                param(
                    [string]$SessionDirectory,
                    [string]$SessionId,
                    [switch]$AllowIncompleteTail
                )
                throw "Expected one session JSONL for $SessionId; found 0"
            }
            function Get-WorkerProcessLifetime(
                $WorkerState,
                [string]$LiveStatus,
                [datetimeoffset]$NowUtc
            ) {
                $start = [datetimeoffset]::Parse([string]$WorkerState.process_start_utc)
                return [pscustomobject]@{
                    process_start_utc = $start.ToString('o')
                    process_end_utc = $start.AddSeconds(
                        $script:TelemetryFixtureElapsedSeconds
                    ).ToString('o')
                    elapsed_seconds = [double]$script:TelemetryFixtureElapsedSeconds
                }
            }
            function Stop-WatchdogWorker(
                $WorkerState,
                [string]$Reason,
                $BudgetExceeded,
                [string]$TerminalStatus = 'stopped'
            ) {
                $script:TelemetryFixtureStopCount++
                $WorkerState.stopped_utc = '2026-01-01T00:10:01Z'
                $WorkerState.stop_reason = $Reason
                $WorkerState.budget_exceeded = $BudgetExceeded
                $WorkerState.status = if ($null -ne $BudgetExceeded) {
                    'budget_exceeded'
                }
                else { $TerminalStatus }
            }

            $workerStates = @()
            $workerConfigs = @()
            foreach ($index in 1..4) {
                $id = 'E{0:d2}' -f $index
                $workerStates += [pscustomobject]@{
                    id = $id; stage = 'E'; status = 'running'; pid = 100 + $index
                    process_start_utc = '2026-01-01T00:00:00Z'; process_exit_utc = $null
                    session_directory = $FixtureRoot; session_id = "pending-$id"
                    workspace_dir = $FixtureRoot; last_metrics = $null
                    metrics_stale_since_utc = $null; metrics_stale_error = $null
                    watchdog_checked_utc = $null; artifact_checkpoint_satisfied = $null
                    artifact_checkpoint_failed = $null; stopped_utc = $null
                    stop_reason = $null; budget_exceeded = $null
                }
                $workerConfigs += [pscustomobject]@{
                    id = $id; stage = 'E'
                    budget = [pscustomobject]@{
                        max_tokens = [int64]1000
                        timeout_seconds = 600
                        max_tool_calls = [int64]10
                        max_output_bytes = [int64]1024
                        artifact_checkpoint_tool_calls = [int64]3
                    }
                    required_outputs = @([pscustomobject]@{
                        source = 'workspace'; path = 'evidence.json'
                    })
                }
            }
            $stageState = [pscustomobject]@{
                id = 'E'; status = 'running'; watchdog_stopped_utc = $null
                stopped_utc = $null; stop_reason = $null
            }
            $state = [pscustomobject]@{
                stages = @($stageState); workers = @($workerStates)
                actual_token_ceiling = [int64]10000
            }
            $validation = [pscustomobject]@{
                config = [pscustomobject]@{ workers = @($workerConfigs) }
            }

            $script:TelemetryFixtureStopCount = 0
            foreach ($elapsed in @(61.0, 300.0, 600.0)) {
                $script:TelemetryFixtureElapsedSeconds = $elapsed
                $keepWatching = Invoke-WatchdogPass $state $validation E
                Assert-True ($keepWatching -and
                    @($workerStates | Where-Object status -ne 'running').Count -eq 0 -and
                    $script:TelemetryFixtureStopCount -eq 0) `
                    "Telemetry-pending workers stopped at permitted wall age $elapsed"
                Assert-True (@($workerStates | Where-Object {
                    $null -ne $_.artifact_checkpoint_satisfied
                }).Count -eq 0) `
                    'Pending telemetry incorrectly granted checkpoint credit'
            }

            $script:TelemetryFixtureElapsedSeconds = 600.001
            $keepWatching = Invoke-WatchdogPass $state $validation E
            Assert-True ($keepWatching -and $script:TelemetryFixtureStopCount -eq 4 -and
                @($workerStates | Where-Object status -eq 'budget_exceeded').Count -eq 4) `
                'Wall-time excess did not isolate every over-budget worker'
            $keepWatching = Invoke-WatchdogPass $state $validation E
            Assert-True (-not $keepWatching -and
                [string]$stageState.status -ceq 'budget_exceeded') `
                'Stage did not terminate after all pending workers exceeded wall time'
        } $supervisorPath (Join-Path $temporaryRoot 'pending-wall')
    }

    Invoke-Test 'exit zero without session telemetry is an ordinary isolated failure' {
        & {
            param($SupervisorUnderTest, $FixtureRoot)
            . $SupervisorUnderTest -Action Status -RunId 'unit-missing-exit-telemetry-import'

            function Get-LiveWorkerStatus($WorkerState) {
                return [string]$WorkerState.status
            }
            function Get-Wave3SessionMetrics {
                param(
                    [string]$SessionDirectory,
                    [string]$SessionId,
                    [switch]$AllowIncompleteTail
                )
                throw "Expected one session JSONL for $SessionId; found 0"
            }
            function Get-WorkerProcessLifetime(
                $WorkerState,
                [string]$LiveStatus,
                [datetimeoffset]$NowUtc
            ) {
                return [pscustomobject]@{
                    process_start_utc = '2026-01-01T00:00:00Z'
                    process_end_utc = '2026-01-01T00:00:01Z'
                    elapsed_seconds = 1.0
                }
            }
            function New-MissingTelemetryState([string]$Id, [string]$Status) {
                return [pscustomobject]@{
                    id = $Id; stage = 'E'; status = $Status; pid = 100
                    process_start_utc = '2026-01-01T00:00:00Z'; process_exit_utc = $null
                    session_directory = $FixtureRoot; session_id = "missing-$Id"
                    workspace_dir = $FixtureRoot; last_metrics = $null
                    metrics_stale_since_utc = $null; metrics_stale_error = $null
                    watchdog_checked_utc = $null; artifact_checkpoint_satisfied = $null
                    artifact_checkpoint_failed = $null; stopped_utc = $null
                    stop_reason = $null; budget_exceeded = $null
                }
            }
            function New-MissingTelemetryConfig([string]$Id) {
                return [pscustomobject]@{
                    id = $Id; stage = 'E'
                    budget = [pscustomobject]@{
                        max_tokens = [int64]1000; timeout_seconds = 600
                        max_tool_calls = [int64]10; max_output_bytes = [int64]1024
                    }
                    required_outputs = @()
                }
            }

            $exited = New-MissingTelemetryState E01 completed
            $peer = New-MissingTelemetryState E02 running
            $stageState = [pscustomobject]@{
                id = 'E'; status = 'running'; watchdog_stopped_utc = $null
                stopped_utc = $null; stop_reason = $null
            }
            $state = [pscustomobject]@{
                stages = @($stageState); workers = @($exited, $peer)
                actual_token_ceiling = [int64]10000
            }
            $validation = [pscustomobject]@{
                config = [pscustomobject]@{
                    workers = @(
                        (New-MissingTelemetryConfig E01),
                        (New-MissingTelemetryConfig E02)
                    )
                }
            }
            $keepWatching = Invoke-WatchdogPass $state $validation E
            Assert-True ($keepWatching -and [string]$exited.status -ceq 'failed' -and
                [string]$exited.stop_reason -ceq 'telemetry_missing_after_exit' -and
                [string]$peer.status -ceq 'running' -and
                [string]$stageState.status -ceq 'running') `
                'Missing terminal telemetry did not fail only the exited worker'
        } $supervisorPath (Join-Path $temporaryRoot 'missing-exit-telemetry')
    }

    Invoke-Test 'authenticated watchdog fail-closes if its first heartbeat write fails' {
        $fixtureRoot = Join-Path $temporaryRoot 'watchdog-first-heartbeat-failure'
        [System.IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
        & {
            param($SupervisorUnderTest, $FixtureRoot)
            . $SupervisorUnderTest -Action Status -RunId 'unit-first-heartbeat-import' -Stage E

            $watchdogRoot = $FixtureRoot
            $fixtureStage = [pscustomobject]@{
                id = 'E'; status = 'running'; watchdog_pid = [int]$PID
                stopped_utc = $null; stop_reason = $null
                watchdog_stopped_utc = $null
            }
            $worker = [pscustomobject]@{ id = 'E01'; stage = 'E'; status = 'running' }
            $script:FirstHeartbeatState = [pscustomobject]@{
                stages = @($fixtureStage); workers = @($worker)
            }
            $script:FirstHeartbeatSidecarCalls = 0
            $script:FirstHeartbeatFailClosedCalls = 0
            $script:FirstHeartbeatStateWrites = 0

            function Get-ValidatedConfig {
                return [pscustomobject]@{ config_path = 'fixture.json' }
            }
            function Open-RunLock { return [System.IO.MemoryStream]::new() }
            function Read-State { return $script:FirstHeartbeatState }
            function Assert-StateMatchesConfig($State, $Validation) { }
            function Get-WatchdogProcessIdentity($StageState) {
                return [pscustomobject]@{ exists = $true; trusted = $true; reason = 'match' }
            }
            function Write-WatchdogSidecar([string]$Path, $Value) {
                $script:FirstHeartbeatSidecarCalls++
                if ($script:FirstHeartbeatSidecarCalls -eq 1) {
                    throw 'fixture_first_heartbeat_publication_failed'
                }
            }
            function Invoke-WatchdogFailClosedActions(
                $TrustedState,
                [string]$StageId,
                [string]$Reason
            ) {
                $script:FirstHeartbeatFailClosedCalls++
                return @()
            }
            function Write-State($State, $Validation) {
                $script:FirstHeartbeatStateWrites++
            }

            Watchdog-Action
            Assert-True ($script:FirstHeartbeatFailClosedCalls -eq 1 -and
                $script:FirstHeartbeatStateWrites -eq 1 -and
                [string]$fixtureStage.status -ceq 'watchdog_failed' -and
                [string]$worker.status -ceq 'running' -and
                $script:FirstHeartbeatSidecarCalls -eq 2) `
                'First authenticated heartbeat failure bypassed fail-closed handling'
        } $supervisorPath $fixtureRoot
    }

    Invoke-Test 'StartStage accepts only a PID-bound authenticated watchdog heartbeat' {
        $fixtureRoot = Join-Path $temporaryRoot 'watchdog-startup-receipt'
        [System.IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
        & {
            param($SupervisorUnderTest, $FixtureRoot)
            . $SupervisorUnderTest -Action Status -RunId 'unit-watchdog-receipt-import'

            $heartbeatPath = Join-Path $FixtureRoot 'heartbeat.json'
            $receiptStage = [pscustomobject]@{
                id = 'E'; watchdog_pid = [int]$PID
                watchdog_heartbeat_file = $heartbeatPath
            }
            Write-Wave3AtomicJson -LiteralPath $heartbeatPath -Value ([ordered]@{
                stage = 'E'; pid = [int]$PID; sequence = 1
                phase = 'waiting_for_lock'; updated_utc = [datetimeoffset]::UtcNow.ToString('o')
            })
            $current = [System.Diagnostics.Process]::GetCurrentProcess()
            $ready = Wait-WatchdogStartupReceipt -StageState $receiptStage `
                -WatchdogProcess $current -TimeoutSeconds 1
            Assert-True ($ready.ready -and
                [string]$ready.reason -ceq 'authenticated_heartbeat_observed') `
                'PID-bound authenticated heartbeat was not accepted'

            $script:StartupReceiptReadCalls = 0
            $script:StartupReceiptJson = Get-Content -LiteralPath $heartbeatPath -Raw
            function Get-Content {
                param([string]$LiteralPath, [switch]$Raw)
                $script:StartupReceiptReadCalls++
                if ($script:StartupReceiptReadCalls -eq 1) {
                    throw [System.IO.IOException]::new('fixture transient read collision')
                }
                return $script:StartupReceiptJson
            }
            $retried = Wait-WatchdogStartupReceipt -StageState $receiptStage `
                -WatchdogProcess $current -TimeoutSeconds 1
            Remove-Item -LiteralPath Function:\Get-Content
            Assert-True ($retried.ready -and $script:StartupReceiptReadCalls -eq 2) `
                'Startup handshake did not recover from one transient heartbeat read'

            $deadProcess = Start-Process -FilePath (Get-Command pwsh.exe).Source `
                -ArgumentList @(
                    '-NoProfile', '-NonInteractive', '-Command', 'exit 0'
                ) -WindowStyle Hidden -PassThru
            $deadProcess.WaitForExit()
            Write-Wave3AtomicJson -LiteralPath $heartbeatPath -Value ([ordered]@{
                stage = 'E'; pid = [int]$deadProcess.Id; sequence = 1
                phase = 'waiting_for_lock'; updated_utc = [datetimeoffset]::UtcNow.ToString('o')
            })
            $deadStage = [pscustomobject]@{
                id = 'E'; watchdog_pid = [int]$deadProcess.Id
                watchdog_heartbeat_file = $heartbeatPath
            }
            $deadReceipt = Wait-WatchdogStartupReceipt -StageState $deadStage `
                -WatchdogProcess $deadProcess -TimeoutSeconds 1
            Assert-True (-not $deadReceipt.ready -and [string]$deadReceipt.reason -like `
                'watchdog_exited_before_ready:*') `
                'Exited watchdog was admitted by its stale valid heartbeat'

            Write-Wave3AtomicJson -LiteralPath $heartbeatPath -Value ([ordered]@{
                stage = 'E'; pid = [int]$PID + 1; sequence = 1
                phase = 'waiting_for_lock'; updated_utc = [datetimeoffset]::UtcNow.ToString('o')
            })
            $rejected = Wait-WatchdogStartupReceipt -StageState $receiptStage `
                -WatchdogProcess $current -TimeoutSeconds 1
            Assert-True (-not $rejected.ready -and [string]$rejected.reason -ceq `
                'watchdog_startup_heartbeat_identity_mismatch') `
                'Foreign watchdog heartbeat was accepted as startup-ready'

            $source = Get-Content -LiteralPath $SupervisorUnderTest -Raw
            Assert-True ($source.Contains('$watchdogStartupHandshakeSeconds = 10') -and
                $source.Contains('$lastTrustedState = $ownerState')) `
                'Supervisor does not freeze startup handshake and authenticated owner state'
        } $supervisorPath $fixtureRoot
    }

    Invoke-Test 'unexpected startup-handshake exceptions still invoke fail-closed cleanup' {
        & {
            param($SupervisorUnderTest)
            . $SupervisorUnderTest -Action Status -RunId 'unit-handshake-exception-import'

            $script:HandshakeExceptionCleanupCalls = 0
            $script:HandshakeExceptionCleanupReason = $null
            function Wait-WatchdogStartupReceipt {
                throw [System.IO.IOException]::new('fixture unexpected handshake I/O')
            }
            function Invoke-StartStageWatchdogStartupFailure(
                $Validation,
                $TrustedState,
                $TrustedStageState,
                [System.Diagnostics.Process]$WatchdogProcess,
                [string]$Reason
            ) {
                $script:HandshakeExceptionCleanupCalls++
                $script:HandshakeExceptionCleanupReason = $Reason
            }

            $caught = $null
            try {
                Complete-WatchdogStartupHandshake `
                    -Validation ([pscustomobject]@{}) `
                    -TrustedState ([pscustomobject]@{}) `
                    -TrustedStageState ([pscustomobject]@{}) `
                    -WatchdogProcess ([System.Diagnostics.Process]::GetCurrentProcess()) `
                    -TimeoutSeconds 1 | Out-Null
            }
            catch { $caught = $_ }
            Assert-True ($null -ne $caught -and
                $script:HandshakeExceptionCleanupCalls -eq 1 -and
                [string]$script:HandshakeExceptionCleanupReason -ceq `
                    'watchdog_startup_handshake_error:fixture unexpected handshake I/O') `
                'Unexpected handshake exception bypassed fail-closed cleanup'
        } $supervisorPath
    }

    Invoke-Test 'real StartStage wires launch receipts and isolated sessions for every E worker' {
        $fixtureId = [guid]::NewGuid().ToString('N')
        $fixtureRunId = "unit-v5-start-$fixtureId"
        $fixtureRunRoot = Join-Path $repositoryRoot `
            (Join-Path 'out\pi-swarm' $fixtureRunId)
        $fakePiRoot = Join-Path $temporaryRoot "startstage-fake-pi-$fixtureId"
        [System.IO.Directory]::CreateDirectory($fakePiRoot) | Out-Null
        $fakePi = Join-Path $fakePiRoot 'fake-pi.cmd'
        [System.IO.File]::WriteAllText(
            $fakePi,
            (@(
                '@echo off',
                ':next',
                'if "%~1"=="" goto done',
                'echo %~1',
                'shift',
                'goto next',
                ':done',
                'exit /b 0'
            ) -join "`r`n") + "`r`n",
            [System.Text.UTF8Encoding]::new($false)
        )
        try {
            $pwsh = (Get-Command pwsh.exe -ErrorAction Stop).Source
            $startOutput = & $pwsh -NoProfile -NonInteractive `
                -ExecutionPolicy Bypass -File $supervisorPath `
                -Action StartStage -RunId $fixtureRunId -Stage E `
                -ConfigPath $validPath -PiCommand $fakePi 2>&1
            Assert-True ($LASTEXITCODE -eq 0) `
                "StartStage fixture failed: $($startOutput -join ' | ')"

            $statePathFixture = Join-Path $fixtureRunRoot 'state.json'
            $deadline = [datetimeoffset]::UtcNow.AddSeconds(10)
            do {
                $fixtureState = Get-Content -LiteralPath $statePathFixture -Raw |
                    ConvertFrom-Json -Depth 100
                $eWorkers = @($fixtureState.workers | Where-Object stage -ceq 'E')
                $allReceipts = $eWorkers.Count -eq 4 -and
                    @($eWorkers | Where-Object {
                        -not (Test-Path -LiteralPath $_.launch_receipt_file -PathType Leaf)
                    }).Count -eq 0
                if (-not $allReceipts) { Start-Sleep -Milliseconds 100 }
            } while (-not $allReceipts -and [datetimeoffset]::UtcNow -lt $deadline)
            Assert-True $allReceipts 'Not every launched E worker published a launch receipt'

            $sessionDirectories = @($eWorkers | ForEach-Object {
                [System.IO.Path]::GetFullPath([string]$_.session_directory)
            })
            Assert-True (@($sessionDirectories | Sort-Object -Unique).Count -eq 4) `
                'Real StartStage assigned a shared session directory'
            foreach ($worker in $eWorkers) {
                $expectedSessionDirectory = [System.IO.Path]::GetFullPath(
                    (Join-Path (Join-Path $fixtureRunRoot 'sessions\E') ([string]$worker.id))
                )
                Assert-True ([string]$worker.session_directory -ceq $expectedSessionDirectory -and
                    (Test-Path -LiteralPath $expectedSessionDirectory -PathType Container)) `
                    "Real StartStage did not isolate session directory for $($worker.id)"

                $receipt = Get-Content -LiteralPath $worker.launch_receipt_file -Raw |
                    ConvertFrom-Json -Depth 20
                Assert-True ([string]$receipt.model -ceq `
                    'opencode-go/deepseek-v4-flash' -and
                    [string]$receipt.session_id -ceq [string]$worker.session_id -and
                    [int]$receipt.pid -eq [int]$worker.pid -and
                    [string]$receipt.session_directory -ceq $expectedSessionDirectory) `
                    "Launch receipt did not bind real StartStage worker $($worker.id)"

                $argsDeadline = [datetimeoffset]::UtcNow.AddSeconds(5)
                while ((-not (Test-Path -LiteralPath $worker.output_file -PathType Leaf) -or
                    (Get-Item -LiteralPath $worker.output_file).Length -eq 0) -and
                    [datetimeoffset]::UtcNow -lt $argsDeadline) {
                    Start-Sleep -Milliseconds 100
                }
                $forwarded = @(Get-Content -LiteralPath $worker.output_file)
                Assert-True (@($forwarded | Where-Object { $_ -ceq '--offline' }).Count -eq 1 -and
                    [array]::IndexOf($forwarded, '--model') -ge 0 -and
                    'opencode-go/deepseek-v4-flash' -in $forwarded) `
                    "Real worker invocation lost offline/model routing for $($worker.id)"
            }
        }
        finally {
            if (Test-Path -LiteralPath (Join-Path $fixtureRunRoot 'state.json') -PathType Leaf) {
                & (Get-Command pwsh.exe).Source -NoProfile -NonInteractive `
                    -ExecutionPolicy Bypass -File $supervisorPath `
                    -Action Stop -RunId $fixtureRunId -Stage E `
                    -ConfigPath $validPath 2>$null | Out-Null
                $processDeadline = [datetimeoffset]::UtcNow.AddSeconds(5)
                do {
                    $fixtureProcesses = @(Get-CimInstance Win32_Process | Where-Object {
                        [string]$_.CommandLine -like "*$fixtureRunId*"
                    })
                    if ($fixtureProcesses.Count) { Start-Sleep -Milliseconds 100 }
                } while ($fixtureProcesses.Count -and
                    [datetimeoffset]::UtcNow -lt $processDeadline)
                Assert-True ($fixtureProcesses.Count -eq 0) `
                    'StartStage fixture left a process alive before cleanup'
            }
            if (Test-Path -LiteralPath $fixtureRunRoot) {
                $expectedParent = [System.IO.Path]::GetFullPath(
                    (Join-Path $repositoryRoot 'out\pi-swarm')
                ).TrimEnd('\')
                $resolvedFixture = [System.IO.Path]::GetFullPath(
                    $fixtureRunRoot
                ).TrimEnd('\')
                Assert-True ([System.IO.Path]::GetDirectoryName($resolvedFixture) -ceq
                    $expectedParent -and
                    [System.IO.Path]::GetFileName($resolvedFixture) -ceq $fixtureRunId) `
                    'Refusing to clean an unexpected StartStage fixture path'
                Remove-Item -LiteralPath $resolvedFixture -Recurse -Force
            }
        }
    }

    Invoke-Test 'real StartStage records the current worker when Pi resolution fails' {
        $fixtureId = [guid]::NewGuid().ToString('N')
        $fixtureRunId = "unit-v5-launchfail-$fixtureId"
        $fixtureRunRoot = Join-Path $repositoryRoot `
            (Join-Path 'out\pi-swarm' $fixtureRunId)
        $missingPi = Join-Path $temporaryRoot `
            "missing-pi-$fixtureId\pi-does-not-exist.cmd"
        try {
            $pwsh = (Get-Command pwsh.exe -ErrorAction Stop).Source
            $launchOutput = & $pwsh -NoProfile -NonInteractive `
                -ExecutionPolicy Bypass -File $supervisorPath `
                -Action StartStage -RunId $fixtureRunId -Stage E `
                -ConfigPath $validPath -PiCommand $missingPi 2>&1
            Assert-True ($LASTEXITCODE -ne 0) `
                'Missing Pi command unexpectedly launched a stage'

            $state = Get-Content -LiteralPath (Join-Path $fixtureRunRoot 'state.json') `
                -Raw | ConvertFrom-Json -Depth 100
            $stageState = @($state.stages | Where-Object id -ceq 'E')[0]
            $eWorkers = @($state.workers | Where-Object stage -ceq 'E' | Sort-Object id)
            Assert-True ([string]$stageState.status -ceq 'launch_failed' -and
                -not [string]::IsNullOrWhiteSpace([string]$stageState.stopped_utc) -and
                [string]$stageState.stop_reason -like 'worker_launch_failed:*') `
                "Stage did not retain terminal launch failure: $($launchOutput -join ' | ')"
            Assert-True ([string]$eWorkers[0].status -ceq 'launch_failed' -and
                $null -eq $eWorkers[0].pid -and
                -not [string]::IsNullOrWhiteSpace([string]$eWorkers[0].stopped_utc) -and
                [string]$eWorkers[0].stop_reason -like 'worker_launch_failed:*') `
                'Current prepared worker remained launching after Pi resolution failure'
            Assert-True (@($eWorkers | Select-Object -Skip 1 | Where-Object {
                [string]$_.status -cne 'pending'
            }).Count -eq 0) `
                'Unattempted peers changed state after first-worker launch failure'
        }
        finally {
            if (Test-Path -LiteralPath $fixtureRunRoot) {
                $expectedParent = [System.IO.Path]::GetFullPath(
                    (Join-Path $repositoryRoot 'out\pi-swarm')
                ).TrimEnd('\')
                $resolvedFixture = [System.IO.Path]::GetFullPath(
                    $fixtureRunRoot
                ).TrimEnd('\')
                Assert-True ([System.IO.Path]::GetDirectoryName($resolvedFixture) -ceq
                    $expectedParent -and
                    [System.IO.Path]::GetFileName($resolvedFixture) -ceq $fixtureRunId) `
                    'Refusing to clean an unexpected launch-failure fixture path'
                Remove-Item -LiteralPath $resolvedFixture -Recurse -Force
            }
        }
    }

    Invoke-Test 'valid 20-worker configuration passes schema and invariants' {
        $result = Read-Wave3Config -ConfigPath $validPath -SchemaPath $schemaPath `
            -RepositoryRoot $repositoryRoot
        Assert-True ($result.config.workers.Count -eq 20) 'Expected 20 workers'
        Assert-True ($result.total_token_budget -eq 7500000) 'Expected 7.5M token cap'
        Assert-True ($result.config_sha256.Length -eq 64) 'Expected SHA-256'
    }

    Invoke-Test 'artifact checkpoint configuration is optional bounded and inside max_tool_calls' {
        foreach ($checkpoint in @(1, 30)) {
            $config = Copy-JsonObject $validConfig
            $budget = ($config.workers | Where-Object id -eq E01).budget
            $budget | Add-Member -NotePropertyName artifact_checkpoint_tool_calls `
                -NotePropertyValue $checkpoint
            $path = Join-Path $temporaryRoot "checkpoint-valid-$checkpoint.json"
            Write-JsonFile $path $config
            $validation = Read-Wave3Config -ConfigPath $path -SchemaPath $schemaPath `
                -RepositoryRoot $repositoryRoot
            $actual = ($validation.config.workers | Where-Object id -eq E01).budget
            Assert-True ($actual.artifact_checkpoint_tool_calls -eq $checkpoint) `
                "Checkpoint $checkpoint was not preserved"
        }

        foreach ($case in @(
            [pscustomobject]@{ value = 0; needle = 'at least 1'; name = 'zero' },
            [pscustomobject]@{ value = 501; needle = 'at most 500'; name = 'schema-max' },
            [pscustomobject]@{ value = 31; needle = 'cannot exceed max_tool_calls'; name = 'worker-max' },
            [pscustomobject]@{ value = 1.5; needle = 'integer'; name = 'fraction' }
        )) {
            $config = Copy-JsonObject $validConfig
            $budget = ($config.workers | Where-Object id -eq E01).budget
            $budget | Add-Member -NotePropertyName artifact_checkpoint_tool_calls `
                -NotePropertyValue $case.value
            Assert-ConfigRejected $config $case.needle `
                (Join-Path $temporaryRoot "checkpoint-invalid-$($case.name).json")
        }
    }

    Invoke-Test 'optional semantic gate passes and rejects failure mutation and traversal' {
        $fixtureId = [guid]::NewGuid().ToString('N')
        $passScript = Join-Path $PSScriptRoot "pi_wave3_semantic_gate_pass_$fixtureId.py"
        $failScript = Join-Path $PSScriptRoot "pi_wave3_semantic_gate_fail_$fixtureId.py"
        $mutatingScript = Join-Path $PSScriptRoot "pi_wave3_semantic_gate_mutate_$fixtureId.py"
        $fixtureScripts = @($passScript, $failScript, $mutatingScript)
        $passSource = @'
from pathlib import Path
import sys
root = Path(sys.argv[1])
if (root / "sentinel.txt").read_text(encoding="utf-8") != "unchanged":
    print("semantic fixture rejected")
    raise SystemExit(5)
print("semantic fixture passed")
'@
        $failSource = @'
print("semantic fixture failed")
raise SystemExit(7)
'@
        $mutatingSource = @'
from pathlib import Path
import sys
(Path(sys.argv[1]) / "sentinel.txt").write_text("changed", encoding="utf-8")
print("semantic fixture mutated input")
'@
        try {
            [System.IO.File]::WriteAllText(
                $passScript, $passSource, [System.Text.UTF8Encoding]::new($false)
            )
            [System.IO.File]::WriteAllText(
                $failScript, $failSource, [System.Text.UTF8Encoding]::new($false)
            )
            [System.IO.File]::WriteAllText(
                $mutatingScript, $mutatingSource, [System.Text.UTF8Encoding]::new($false)
            )
            $passRelative = [System.IO.Path]::GetRelativePath(
                $repositoryRoot, $passScript
            ).Replace('\', '/')
            $failRelative = [System.IO.Path]::GetRelativePath(
                $repositoryRoot, $failScript
            ).Replace('\', '/')
            $mutatingRelative = [System.IO.Path]::GetRelativePath(
                $repositoryRoot, $mutatingScript
            ).Replace('\', '/')
            $passGate = [ordered]@{
                stage = 'E'
                script = $passRelative
                script_sha256 = Get-Wave3Sha256 -LiteralPath $passScript
                workspace_root = 'E'
            }

            $config = Copy-JsonObject $validConfig
            $config | Add-Member -NotePropertyName semantic_gates `
                -NotePropertyValue @([pscustomobject]$passGate)
            $configPath = Join-Path $temporaryRoot 'semantic-gate-valid.json'
            Write-JsonFile $configPath $config
            $validation = Read-Wave3Config -ConfigPath $configPath `
                -SchemaPath $schemaPath -RepositoryRoot $repositoryRoot
            Assert-True ($validation.config.semantic_gates.Count -eq 1) `
                'Valid semantic gate was not preserved'

            $wrongHash = Copy-JsonObject $config
            $wrongHash.semantic_gates[0].script_sha256 = ('f' * 64)
            Assert-ConfigRejected $wrongHash 'SHA-256' `
                (Join-Path $temporaryRoot 'semantic-gate-wrong-hash.json')

            $duplicate = Copy-JsonObject $config
            $duplicate.semantic_gates = @(
                $duplicate.semantic_gates[0],
                [pscustomobject]@{
                    stage = 'E'
                    script = $failRelative
                    script_sha256 = Get-Wave3Sha256 -LiteralPath $failScript
                    workspace_root = 'E'
                }
            )
            Assert-ConfigRejected $duplicate 'more than one semantic gate' `
                (Join-Path $temporaryRoot 'semantic-gate-duplicate.json')

            $foreignWorkspace = Copy-JsonObject $config
            ($foreignWorkspace.workers | Where-Object id -eq O01).writable_dir = 'e/O01'
            Assert-ConfigRejected $foreignWorkspace "another stage's worker workspace" `
                (Join-Path $temporaryRoot 'semantic-gate-foreign-workspace.json')

            $traversalConfig = Copy-JsonObject $config
            $traversalConfig.semantic_gates[0].workspace_root = '../E'
            $caught = $null
            try {
                $traversalPath = Join-Path $temporaryRoot 'semantic-gate-traversal.json'
                Write-JsonFile $traversalPath $traversalConfig
                Read-Wave3Config -ConfigPath $traversalPath -SchemaPath $schemaPath `
                    -RepositoryRoot $repositoryRoot | Out-Null
            }
            catch { $caught = $_ }
            Assert-True ($null -ne $caught) `
                'Semantic gate traversal passed frozen configuration validation'

            $semanticWorkspace = Join-Path $temporaryRoot 'semantic-workspaces'
            $semanticArgument = Join-Path $semanticWorkspace 'E'
            [System.IO.Directory]::CreateDirectory($semanticArgument) | Out-Null
            [System.IO.File]::WriteAllText(
                (Join-Path $semanticArgument 'sentinel.txt'), 'unchanged',
                [System.Text.UTF8Encoding]::new($false)
            )
            $receipt = Invoke-Wave3SemanticGate -GateConfig ([pscustomobject]$passGate) `
                -RepositoryRoot $repositoryRoot -WorkspaceRoot $semanticWorkspace
            Assert-True ($receipt.exit_code -eq 0 -and
                $receipt.stdout -ceq 'semantic fixture passed' -and
                $receipt.stderr -ceq '') 'Passing semantic gate receipt was not deterministic'
            $fixtureBytecode = @(Get-ChildItem -LiteralPath (
                Join-Path $PSScriptRoot '__pycache__'
            ) -Filter "pi_wave3_semantic_gate_*_$fixtureId*.pyc" `
                -ErrorAction SilentlyContinue)
            Assert-True ($fixtureBytecode.Count -eq 0) `
                'Semantic gate invocation wrote Python bytecode'

            $failingGate = [pscustomobject]@{
                stage = 'E'
                script = $failRelative
                script_sha256 = Get-Wave3Sha256 -LiteralPath $failScript
                workspace_root = 'E'
            }
            $caught = $null
            try {
                Invoke-Wave3SemanticGate -GateConfig $failingGate `
                    -RepositoryRoot $repositoryRoot -WorkspaceRoot $semanticWorkspace | Out-Null
            }
            catch { $caught = $_ }
            Assert-True ($null -ne $caught -and
                $caught.Exception.Message -like '*exit code 7*semantic fixture failed*') `
                'Nonzero semantic gate did not fail closed with captured output'

            $mutatingGate = [pscustomobject]@{
                stage = 'E'
                script = $mutatingRelative
                script_sha256 = Get-Wave3Sha256 -LiteralPath $mutatingScript
                workspace_root = 'E'
            }
            $caught = $null
            try {
                Invoke-Wave3SemanticGate -GateConfig $mutatingGate `
                    -RepositoryRoot $repositoryRoot -WorkspaceRoot $semanticWorkspace | Out-Null
            }
            catch { $caught = $_ }
            Assert-True ($null -ne $caught -and
                $caught.Exception.Message -like '*mutated its read-only workspace argument*') `
                'Workspace-mutating semantic gate was accepted'
            [System.IO.File]::WriteAllText(
                (Join-Path $semanticArgument 'sentinel.txt'), 'unchanged',
                [System.Text.UTF8Encoding]::new($false)
            )

            [System.IO.File]::AppendAllText($passScript, "`n# mutation")
            $caught = $null
            try {
                Invoke-Wave3SemanticGate -GateConfig ([pscustomobject]$passGate) `
                    -RepositoryRoot $repositoryRoot -WorkspaceRoot $semanticWorkspace | Out-Null
            }
            catch { $caught = $_ }
            Assert-True ($null -ne $caught -and
                $caught.Exception.Message -like '*script changed after configuration freeze*') `
                'Post-freeze semantic gate script mutation was accepted'

            foreach ($field in @('script', 'workspace_root')) {
                $traversalGate = Copy-JsonObject $failingGate
                if ($field -eq 'script') { $traversalGate.script = '../outside.py' }
                else { $traversalGate.workspace_root = '../outside' }
                $caught = $null
                try {
                    Invoke-Wave3SemanticGate -GateConfig $traversalGate `
                        -RepositoryRoot $repositoryRoot -WorkspaceRoot $semanticWorkspace | Out-Null
                }
                catch { $caught = $_ }
                Assert-True ($null -ne $caught -and
                    $caught.Exception.Message -like '*escapes its allowed root*') `
                    "Semantic gate $field traversal was accepted"
            }
        }
        finally {
            foreach ($fixtureScript in $fixtureScripts) {
                if ([System.IO.File]::Exists($fixtureScript)) {
                    [System.IO.File]::Delete($fixtureScript)
                }
            }
        }
    }

    Invoke-Test '7.5M frozen state round-trip rejects ceiling and worker-budget mutation' {
        $validation = Read-Wave3Config -ConfigPath $validPath -SchemaPath $schemaPath `
            -RepositoryRoot $repositoryRoot
        $fixtureRunId = 'state-roundtrip'
        $fixtureRunRoot = Join-Path $temporaryRoot $fixtureRunId
        $fixture = New-FrozenStateFixture $validation $fixtureRunId $fixtureRunRoot
        $statePathFixture = Join-Path $temporaryRoot 'state-roundtrip.json'
        Write-JsonFile $statePathFixture $fixture
        $roundTrip = Get-Content -LiteralPath $statePathFixture -Raw | ConvertFrom-Json -Depth 100
        Assert-Wave3FrozenState -State $roundTrip -Validation $validation `
            -ExpectedRunId $fixtureRunId -ExpectedRunRoot $fixtureRunRoot `
            -ExpectedRepositoryRoot $repositoryRoot -ConfigSchemaPath $schemaPath | Out-Null

        foreach ($mutation in @('ceiling', 'budget')) {
            $changed = Copy-JsonObject $roundTrip
            if ($mutation -eq 'ceiling') { $changed.actual_token_ceiling++ }
            else { $changed.workers[0].budget.max_tokens++ }
            $caught = $false
            try {
                Assert-Wave3FrozenState -State $changed -Validation $validation `
                    -ExpectedRunId $fixtureRunId -ExpectedRunRoot $fixtureRunRoot `
                    -ExpectedRepositoryRoot $repositoryRoot -ConfigSchemaPath $schemaPath | Out-Null
            }
            catch { $caught = $true }
            Assert-True $caught "Frozen-state $mutation mutation was accepted"
        }
    }

    Invoke-Test 'frozen state preserves artifact checkpoint presence and exact value' {
        $config = Copy-JsonObject $validConfig
        $budget = ($config.workers | Where-Object id -eq E01).budget
        $budget | Add-Member -NotePropertyName artifact_checkpoint_tool_calls `
            -NotePropertyValue 12
        $configPath = Join-Path $temporaryRoot 'checkpoint-frozen-config.json'
        Write-JsonFile $configPath $config
        $validation = Read-Wave3Config -ConfigPath $configPath -SchemaPath $schemaPath `
            -RepositoryRoot $repositoryRoot
        $fixtureRunId = 'checkpoint-frozen-state'
        $fixtureRunRoot = Join-Path $temporaryRoot $fixtureRunId
        $fixture = New-FrozenStateFixture $validation $fixtureRunId $fixtureRunRoot
        $roundTripPath = Join-Path $temporaryRoot 'checkpoint-frozen-state.json'
        Write-JsonFile $roundTripPath $fixture
        $roundTrip = Get-Content -LiteralPath $roundTripPath -Raw | ConvertFrom-Json -Depth 100
        Assert-Wave3FrozenState -State $roundTrip -Validation $validation `
            -ExpectedRunId $fixtureRunId -ExpectedRunRoot $fixtureRunRoot `
            -ExpectedRepositoryRoot $repositoryRoot -ConfigSchemaPath $schemaPath | Out-Null

        foreach ($mutation in @('value', 'missing')) {
            $changed = Copy-JsonObject $roundTrip
            $changedBudget = ($changed.workers | Where-Object id -eq E01).budget
            if ($mutation -eq 'value') { $changedBudget.artifact_checkpoint_tool_calls++ }
            else { $changedBudget.PSObject.Properties.Remove('artifact_checkpoint_tool_calls') }
            $caught = $false
            try {
                Assert-Wave3FrozenState -State $changed -Validation $validation `
                    -ExpectedRunId $fixtureRunId -ExpectedRunRoot $fixtureRunRoot `
                    -ExpectedRepositoryRoot $repositoryRoot -ConfigSchemaPath $schemaPath | Out-Null
            }
            catch { $caught = $true }
            Assert-True $caught "Frozen checkpoint $mutation mutation was accepted"
        }

        $plainValidation = Read-Wave3Config -ConfigPath $validPath -SchemaPath $schemaPath `
            -RepositoryRoot $repositoryRoot
        $plainState = Copy-JsonObject (New-FrozenStateFixture $plainValidation `
            'checkpoint-absent' (Join-Path $temporaryRoot 'checkpoint-absent'))
        ($plainState.workers | Where-Object id -eq E01).budget |
            Add-Member -NotePropertyName artifact_checkpoint_tool_calls -NotePropertyValue 12
        $caught = $false
        try {
            Assert-Wave3FrozenState -State $plainState -Validation $plainValidation `
                -ExpectedRunId 'checkpoint-absent' `
                -ExpectedRunRoot (Join-Path $temporaryRoot 'checkpoint-absent') `
                -ExpectedRepositoryRoot $repositoryRoot -ConfigSchemaPath $schemaPath | Out-Null
        }
        catch { $caught = $true }
        Assert-True $caught 'State-added checkpoint was accepted when frozen config omitted it'
    }

    Invoke-Test 'supervisor Validate performs config-only validation without launching' {
        $runId = 'unit-' + [guid]::NewGuid().ToString('N')
        $output = & (Get-Command pwsh.exe).Source -NoProfile -NonInteractive `
            -File $supervisorPath -Action Validate -RunId $runId -ConfigPath $validPath 2>&1
        Assert-True ($LASTEXITCODE -eq 0) "Validate exited $LASTEXITCODE`: $output"
        Assert-True (($output -join "`n") -like '*config_valid=*') 'Missing config_valid output'
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $repositoryRoot "out/pi-swarm/$runId"))) `
            'Config-only validation created a run directory'
    }

    Invoke-Test 'supervisor publishes no validated state or manifest before semantic gate success' {
        $semanticPublicationRoot = Join-Path $temporaryRoot 'semantic-publication'
        [System.IO.Directory]::CreateDirectory($semanticPublicationRoot) | Out-Null
        & {
            param($SupervisorUnderTest, $PublicationRoot)
            . $SupervisorUnderTest -Action Status -RunId 'unit-semantic-publication' -Stage E

            $exitPath = Join-Path $PublicationRoot 'worker.exit.txt'
            [System.IO.File]::WriteAllText($exitPath, "0`n")
            $workspacePath = Join-Path $PublicationRoot 'workspaces/E/E01'
            [System.IO.Directory]::CreateDirectory($workspacePath) | Out-Null
            $contextPath = Join-Path $PublicationRoot 'context.json'
            [System.IO.File]::WriteAllText($contextPath, '{}')

            $workerConfig = [pscustomobject]@{
                id = 'E01'
                stage = 'E'
                role = 'semantic_fixture'
                budget = [pscustomobject]@{
                    max_tokens = 100
                    timeout_seconds = 30
                    max_tool_calls = 3
                    max_output_bytes = 1024
                }
                required_outputs = @()
            }
            $gateConfig = [pscustomobject]@{
                stage = 'E'
                script = 'scripts/fixture.py'
                script_sha256 = ('a' * 64)
                workspace_root = 'E'
            }
            $validation = [pscustomobject]@{
                config_sha256 = ('b' * 64)
                config = [pscustomobject]@{
                    model = 'opencode-go/deepseek-v4-flash'
                    stages = @([pscustomobject]@{
                        id = 'E'; depends_on = @(); worker_count = 1
                    })
                    workers = @($workerConfig)
                    semantic_gates = @($gateConfig)
                }
            }
            $stageState = [pscustomobject]@{
                id = 'E'
                status = 'running'
                stage_config_sha256 = ('c' * 64)
                validated_utc = $null
                manifest_file = $null
                manifest_sha256 = $null
            }
            $workerState = [pscustomobject]@{
                id = 'E01'
                stage = 'E'
                role = 'semantic_fixture'
                status = 'completed'
                exit_file = $exitPath
                session_directory = $PublicationRoot
                session_id = 'fixture-session'
                context_manifest = $contextPath
                context_manifest_sha256 = ('d' * 64)
                workspace_dir = $workspacePath
            }
            $state = [pscustomobject]@{
                stages = @($stageState)
                workers = @($workerState)
            }
            $manifestRoot = $PublicationRoot
            $workspaceRoot = Join-Path $PublicationRoot 'workspaces'
            $runRoot = $PublicationRoot
            $script:SemanticPublicationReject = $true
            $script:SemanticPublicationManifestWrites = 0
            $script:SemanticPublicationStateWrites = 0

            function Assert-DependencyManifests($State, $StageConfig) { return @{} }
            function Get-LiveWorkerStatus($WorkerState) { return 'completed' }
            function Assert-ContextManifestCurrent($WorkerState) {
                return [pscustomobject]@{ declared_inputs = @() }
            }
            function Get-Wave3SessionMetrics {
                param([string]$SessionDirectory, [string]$SessionId)
                return [pscustomobject]@{
                    total_tokens = 1; input_tokens = 1; output_tokens = 0
                    cache_read_tokens = 0; assistant_turns = 1
                    tool_calls = 1; completed_tool_calls = 1
                }
            }
            function Get-WorkerProcessLifetime($WorkerState, $LiveStatus, $NowUtc) {
                return [pscustomobject]@{ elapsed_seconds = 1.0 }
            }
            function Resolve-WorkerOutputs($WorkerConfig, $WorkerState) {
                return [pscustomobject]@{ artifacts = @(); documents = @() }
            }
            function Get-WorkspaceInventory([string]$WorkspacePath) { return @() }
            function Assert-StageDocuments {
                param(
                    $StageId, $WorkerConfigs, $ResolvedOutputs,
                    $DependencyArtifactIndex, $AllowedRequirementIds,
                    $ExpectedMilestone
                )
            }
            function Get-RunRelativePath([string]$Path) { return $Path }
            function Invoke-Wave3SemanticGate {
                param($GateConfig, $RepositoryRoot, $WorkspaceRoot)
                if ($script:SemanticPublicationReject) {
                    throw 'semantic fixture rejection'
                }
                return [pscustomobject][ordered]@{
                    stage = 'E'; script = 'scripts/fixture.py'
                    script_sha256 = ('a' * 64); workspace_root = 'E'
                    exit_code = 0; stdout = 'fixture passed'; stderr = ''
                }
            }
            function Write-Wave3AtomicJson {
                param([string]$LiteralPath, $Value)
                $script:SemanticPublicationManifestWrites++
            }
            function Get-Wave3Sha256 { param([string]$LiteralPath); return ('e' * 64) }
            function Write-State($State, $Validation) {
                $script:SemanticPublicationStateWrites++
            }

            $caught = $null
            try { Validate-Stage $state $validation E | Out-Null }
            catch { $caught = $_ }
            Assert-True ($null -ne $caught -and
                $caught.Exception.Message -ceq 'semantic fixture rejection') `
                'Failing semantic gate was not propagated'
            Assert-True ($stageState.status -ceq 'running' -and
                $workerState.status -ceq 'completed' -and
                $script:SemanticPublicationManifestWrites -eq 0 -and
                $script:SemanticPublicationStateWrites -eq 0) `
                'Failing semantic gate published validated state or a manifest'

            $script:SemanticPublicationReject = $false
            $result = Validate-Stage $state $validation E
            Assert-True ($result.status -ceq 'validated' -and
                $workerState.status -ceq 'validated' -and
                $script:SemanticPublicationManifestWrites -eq 1 -and
                $script:SemanticPublicationStateWrites -eq 1) `
                'Passing semantic gate did not publish exactly one validated transition'
        } $supervisorPath $semanticPublicationRoot
    }

    Invoke-Test 'supervisor publishes no G validation before reviewer consensus success' {
        $consensusPublicationRoot = Join-Path $temporaryRoot 'consensus-publication'
        [System.IO.Directory]::CreateDirectory($consensusPublicationRoot) | Out-Null
        & {
            param($SupervisorUnderTest, $PublicationRoot)
            . $SupervisorUnderTest -Action Status -RunId 'unit-consensus-publication' -Stage G

            $exitPath = Join-Path $PublicationRoot 'worker.exit.txt'
            [System.IO.File]::WriteAllText($exitPath, "0`n")
            $workspacePath = Join-Path $PublicationRoot 'workspaces/G/G01'
            [System.IO.Directory]::CreateDirectory($workspacePath) | Out-Null
            $contextPath = Join-Path $PublicationRoot 'context.json'
            [System.IO.File]::WriteAllText($contextPath, '{}')

            $workerConfig = [pscustomobject]@{
                id = 'G01'
                stage = 'G'
                role = 'consensus_fixture'
                budget = [pscustomobject]@{
                    max_tokens = 100
                    timeout_seconds = 30
                    max_tool_calls = 3
                    max_output_bytes = 1024
                }
                required_outputs = @()
            }
            $reviewerConfigs = @(
                [pscustomobject]@{ id = 'R01'; stage = 'R'; review_targets = @('I01') },
                [pscustomobject]@{ id = 'R02'; stage = 'R'; review_targets = @('I01') }
            )
            $validation = [pscustomobject]@{
                config_sha256 = ('b' * 64)
                config = [pscustomobject]@{
                    model = 'opencode-go/deepseek-v4-flash'
                    stages = @([pscustomobject]@{
                        id = 'G'; depends_on = @(); worker_count = 1
                    })
                    workers = @($workerConfig) + @($reviewerConfigs)
                    semantic_gates = @([pscustomobject]@{
                        stage = 'E'
                        script = 'scripts/unrelated_fixture.py'
                        script_sha256 = ('a' * 64)
                        workspace_root = 'E'
                    })
                }
            }
            $stageState = [pscustomobject]@{
                id = 'G'
                status = 'running'
                stage_config_sha256 = ('c' * 64)
                validated_utc = $null
                manifest_file = $null
                manifest_sha256 = $null
            }
            $workerState = [pscustomobject]@{
                id = 'G01'
                stage = 'G'
                role = 'consensus_fixture'
                status = 'completed'
                exit_file = $exitPath
                session_directory = $PublicationRoot
                session_id = 'fixture-session'
                context_manifest = $contextPath
                context_manifest_sha256 = ('d' * 64)
                workspace_dir = $workspacePath
            }
            $state = [pscustomobject]@{
                stages = @($stageState)
                workers = @($workerState)
            }
            $manifestRoot = $PublicationRoot
            $workspaceRoot = Join-Path $PublicationRoot 'workspaces'
            $runRoot = $PublicationRoot
            $script:ConsensusPublicationReject = $true
            $script:ConsensusPublicationCalls = 0
            $script:ConsensusPublicationManifestWrites = 0
            $script:ConsensusPublicationStateWrites = 0
            $script:ConsensusPublishedManifest = $null

            function Assert-DependencyManifests($State, $StageConfig) { return @{} }
            function Get-LiveWorkerStatus($WorkerState) { return 'completed' }
            function Assert-ContextManifestCurrent($WorkerState) {
                return [pscustomobject]@{ declared_inputs = @() }
            }
            function Get-Wave3SessionMetrics {
                param([string]$SessionDirectory, [string]$SessionId)
                return [pscustomobject]@{
                    total_tokens = 1; input_tokens = 1; output_tokens = 0
                    cache_read_tokens = 0; assistant_turns = 1
                    tool_calls = 1; completed_tool_calls = 1
                }
            }
            function Get-WorkerProcessLifetime($WorkerState, $LiveStatus, $NowUtc) {
                return [pscustomobject]@{ elapsed_seconds = 1.0 }
            }
            function Resolve-WorkerOutputs($WorkerConfig, $WorkerState) {
                return [pscustomobject]@{
                    artifacts = @()
                    documents = @([pscustomobject]@{
                        name = 'integration'
                        value = [pscustomobject]@{ worker_id = 'G01' }
                    })
                }
            }
            function Get-WorkspaceInventory([string]$WorkspacePath) { return @() }
            function Assert-StageDocuments {
                param(
                    $StageId, $WorkerConfigs, $ResolvedOutputs,
                    $DependencyArtifactIndex, $AllowedRequirementIds,
                    $ExpectedMilestone
                )
            }
            function Assert-Wave3SelectedCandidateReviewConsensus {
                param($Documents, $ReviewerConfigs, $ArtifactIndex)
                $script:ConsensusPublicationCalls++
                if ($script:ConsensusPublicationReject) {
                    throw 'consensus fixture rejection'
                }
                return [pscustomobject][ordered]@{
                    policy = 'two_configured_reviewers_must_pass'
                    candidate_count = 1
                    candidates = @()
                }
            }
            function Get-RunRelativePath([string]$Path) { return $Path }
            function Write-Wave3AtomicJson {
                param([string]$LiteralPath, $Value)
                $script:ConsensusPublicationManifestWrites++
                $script:ConsensusPublishedManifest = $Value
            }
            function Get-Wave3Sha256 { param([string]$LiteralPath); return ('e' * 64) }
            function Write-State($State, $Validation) {
                $script:ConsensusPublicationStateWrites++
            }

            $caught = $null
            try { Validate-Stage $state $validation G | Out-Null }
            catch { $caught = $_ }
            Assert-True ($null -ne $caught -and
                $caught.Exception.Message -ceq 'consensus fixture rejection') `
                "Failing reviewer consensus was not propagated: $($caught.Exception.Message) [$($caught.ScriptStackTrace)]"
            Assert-True ($stageState.status -ceq 'running' -and
                $workerState.status -ceq 'completed' -and
                $script:ConsensusPublicationCalls -eq 1 -and
                $script:ConsensusPublicationManifestWrites -eq 0 -and
                $script:ConsensusPublicationStateWrites -eq 0) `
                'Failing reviewer consensus published validated state or a manifest'

            $script:ConsensusPublicationReject = $false
            $result = Validate-Stage $state $validation G
            Assert-True ($result.status -ceq 'validated' -and
                $workerState.status -ceq 'validated' -and
                $script:ConsensusPublicationCalls -eq 2 -and
                $script:ConsensusPublicationManifestWrites -eq 1 -and
                $script:ConsensusPublicationStateWrites -eq 1) `
                'Passing reviewer consensus did not publish exactly one validated transition'
            Assert-True ($null -ne $script:ConsensusPublishedManifest.reviewer_consensus -and
                $script:ConsensusPublishedManifest.reviewer_consensus.policy -ceq
                    'two_configured_reviewers_must_pass') `
                'Published G manifest omitted the reviewer-consensus receipt'
        } $supervisorPath $consensusPublicationRoot
    }

    Invoke-Test 'duplicate worker ID is rejected' {
        $config = Copy-JsonObject $validConfig
        $config.workers[1].id = $config.workers[0].id
        Assert-ConfigRejected $config 'Worker IDs must be unique' (Join-Path $temporaryRoot 'duplicate.json')
    }

    Invoke-Test 'correlated reviewer coverage is rejected' {
        $config = Copy-JsonObject $validConfig
        ($config.workers | Where-Object id -eq R04).review_targets = @('I01', 'I02', 'I03')
        Assert-ConfigRejected $config 'exactly two reviewers' (Join-Path $temporaryRoot 'reviews.json')
    }

    Invoke-Test 'E O and R require one isolated workspace JSON and no edit tool' {
        $missingWorkspace = Copy-JsonObject $validConfig
        ($missingWorkspace.workers | Where-Object id -eq E01).writable_dir = $null
        Assert-ConfigRejected $missingWorkspace 'must declare writable_dir' `
            (Join-Path $temporaryRoot 'artifact-no-workspace.json')

        $reportTransport = Copy-JsonObject $validConfig
        $output = ($reportTransport.workers | Where-Object id -eq O01).required_outputs[0]
        $output.source = 'report'
        $output.PSObject.Properties.Remove('path')
        Assert-ConfigRejected $reportTransport 'schema-validated workspace JSON' `
            (Join-Path $temporaryRoot 'artifact-report.json')

        $missingWrite = Copy-JsonObject $validConfig
        $worker = $missingWrite.workers | Where-Object id -eq R01
        $worker.tools = @($worker.tools | Where-Object { $_ -ne 'write' })
        Assert-ConfigRejected $missingWrite 'must have the write tool' `
            (Join-Path $temporaryRoot 'artifact-no-write.json')

        $editSource = Copy-JsonObject $validConfig
        ($editSource.workers | Where-Object id -eq E02).tools += 'edit'
        Assert-ConfigRejected $editSource 'forbidden tools' `
            (Join-Path $temporaryRoot 'artifact-edit.json')

        $powershellEvidence = Copy-JsonObject $validConfig
        ($powershellEvidence.workers | Where-Object id -eq E03).tools += 'powershell'
        Assert-ConfigRejected $powershellEvidence 'forbidden tools' `
            (Join-Path $temporaryRoot 'artifact-powershell.json')
    }

    Invoke-Test 'one ordered workspace inventory record is exactly one file' {
        $record = [ordered]@{
            path = 'evidence.json'
            sha256 = ('0' * 64)
            byte_count = 2
        }
        Assert-Wave3ExactWorkspaceInventory -Inventory $record `
            -ExpectedPath 'evidence.json' -WorkerId E01 | Out-Null

        foreach ($invalid in @(
            @(),
            @($record, [ordered]@{ path = 'extra.txt'; sha256 = ('1' * 64); byte_count = 1 }),
            [ordered]@{ path = 'wrong.json'; sha256 = ('2' * 64); byte_count = 2 }
        )) {
            $caught = $false
            try {
                Assert-Wave3ExactWorkspaceInventory -Inventory $invalid `
                    -ExpectedPath 'evidence.json' -WorkerId E01 | Out-Null
            }
            catch { $caught = $true }
            Assert-True $caught 'Invalid source-read-only inventory was accepted'
        }
    }

    Invoke-Test 'declared candidate inventory must be duplicate-free and exact' {
        $inventory = @(
            [ordered]@{ path = 'submission.json'; sha256 = ('0' * 64); byte_count = 2 },
            [ordered]@{ path = 'guest32.c'; sha256 = ('1' * 64); byte_count = 10 }
        )
        Assert-Wave3ExactWorkspacePathSet -Inventory $inventory `
            -ExpectedPaths @('submission.json', 'guest32.c') -WorkerId I01 | Out-Null
        foreach ($expected in @(
            @('submission.json'),
            @('submission.json', 'guest32.c', 'extra.c'),
            @('submission.json', 'guest32.c', 'guest32.c')
        )) {
            $caught = $false
            try {
                Assert-Wave3ExactWorkspacePathSet -Inventory $inventory `
                    -ExpectedPaths $expected -WorkerId I01 | Out-Null
            }
            catch { $caught = $true }
            Assert-True $caught 'Non-exact declared workspace inventory was accepted'
        }
    }

    Invoke-Test 'configured writable package filenames are frozen and include the manifest' {
        $accepted = Copy-JsonObject $validConfig
        ($accepted.workers | Where-Object id -eq I01) |
            Add-Member -NotePropertyName expected_workspace_files `
                -NotePropertyValue @('submission.json', 'guest32.c')
        $acceptedPath = Join-Path $temporaryRoot 'expected-files-ok.json'
        Write-JsonFile $acceptedPath $accepted
        Read-Wave3Config -ConfigPath $acceptedPath -SchemaPath $schemaPath `
            -RepositoryRoot $repositoryRoot | Out-Null

        $missingManifest = Copy-JsonObject $accepted
        ($missingManifest.workers | Where-Object id -eq I01).expected_workspace_files = @('guest32.c')
        Assert-ConfigRejected $missingManifest 'omits required output submission.json' `
            (Join-Path $temporaryRoot 'expected-files-missing-manifest.json')

        $readOnly = Copy-JsonObject $validConfig
        ($readOnly.workers | Where-Object id -eq E01) |
            Add-Member -NotePropertyName expected_workspace_files `
                -NotePropertyValue @('evidence.json')
        Assert-ConfigRejected $readOnly 'Only writable I/G worker' `
            (Join-Path $temporaryRoot 'expected-files-read-only.json')
    }

    Invoke-Test 'dependency artifacts and full workspaces are hash authenticated' {
        $artifactRunRoot = Join-Path $temporaryRoot 'dependency-artifacts'
        [System.IO.Directory]::CreateDirectory($artifactRunRoot) | Out-Null
        $newDependencyWorker = {
            param([string]$StageId, [string]$WorkerId, [string]$ArtifactName, [string]$ArtifactFile)
            $workspaceRelative = "workspaces/$StageId/$WorkerId"
            $workspaceAbsolute = Join-Path $artifactRunRoot $workspaceRelative
            [System.IO.Directory]::CreateDirectory($workspaceAbsolute) | Out-Null
            $artifactAbsolute = Join-Path $workspaceAbsolute $ArtifactFile
            [System.IO.File]::WriteAllText(
                $artifactAbsolute, "artifact-$WorkerId", [System.Text.UTF8Encoding]::new($false)
            )
            if ($StageId -eq 'I') {
                [System.IO.File]::WriteAllText(
                    (Join-Path $workspaceAbsolute 'probe.c'), 'source-v1',
                    [System.Text.UTF8Encoding]::new($false)
                )
            }
            $inventory = @(Get-ChildItem -LiteralPath $workspaceAbsolute -File | Sort-Object Name |
                ForEach-Object {
                    [pscustomobject]@{
                        path = $_.Name
                        sha256 = Get-Wave3Sha256 -LiteralPath $_.FullName
                        byte_count = [int64]$_.Length
                    }
                })
            $artifactRelative = "$workspaceRelative/$ArtifactFile"
            return [pscustomobject]@{
                id = $WorkerId
                workspace_path = $workspaceRelative
                workspace_inventory = $inventory
                artifacts = @([pscustomobject]@{
                    name = $ArtifactName
                    path = $artifactRelative
                    sha256 = Get-Wave3Sha256 -LiteralPath $artifactAbsolute
                    byte_count = [int64](Get-Item -LiteralPath $artifactAbsolute).Length
                })
            }
        }

        $iWorker = & $newDependencyWorker I I01 submission submission.json
        $eWorker = & $newDependencyWorker E E01 evidence evidence.json
        $oWorker = & $newDependencyWorker O O01 oracle oracle.json
        $rWorker = & $newDependencyWorker R R01 findings findings.json
        $manifests = @(
            [pscustomobject]@{ stage = 'E'; workers = @($eWorker) },
            [pscustomobject]@{ stage = 'O'; workers = @($oWorker) },
            [pscustomobject]@{ stage = 'I'; workers = @($iWorker) },
            [pscustomobject]@{ stage = 'R'; workers = @($rWorker) }
        )
        $index = Get-Wave3DependencyArtifactIndex -StageManifests $manifests `
            -RunRoot $artifactRunRoot
        Assert-True ($index.Count -eq 4) 'Expected four authenticated dependency workers'

        $review = [pscustomobject]@{
            worker_id = 'R02'
            reviews = @([pscustomobject]@{
                candidate_id = 'I01'
                candidate_sha256 = [string]$iWorker.artifacts[0].sha256
            })
        }
        Assert-Wave3DependencyArtifactReferences -StageId R -Documents @($review) `
            -ArtifactIndex $index | Out-Null
        $components = [pscustomobject]@{
            worker_id = 'G01'
            selected_components = @(@($eWorker, $oWorker, $iWorker, $rWorker) | ForEach-Object {
                [pscustomobject]@{
                    worker_id = [string]$_.id
                    artifact_sha256 = [string]$_.artifacts[0].sha256
                }
            })
        }
        Assert-Wave3DependencyArtifactReferences -StageId G -Documents @($components) `
            -ArtifactIndex $index | Out-Null
        $emptyIndex = Get-Wave3DependencyArtifactIndex -StageManifests @() `
            -RunRoot $artifactRunRoot
        Assert-True ($emptyIndex.Count -eq 0) 'Empty dependency set should yield an empty index'

        foreach ($mutation in @('wrong_hash', 'unknown', 'duplicate', 'missing_stage', 'wrong_stage')) {
            $changed = Copy-JsonObject $components
            switch ($mutation) {
                'wrong_hash' { $changed.selected_components[0].artifact_sha256 = ('f' * 64) }
                'unknown' { $changed.selected_components[0].worker_id = 'E99' }
                'duplicate' { $changed.selected_components += $changed.selected_components[0] }
                'missing_stage' {
                    $changed.selected_components = @($changed.selected_components | Where-Object worker_id -ne R01)
                }
                'wrong_stage' {
                    $changed = [pscustomobject]@{
                        worker_id = 'R02'
                        reviews = @([pscustomobject]@{
                            candidate_id = 'E01'
                            candidate_sha256 = [string]$eWorker.artifacts[0].sha256
                        })
                    }
                }
            }
            $caught = $false
            try {
                Assert-Wave3DependencyArtifactReferences `
                    -StageId $(if ($mutation -eq 'wrong_stage') { 'R' } else { 'G' }) `
                    -Documents @($changed) -ArtifactIndex $index | Out-Null
            }
            catch { $caught = $true }
            Assert-True $caught "Dependency reference mutation $mutation was accepted"
        }

        $wrongReviewHash = Copy-JsonObject $review
        $wrongReviewHash.reviews[0].candidate_sha256 = ('e' * 64)
        $caught = $false
        try {
            Assert-Wave3DependencyArtifactReferences -StageId R `
                -Documents @($wrongReviewHash) -ArtifactIndex $index | Out-Null
        }
        catch { $caught = $true }
        Assert-True $caught 'Wrong R candidate hash was accepted'

        $probePath = Join-Path $artifactRunRoot 'workspaces/I/I01/probe.c'
        [System.IO.File]::WriteAllText(
            $probePath, 'source-tampered', [System.Text.UTF8Encoding]::new($false)
        )
        $caught = $false
        try {
            Get-Wave3DependencyArtifactIndex -StageManifests $manifests `
                -RunRoot $artifactRunRoot | Out-Null
        }
        catch { $caught = $true }
        Assert-True $caught 'Tampered dependency workspace source was accepted'
        [System.IO.File]::WriteAllText(
            $probePath, 'source-v1', [System.Text.UTF8Encoding]::new($false)
        )

        $duplicateWorker = @($manifests)
        $duplicateWorker += [pscustomobject]@{
            stage = 'I'; workers = @($iWorker)
        }
        $caught = $false
        try {
            Get-Wave3DependencyArtifactIndex -StageManifests $duplicateWorker `
                -RunRoot $artifactRunRoot | Out-Null
        }
        catch { $caught = $true }
        Assert-True $caught 'Duplicate dependency worker identity was accepted'

        $duplicateArtifactManifests = Copy-JsonObject $manifests
        $duplicateArtifactManifests[2].workers[0].artifacts += `
            $duplicateArtifactManifests[2].workers[0].artifacts[0]
        $caught = $false
        try {
            Get-Wave3DependencyArtifactIndex -StageManifests $duplicateArtifactManifests `
                -RunRoot $artifactRunRoot | Out-Null
        }
        catch { $caught = $true }
        Assert-True $caught 'Duplicate dependency artifact name was accepted'
    }

    Invoke-Test 'G reviewer consensus admits two authenticated passes and rejects missing duplicate fail or mismatched reviews' {
        $consensusRoot = Join-Path $temporaryRoot 'review-consensus'
        [System.IO.Directory]::CreateDirectory($consensusRoot) | Out-Null
        $candidatePath = Join-Path $consensusRoot 'submission.json'
        Write-JsonFile $candidatePath ([ordered]@{ worker_id = 'I01'; stage = 'I' })
        $candidateHash = Get-Wave3Sha256 -LiteralPath $candidatePath
        $candidateEntry = [pscustomobject]@{
            stage = 'I'
            worker_id = 'I01'
            artifacts = @([pscustomobject]@{
                name = 'submission'
                path = 'workspaces/I/I01/submission.json'
                sha256 = $candidateHash
                byte_count = [int64](Get-Item -LiteralPath $candidatePath).Length
                absolute_path = $candidatePath
            })
        }
        $reviewerConfigs = @(
            [pscustomobject]@{ id = 'R01'; stage = 'R'; review_targets = @('I01') },
            [pscustomobject]@{ id = 'R02'; stage = 'R'; review_targets = @('I01') }
        )
        $integrationDocument = [pscustomobject]@{
            worker_id = 'G01'
            selected_components = @([pscustomobject]@{
                worker_id = 'I01'
                artifact_sha256 = $candidateHash
            })
        }
        $newReviewDocument = {
            param([string]$ReviewerId, [string]$Verdict, [string]$ReviewedHash)
            return [pscustomobject]@{
                worker_id = $ReviewerId
                stage = 'R'
                reviews = @([pscustomobject]@{
                    candidate_id = 'I01'
                    candidate_sha256 = $ReviewedHash
                    verdict = $Verdict
                    tests_run = @('fixture')
                    findings = @()
                })
            }
        }
        $newConsensusIndex = {
            param([object]$R01Document, [object]$R02Document)
            $index = [hashtable]::new([System.StringComparer]::Ordinal)
            $index['I01'] = $candidateEntry
            foreach ($pair in @(
                [pscustomobject]@{ id = 'R01'; document = $R01Document },
                [pscustomobject]@{ id = 'R02'; document = $R02Document }
            )) {
                $reviewPath = Join-Path $consensusRoot (
                    "$($pair.id)-$([guid]::NewGuid().ToString('N')).json"
                )
                Write-JsonFile $reviewPath $pair.document
                $index[[string]$pair.id] = [pscustomobject]@{
                    stage = 'R'
                    worker_id = [string]$pair.id
                    artifacts = @([pscustomobject]@{
                        name = 'findings'
                        path = "workspaces/R/$($pair.id)/findings.json"
                        sha256 = Get-Wave3Sha256 -LiteralPath $reviewPath
                        byte_count = [int64](Get-Item -LiteralPath $reviewPath).Length
                        absolute_path = $reviewPath
                    })
                }
            }
            return $index
        }

        $passingR01 = & $newReviewDocument R01 pass $candidateHash
        $passingR02 = & $newReviewDocument R02 pass $candidateHash
        $passingIndex = & $newConsensusIndex $passingR01 $passingR02
        $receipt = Assert-Wave3SelectedCandidateReviewConsensus `
            -Documents @($integrationDocument) -ReviewerConfigs $reviewerConfigs `
            -ArtifactIndex $passingIndex
        Assert-True ($receipt.policy -ceq 'two_configured_reviewers_must_pass' -and
            [int]$receipt.candidate_count -eq 1 -and
            @($receipt.candidates[0].reviews).Count -eq 2) `
            'Two authenticated pass verdicts did not produce a consensus receipt'
        Assert-True (((@($receipt.candidates[0].reviews | ForEach-Object reviewer_id) |
            Sort-Object) -join ',') -ceq 'R01,R02') `
            'Consensus receipt did not name both configured reviewers'

        foreach ($mutation in @(
            'missing', 'duplicate', 'fail', 'blocked', 'mismatched_hash', 'wrong_identity'
        )) {
            $r01 = Copy-JsonObject $passingR01
            $r02 = Copy-JsonObject $passingR02
            switch ($mutation) {
                'missing' { $r01.reviews = @() }
                'duplicate' { $r01.reviews += Copy-JsonObject $r01.reviews[0] }
                'fail' { $r01.reviews[0].verdict = 'fail' }
                'blocked' { $r01.reviews[0].verdict = 'blocked' }
                'mismatched_hash' { $r01.reviews[0].candidate_sha256 = ('f' * 64) }
                'wrong_identity' { $r01.worker_id = 'R02' }
            }
            $changedIndex = & $newConsensusIndex $r01 $r02
            $caught = $false
            try {
                Assert-Wave3SelectedCandidateReviewConsensus `
                    -Documents @($integrationDocument) -ReviewerConfigs $reviewerConfigs `
                    -ArtifactIndex $changedIndex | Out-Null
            }
            catch { $caught = $true }
            Assert-True $caught "Reviewer-consensus mutation $mutation was accepted"
        }

        $missingArtifactIndex = & $newConsensusIndex $passingR01 $passingR02
        $missingArtifactIndex.Remove('R02')
        $caught = $false
        try {
            Assert-Wave3SelectedCandidateReviewConsensus `
                -Documents @($integrationDocument) -ReviewerConfigs $reviewerConfigs `
                -ArtifactIndex $missingArtifactIndex | Out-Null
        }
        catch { $caught = $true }
        Assert-True $caught 'Missing assigned reviewer artifact was accepted'

        $tamperedIndex = & $newConsensusIndex $passingR01 $passingR02
        $tamperedPath = [string]$tamperedIndex['R01'].artifacts[0].absolute_path
        [System.IO.File]::AppendAllText(
            $tamperedPath, " `n", [System.Text.UTF8Encoding]::new($false)
        )
        $caught = $false
        try {
            Assert-Wave3SelectedCandidateReviewConsensus `
                -Documents @($integrationDocument) -ReviewerConfigs $reviewerConfigs `
                -ArtifactIndex $tamperedIndex | Out-Null
        }
        catch { $caught = $true }
        Assert-True $caught 'Post-index findings artifact tampering was accepted'
    }

    Invoke-Test 'configured canonical requirement IDs reject typos in O I R and G' {
        $allowed = @('DP-ABI-001', 'DP-MEM-001')
        $documents = @{
            O = [pscustomobject]@{
                worker_id = 'O01'
                tests = @([pscustomobject]@{
                    requirement_ids = @('DP-ABI-001', 'DP-MEM-001')
                })
            }
            I = [pscustomobject]@{
                worker_id = 'I01'
                requirement_ids = @('DP-ABI-001', 'DP-MEM-001')
            }
            R = [pscustomobject]@{
                worker_id = 'R01'
                reviews = @([pscustomobject]@{
                    findings = @([pscustomobject]@{ requirement_id = 'DP-ABI-001' })
                })
            }
            G = [pscustomobject]@{
                worker_id = 'G01'
                requirement_ids = @('DP-ABI-001', 'DP-MEM-001')
            }
        }
        foreach ($stageId in @('O', 'I', 'R', 'G')) {
            Assert-Wave3RequirementIds -StageId $stageId -Documents @($documents[$stageId]) `
                -AllowedRequirementIds $allowed | Out-Null
        }
        foreach ($stageId in @('O', 'I', 'R', 'G')) {
            $changed = Copy-JsonObject $documents[$stageId]
            switch ($stageId) {
                'O' { $changed.tests[0].requirement_ids[0] = 'DP-TYPO-999' }
                'I' { $changed.requirement_ids[0] = 'DP-TYPO-999' }
                'R' { $changed.reviews[0].findings[0].requirement_id = 'DP-TYPO-999' }
                'G' { $changed.requirement_ids[0] = 'DP-TYPO-999' }
            }
            $caught = $false
            try {
                Assert-Wave3RequirementIds -StageId $stageId -Documents @($changed) `
                    -AllowedRequirementIds $allowed | Out-Null
            }
            catch { $caught = $true }
            Assert-True $caught "Non-canonical $stageId requirement ID was accepted"
        }
        foreach ($stageId in @('O', 'I', 'G')) {
            $changed = Copy-JsonObject $documents[$stageId]
            if ($stageId -eq 'O') { $changed.tests[0].requirement_ids = @('DP-ABI-001') }
            else { $changed.requirement_ids = @('DP-ABI-001') }
            $caught = $false
            try {
                Assert-Wave3RequirementIds -StageId $stageId -Documents @($changed) `
                    -AllowedRequirementIds $allowed | Out-Null
            }
            catch { $caught = $true }
            Assert-True $caught "Incomplete $stageId requirement coverage was accepted"
        }
        $missingG = [pscustomobject]@{ worker_id = 'G01' }
        $caught = $false
        try {
            Assert-Wave3RequirementIds -StageId G -Documents @($missingG) `
                -AllowedRequirementIds $allowed | Out-Null
        }
        catch { $caught = $true }
        Assert-True $caught 'G integration without requirement_ids was accepted'
    }

    Invoke-Test 'I and G milestone values must match the frozen literal exactly' {
        $documents = @(
            [pscustomobject]@{ worker_id = 'I01'; milestone = 'entry-policy-dynamic-probe-v1' },
            [pscustomobject]@{ worker_id = 'G01'; milestone = 'entry-policy-dynamic-probe-v1' }
        )
        Assert-Wave3Milestone -Documents $documents `
            -ExpectedMilestone 'entry-policy-dynamic-probe-v1' | Out-Null
        $changed = Copy-JsonObject $documents
        $changed[1].milestone = 'dynamic-probe'
        $caught = $false
        try {
            Assert-Wave3Milestone -Documents $changed `
                -ExpectedMilestone 'entry-policy-dynamic-probe-v1' | Out-Null
        }
        catch { $caught = $true }
        Assert-True $caught 'Non-frozen milestone value was accepted'
    }

    Invoke-Test 'stage starts are serial across all active wave stages' {
        $stages = @(
            [pscustomobject]@{ id = 'E'; status = 'running' },
            [pscustomobject]@{ id = 'O'; status = 'pending' }
        )
        $caught = $false
        try { Assert-Wave3SerialStageStart -Stages $stages -RequestedStage O | Out-Null }
        catch { $caught = $true }
        Assert-True $caught 'Concurrent stage start was accepted'
        $stages[0].status = 'pending'
        $caught = $false
        try { Assert-Wave3SerialStageStart -Stages $stages -RequestedStage O | Out-Null }
        catch { $caught = $true }
        Assert-True $caught 'Out-of-order O start was accepted while E was pending'
        $stages[0].status = 'validated'
        Assert-Wave3SerialStageStart -Stages $stages -RequestedStage O | Out-Null
    }

    Invoke-Test 'oracle mutant mappings must exist and be exactly reciprocal' {
        $valid = [pscustomobject]@{
            worker_id = 'O01'
            tests = @(1..8 | ForEach-Object {
                [pscustomobject]@{ test_id = "O01.T$_"; mutant_ids = @("O01.M$_") }
            })
            mutants = @(1..8 | ForEach-Object {
                [pscustomobject]@{
                    mutant_id = "O01.M$_"; expected_killer_ids = @("O01.T$_")
                }
            })
        }
        Assert-Wave3OracleReciprocity -Documents @($valid) | Out-Null
        foreach ($mutation in @(
            'wrong_count', 'wrong_prefix', 'multiple_mutants', 'wrong_pair', 'cross_worker', 'unknown_mutant',
            'missing_reverse', 'unknown_test', 'missing_forward'
        )) {
            $changed = Copy-JsonObject $valid
            switch ($mutation) {
                'wrong_count' { $changed.tests = @($changed.tests | Select-Object -First 7) }
                'wrong_prefix' { $changed.tests[0].test_id = 'OTHER.T1' }
                'multiple_mutants' { $changed.tests[0].mutant_ids = @('O01.M1', 'O01.M2') }
                'wrong_pair' {
                    $changed.tests[0].mutant_ids = @('O01.M2')
                    $changed.tests[1].mutant_ids = @('O01.M1')
                    $changed.mutants[0].expected_killer_ids = @('O01.T2')
                    $changed.mutants[1].expected_killer_ids = @('O01.T1')
                }
                'cross_worker' {
                    $changed.tests[0].mutant_ids = @('O02.M1')
                    $changed.mutants[0].mutant_id = 'O02.M1'
                    $changed.mutants[0].expected_killer_ids = @('O01.T1')
                }
                'unknown_mutant' { $changed.tests[0].mutant_ids = @('O01.MISSING') }
                'missing_reverse' { $changed.mutants[0].expected_killer_ids = @() }
                'unknown_test' { $changed.mutants[0].expected_killer_ids = @('O01.MISSING') }
                'missing_forward' { $changed.tests[0].mutant_ids = @() }
            }
            $caught = $false
            try { Assert-Wave3OracleReciprocity -Documents @($changed) | Out-Null }
            catch { $caught = $true }
            Assert-True $caught "Oracle reciprocity mutation $mutation was accepted"
        }
        $descriptive = Copy-JsonObject $valid
        $descriptive.tests[0].test_id = 'O01.T1.descriptive-suffix'
        $descriptive.tests[0].mutant_ids = @('O01.M1.descriptive-suffix')
        $descriptive.mutants[0].mutant_id = 'O01.M1.descriptive-suffix'
        $descriptive.mutants[0].expected_killer_ids = @('O01.T1.descriptive-suffix')
        $caught = $false
        try { Assert-Wave3OracleReciprocity -Documents @($descriptive) | Out-Null }
        catch { $caught = $true }
        Assert-True $caught 'Descriptive oracle ID suffixes were accepted'
    }

    Invoke-Test 'R workers may use PowerShell and write artifacts but not edit sources' {
        $accepted = Copy-JsonObject $validConfig
        Write-JsonFile (Join-Path $temporaryRoot 'reviewer-ok.json') $accepted
        Read-Wave3Config -ConfigPath (Join-Path $temporaryRoot 'reviewer-ok.json') `
            -SchemaPath $schemaPath -RepositoryRoot $repositoryRoot | Out-Null
        $rejected = Copy-JsonObject $validConfig
        ($rejected.workers | Where-Object id -eq R01).tools += 'edit'
        Assert-ConfigRejected $rejected 'forbidden tools' (Join-Path $temporaryRoot 'reviewer-bad.json')
    }

    Invoke-Test 'path traversal is rejected before launch' {
        $config = Copy-JsonObject $validConfig
        ($config.workers | Where-Object id -eq I01).writable_dir = '../escape'
        Assert-ConfigRejected $config 'escapes its allowed root' (Join-Path $temporaryRoot 'escape.json')
    }

    Invoke-Test 'per-role budget cap is rejected' {
        $config = Copy-JsonObject $validConfig
        ($config.workers | Where-Object id -eq E01).budget.max_tokens = 250001
        Assert-ConfigRejected $config 'token cap' (Join-Path $temporaryRoot 'budget.json')
    }

    Invoke-Test 'atomic text replacement leaves exactly the destination' {
        $path = Join-Path $temporaryRoot 'atomic.json'
        Write-Wave3AtomicText -LiteralPath $path -Text 'first'
        Write-Wave3AtomicText -LiteralPath $path -Text 'second'
        Assert-True ((Get-Content -LiteralPath $path -Raw) -ceq 'second') 'Atomic replacement has wrong bytes'
        $siblings = @(Get-ChildItem -LiteralPath $temporaryRoot -Filter '.atomic.json.tmp.*')
        Assert-True ($siblings.Count -eq 0) 'Atomic replacement leaked temporary files'
    }

    Invoke-Test 'workspace roots reject reparse points and artifacts reject hardlinks when supported' {
        $linkRoot = Join-Path $temporaryRoot 'link-safety'
        $boundary = Join-Path $linkRoot 'boundary'
        $targetDirectory = Join-Path $linkRoot 'target-directory'
        [System.IO.Directory]::CreateDirectory($boundary) | Out-Null
        [System.IO.Directory]::CreateDirectory($targetDirectory) | Out-Null
        $junction = Join-Path $boundary 'junction'
        $junctionCreated = $false
        try {
            New-Item -ItemType Junction -Path $junction -Target $targetDirectory -ErrorAction Stop | Out-Null
            $junctionCreated = $true
        }
        catch { }
        if ($junctionCreated) {
            $caught = $false
            try { Assert-Wave3SafeDirectoryTree -LiteralPath $junction -BoundaryPath $boundary | Out-Null }
            catch { $caught = $true }
            Assert-True $caught 'Reparse workspace root was accepted'
        }

        $original = Join-Path $boundary 'original.json'
        $hardlink = Join-Path $boundary 'hardlink.json'
        [System.IO.File]::WriteAllText($original, '{}')
        $hardlinkCreated = $false
        try {
            New-Item -ItemType HardLink -Path $hardlink -Target $original -ErrorAction Stop | Out-Null
            $hardlinkCreated = $true
        }
        catch { }
        if ($hardlinkCreated) {
            $caught = $false
            try { Assert-Wave3ArtifactFile -LiteralPath $original | Out-Null }
            catch { $caught = $true }
            Assert-True $caught 'Hardlinked artifact was accepted'
        }
    }

    Invoke-Test 'frozen harness hashes accept exact files and reject any mutation' {
        $hashRoot = Join-Path $temporaryRoot 'hashes'
        [System.IO.Directory]::CreateDirectory($hashRoot) | Out-Null
        $supervisorFixture = Join-Path $hashRoot 'supervisor.ps1'
        $commonFixture = Join-Path $hashRoot 'common.psm1'
        $workerFixture = Join-Path $hashRoot 'worker.ps1'
        [System.IO.File]::WriteAllText($supervisorFixture, 'supervisor-v1')
        [System.IO.File]::WriteAllText($commonFixture, 'common-v1')
        [System.IO.File]::WriteAllText($workerFixture, 'worker-v1')
        $state = [ordered]@{
            supervisor_sha256 = Get-Wave3Sha256 -LiteralPath $supervisorFixture
            common_module_sha256 = Get-Wave3Sha256 -LiteralPath $commonFixture
            worker_script_sha256 = Get-Wave3Sha256 -LiteralPath $workerFixture
        }
        Assert-Wave3FrozenHarness -State $state -SupervisorPath $supervisorFixture `
            -CommonModulePath $commonFixture -WorkerScriptPath $workerFixture | Out-Null

        [System.IO.File]::WriteAllText($commonFixture, 'common-v2')
        $caught = $null
        try {
            Assert-Wave3FrozenHarness -State $state -SupervisorPath $supervisorFixture `
                -CommonModulePath $commonFixture -WorkerScriptPath $workerFixture | Out-Null
        }
        catch { $caught = $_ }
        Assert-True ($null -ne $caught) 'Mutated common module should be rejected'
        Assert-True ($caught.Exception.Message -like '*common module changed*') `
            "Unexpected frozen-hash rejection: $($caught.Exception.Message)"
    }

    Invoke-Test 'artifact checkpoint uses completed receipts and rejects late or in-flight cures' {
        $checkpointRoot = Join-Path $temporaryRoot 'artifact-checkpoint'
        [System.IO.Directory]::CreateDirectory($checkpointRoot) | Out-Null
        $worker = [pscustomobject]@{
            id = 'I01'
            budget = [pscustomobject]@{
                max_tool_calls = 10
                artifact_checkpoint_tool_calls = 3
            }
            required_outputs = @(
                [pscustomobject]@{ source = 'workspace'; path = 'submission.json' },
                [pscustomobject]@{ source = 'workspace'; path = 'ported.c' },
                [pscustomobject]@{ source = 'report' }
            )
        }

        $below = Get-Wave3ArtifactCheckpointDecision -WorkerConfig $worker `
            -WorkspacePath $checkpointRoot -DeclaredToolCalls 3 -CompletedToolCalls 2 `
            -TelemetryFresh $true -PreviouslySatisfied $false
        Assert-True ($null -eq $below) 'Checkpoint fired below its exact boundary'
        $stale = Get-Wave3ArtifactCheckpointDecision -WorkerConfig $worker `
            -WorkspacePath $checkpointRoot -DeclaredToolCalls 3 -CompletedToolCalls 3 `
            -TelemetryFresh $false -PreviouslySatisfied $false
        Assert-True ($null -eq $stale) 'Stale telemetry was treated as authoritative'

        $exact = Get-Wave3ArtifactCheckpointDecision -WorkerConfig $worker `
            -WorkspacePath $checkpointRoot -DeclaredToolCalls 3 -CompletedToolCalls 3 `
            -TelemetryFresh $true -PreviouslySatisfied $false
        Assert-True ($exact.kind -ceq 'artifact_checkpoint_not_satisfied_by_deadline') `
            'Missing exact-boundary checkpoint did not fail'
        Assert-True ($exact.observed_completed_tool_calls -eq 3 -and $exact.limit -eq 3) `
            'Checkpoint failure did not preserve exact observed and limit values'
        Assert-True ($exact.required_artifact_count -eq 2) `
            'Report transport was incorrectly counted as a workspace artifact'

        $emptyPath = Join-Path $checkpointRoot 'submission.json'
        [System.IO.File]::WriteAllText($emptyPath, '')
        $empty = Get-Wave3ArtifactCheckpointDecision -WorkerConfig $worker `
            -WorkspacePath $checkpointRoot -DeclaredToolCalls 4 -CompletedToolCalls 4 `
            -TelemetryFresh $true -PreviouslySatisfied $false
        Assert-True ($empty.kind -ceq 'artifact_checkpoint_not_satisfied_by_deadline') `
            'An empty artifact incorrectly satisfied the checkpoint'

        $nonemptyPath = Join-Path $checkpointRoot 'ported.c'
        [System.IO.File]::WriteAllText($nonemptyPath, '{')
        $late = Get-Wave3ArtifactCheckpointDecision -WorkerConfig $worker `
            -WorkspacePath $checkpointRoot -DeclaredToolCalls 4 -CompletedToolCalls 4 `
            -TelemetryFresh $true -PreviouslySatisfied $false
        Assert-True ($late.kind -ceq 'artifact_checkpoint_not_satisfied_by_deadline' -and
            $late.safe_artifact_present_now) `
            'A nonempty artifact first observed after the deadline cured the checkpoint'

        $inFlight = Get-Wave3ArtifactCheckpointDecision -WorkerConfig $worker `
            -WorkspacePath $checkpointRoot -DeclaredToolCalls 4 -CompletedToolCalls 3 `
            -TelemetryFresh $true -PreviouslySatisfied $false
        Assert-True ($inFlight.kind -ceq 'artifact_checkpoint_not_satisfied_by_deadline') `
            'An N+1 call in flight was allowed to provide a deadline artifact'

        $early = Get-Wave3ArtifactCheckpointDecision -WorkerConfig $worker `
            -WorkspacePath $checkpointRoot -DeclaredToolCalls 3 -CompletedToolCalls 2 `
            -TelemetryFresh $true -PreviouslySatisfied $false
        Assert-True ($early.kind -ceq 'artifact_checkpoint_satisfied' -and
            $early.artifact_path -ceq 'ported.c') `
            'A safe artifact observed before the completed-call deadline was not receipted'
        [System.IO.File]::Delete($nonemptyPath)
        $persisted = Get-Wave3ArtifactCheckpointDecision -WorkerConfig $worker `
            -WorkspacePath $checkpointRoot -DeclaredToolCalls 9 -CompletedToolCalls 9 `
            -TelemetryFresh $true -PreviouslySatisfied $true
        Assert-True ($null -eq $persisted) `
            'A persisted early checkpoint receipt was incorrectly revoked later'

        [System.IO.File]::WriteAllText($nonemptyPath, '{')
        $exactQuiescent = Get-Wave3ArtifactCheckpointDecision -WorkerConfig $worker `
            -WorkspacePath $checkpointRoot -DeclaredToolCalls 3 -CompletedToolCalls 3 `
            -TelemetryFresh $true -PreviouslySatisfied $false
        Assert-True ($exactQuiescent.kind -ceq 'artifact_checkpoint_satisfied') `
            'A safe artifact at an exact quiescent deadline was not accepted'
        $schemaCaught = $false
        try {
            Test-Wave3JsonDocument -DocumentPath $nonemptyPath `
                -SchemaPath (Join-Path $repositoryRoot 'scripts/pi_wave3_submission.schema.json') | Out-Null
        }
        catch { $schemaCaught = $true }
        Assert-True $schemaCaught `
            'Checkpoint presence accidentally replaced normal JSON schema validation'

        $optionalWorker = Copy-JsonObject $worker
        $optionalWorker.budget.PSObject.Properties.Remove('artifact_checkpoint_tool_calls')
        $disabled = Get-Wave3ArtifactCheckpointDecision -WorkerConfig $optionalWorker `
            -WorkspacePath $checkpointRoot -DeclaredToolCalls 999 -CompletedToolCalls 999 `
            -TelemetryFresh $true -PreviouslySatisfied $false
        Assert-True ($null -eq $disabled) 'Omitted optional checkpoint was enforced'

        $caught = $false
        try {
            Get-Wave3ArtifactCheckpointDecision -WorkerConfig $worker `
                -WorkspacePath $checkpointRoot -DeclaredToolCalls 2 -CompletedToolCalls 3 `
                -TelemetryFresh $true -PreviouslySatisfied $false | Out-Null
        }
        catch { $caught = $true }
        Assert-True $caught 'Completed calls exceeding declarations were accepted'
    }

    Invoke-Test 'artifact checkpoint rejects junction ancestry and hardlinked files' {
        $checkpointRoot = Join-Path $temporaryRoot 'artifact-checkpoint-links'
        $outsideRoot = Join-Path $temporaryRoot 'artifact-checkpoint-outside'
        [System.IO.Directory]::CreateDirectory($checkpointRoot) | Out-Null
        [System.IO.Directory]::CreateDirectory($outsideRoot) | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $outsideRoot 'checkpoint.json'), '{}')
        $worker = [pscustomobject]@{
            id = 'E01'
            budget = [pscustomobject]@{
                max_tool_calls = 10
                artifact_checkpoint_tool_calls = 3
            }
            required_outputs = @(
                [pscustomobject]@{ source = 'workspace'; path = 'linked/checkpoint.json' }
            )
        }

        $junction = Join-Path $checkpointRoot 'linked'
        $junctionCreated = $false
        try {
            New-Item -ItemType Junction -Path $junction -Target $outsideRoot `
                -ErrorAction Stop | Out-Null
            $junctionCreated = $true
        }
        catch { }
        if ($junctionCreated) {
            $decision = Get-Wave3ArtifactCheckpointDecision -WorkerConfig $worker `
                -WorkspacePath $checkpointRoot -DeclaredToolCalls 3 -CompletedToolCalls 3 `
                -TelemetryFresh $true -PreviouslySatisfied $false
            Assert-True ($decision.kind -ceq 'artifact_checkpoint_not_satisfied_by_deadline') `
                'A nonempty artifact through an out-of-workspace junction passed the checkpoint'
        }

        $hardlinkOriginal = Join-Path $checkpointRoot 'original.json'
        $hardlinkPath = Join-Path $checkpointRoot 'checkpoint.json'
        [System.IO.File]::WriteAllText($hardlinkOriginal, '{}')
        $hardlinkCreated = $false
        try {
            New-Item -ItemType HardLink -Path $hardlinkPath -Target $hardlinkOriginal `
                -ErrorAction Stop | Out-Null
            $hardlinkCreated = $true
        }
        catch { }
        if ($hardlinkCreated) {
            $worker.required_outputs[0].path = 'checkpoint.json'
            $decision = Get-Wave3ArtifactCheckpointDecision -WorkerConfig $worker `
                -WorkspacePath $checkpointRoot -DeclaredToolCalls 3 -CompletedToolCalls 3 `
                -TelemetryFresh $true -PreviouslySatisfied $false
            Assert-True ($decision.kind -ceq 'artifact_checkpoint_not_satisfied_by_deadline') `
                'A hardlinked required artifact passed the checkpoint'
        }
    }

    Invoke-Test 'supervisor wires checkpoint failures as ordinary failed workers' {
        $source = Get-Content -LiteralPath $supervisorPath -Raw
        Assert-True ($source.Contains('Get-Wave3ArtifactCheckpointDecision')) `
            'Watchdog does not invoke the external artifact checkpoint'
        Assert-True ($source.Contains('-CompletedToolCalls $completedToolCalls')) `
            'Watchdog checkpoint does not use completed tool-result receipts'
        Assert-True ($source.Contains('-TelemetryFresh ([bool]$freshMetricsByWorker')) `
            'Watchdog checkpoint is not gated by fresh telemetry'
        Assert-True ($source.Contains('-BudgetExceeded $null -TerminalStatus failed')) `
            'Checkpoint stop does not use ordinary failed status'
        Assert-True ($source.Contains('$liveByWorker[$workerId] = ''failed''')) `
            'Checkpoint failure is not fed into ordinary peer-isolating failure handling'
    }

    Invoke-Test 'watchdog ownership rejects a foreign PID without side effects and admits the owner' {
        $ownershipRoot = Join-Path $temporaryRoot 'watchdog-ownership'
        [System.IO.Directory]::CreateDirectory($ownershipRoot) | Out-Null
        & {
            param($SupervisorUnderTest, $OwnershipRoot)
            . $SupervisorUnderTest -Action Status -RunId 'unit-watchdog-ownership' -Stage E

            $script:WatchdogOwnershipFixtureState = $null
            $script:WatchdogOwnershipIdentityCalls = 0
            $script:WatchdogOwnershipStateWrites = 0
            $script:WatchdogOwnershipFailClosedCalls = 0

            function Get-ValidatedConfig {
                return [pscustomobject]@{ config_path = 'unit-watchdog-ownership.json' }
            }
            function Open-RunLock {
                return [System.IO.MemoryStream]::new()
            }
            function Read-State {
                return $script:WatchdogOwnershipFixtureState
            }
            function Assert-StateMatchesConfig($State, $Validation) { }
            function Get-WatchdogProcessIdentity($StageState) {
                $script:WatchdogOwnershipIdentityCalls++
                return [pscustomobject]@{ exists = $true; trusted = $true; reason = 'match' }
            }
            function Invoke-WatchdogPass($State, $Validation, [string]$StageId) {
                return $false
            }
            function Write-State($State, $Validation) {
                $script:WatchdogOwnershipStateWrites++
            }
            function Invoke-WatchdogFailClosedActions(
                $TrustedState,
                [string]$StageId,
                [string]$Reason
            ) {
                $script:WatchdogOwnershipFailClosedCalls++
                return @()
            }

            $foreignRoot = Join-Path $OwnershipRoot 'foreign'
            [System.IO.Directory]::CreateDirectory($foreignRoot) | Out-Null
            $watchdogRoot = $foreignRoot
            $foreignPid = if ($PID -lt [int]::MaxValue) { [int]$PID + 1 } else { [int]$PID - 1 }
            $foreignStage = [pscustomobject]@{
                id = 'E'
                status = 'running'
                watchdog_pid = $foreignPid
                stop_reason = $null
            }
            $script:WatchdogOwnershipFixtureState = [pscustomobject]@{
                stages = @($foreignStage)
                workers = @()
            }
            $foreignHeartbeat = Join-Path $foreignRoot 'E.heartbeat.json'
            $sentinel = 'registered-watchdog-heartbeat'
            [System.IO.File]::WriteAllText(
                $foreignHeartbeat,
                $sentinel,
                [System.Text.UTF8Encoding]::new($false)
            )
            $caught = $null
            try { Watchdog-Action }
            catch { $caught = $_ }
            Assert-True ($null -ne $caught -and $caught.Exception.Message -like `
                'watchdog_invocation_pid_mismatch:*') `
                'A foreign watchdog invocation was not rejected by registered PID'
            Assert-True ([System.IO.File]::ReadAllText($foreignHeartbeat) -ceq $sentinel) `
                'A rejected watchdog overwrote the registered watchdog heartbeat'
            Assert-True (-not (Test-Path -LiteralPath (Join-Path $foreignRoot 'E.error.txt')) -and
                -not (Test-Path -LiteralPath (Join-Path $foreignRoot 'E.exit.json'))) `
                'A rejected watchdog wrote shared error or exit sidecars'
            Assert-True ($script:WatchdogOwnershipIdentityCalls -eq 0 -and
                $script:WatchdogOwnershipStateWrites -eq 0 -and
                $script:WatchdogOwnershipFailClosedCalls -eq 0) `
                'A rejected watchdog reached identity, state mutation, or fail-closed actions'

            $ownerRoot = Join-Path $OwnershipRoot 'owner'
            [System.IO.Directory]::CreateDirectory($ownerRoot) | Out-Null
            $watchdogRoot = $ownerRoot
            $ownerStage = [pscustomobject]@{
                id = 'E'
                status = 'running'
                watchdog_pid = [int]$PID
                stop_reason = 'fixture_complete'
            }
            $script:WatchdogOwnershipFixtureState = [pscustomobject]@{
                stages = @($ownerStage)
                workers = @()
            }
            $script:WatchdogOwnershipIdentityCalls = 0
            $script:WatchdogOwnershipStateWrites = 0
            $script:WatchdogOwnershipFailClosedCalls = 0
            Watchdog-Action

            $ownerHeartbeat = Get-Content -LiteralPath (Join-Path $ownerRoot 'E.heartbeat.json') `
                -Raw | ConvertFrom-Json -Depth 20
            $ownerExit = Get-Content -LiteralPath (Join-Path $ownerRoot 'E.exit.json') `
                -Raw | ConvertFrom-Json -Depth 20
            Assert-True ([int]$ownerHeartbeat.pid -eq [int]$PID -and
                [string]$ownerHeartbeat.phase -ceq 'checking_budgets') `
                'The registered watchdog did not publish its owned heartbeat'
            Assert-True ([int]$ownerExit.pid -eq [int]$PID -and
                [string]$ownerExit.status -ceq 'clean_exit' -and
                [string]$ownerExit.reason -ceq 'fixture_complete') `
                'The registered watchdog did not complete its one-pass fixture cleanly'
            Assert-True ($script:WatchdogOwnershipIdentityCalls -eq 1 -and
                $script:WatchdogOwnershipStateWrites -eq 1 -and
                $script:WatchdogOwnershipFailClosedCalls -eq 0) `
                'The registered watchdog did not execute exactly one authenticated pass'
            Assert-True (-not (Test-Path -LiteralPath (Join-Path $ownerRoot 'E.error.txt'))) `
                'The registered watchdog wrote an unexpected error sidecar'
        } $supervisorPath $ownershipRoot
    }

    Invoke-Test 'watchdog behavior persists an early receipt and rejects an unreceipted overshoot' {
        $behaviorRoot = Join-Path $temporaryRoot 'checkpoint-watchdog-behavior'
        [System.IO.Directory]::CreateDirectory($behaviorRoot) | Out-Null
        & {
            param($SupervisorUnderTest, $WorkspaceUnderTest)
            . $SupervisorUnderTest -Action Status -RunId 'unit-checkpoint-import'

            function Get-LiveWorkerStatus($WorkerState) {
                return [string]$WorkerState.status
            }
            function Get-WatchdogMetrics($WorkerState, [string]$LiveStatus, [datetimeoffset]$ObservedAt) {
                return [pscustomobject]@{
                    metrics = $script:CheckpointFixtureMetrics
                    fresh = $true
                }
            }
            function Get-WorkerProcessLifetime($WorkerState, [string]$LiveStatus, [datetimeoffset]$NowUtc) {
                return [pscustomobject]@{
                    process_start_utc = '2026-01-01T00:00:00.0000000+00:00'
                    process_end_utc = '2026-01-01T00:00:01.0000000+00:00'
                    elapsed_seconds = 1.0
                }
            }
            function Stop-WatchdogWorker(
                $WorkerState,
                [string]$Reason,
                $BudgetExceeded,
                [string]$TerminalStatus = 'stopped'
            ) {
                $WorkerState.stopped_utc = '2026-01-01T00:00:02.0000000+00:00'
                $WorkerState.stop_reason = $Reason
                $WorkerState.budget_exceeded = $BudgetExceeded
                $WorkerState.status = $TerminalStatus
            }

            $workerConfig = [pscustomobject]@{
                id = 'E01'; stage = 'E'
                budget = [pscustomobject]@{
                    max_tokens = 1000; timeout_seconds = 30; max_tool_calls = 10
                    max_output_bytes = 1024; artifact_checkpoint_tool_calls = 3
                }
                required_outputs = @([pscustomobject]@{
                    source = 'workspace'; path = 'evidence.json'
                })
            }
            $workerState = [pscustomobject]@{
                id = 'E01'; stage = 'E'; status = 'running'
                process_start_utc = '2026-01-01T00:00:00Z'; process_exit_utc = $null
                workspace_dir = $WorkspaceUnderTest
                last_metrics = $null; watchdog_checked_utc = $null
                artifact_checkpoint_satisfied = $null; artifact_checkpoint_failed = $null
                stopped_utc = $null; stop_reason = $null; budget_exceeded = $null
            }
            $stageState = [pscustomobject]@{
                id = 'E'; status = 'running'; watchdog_stopped_utc = $null
                stopped_utc = $null; stop_reason = $null
            }
            $state = [pscustomobject]@{
                stages = @($stageState); workers = @($workerState)
                actual_token_ceiling = [int64]10000
            }
            $validation = [pscustomobject]@{
                config = [pscustomobject]@{ workers = @($workerConfig) }
            }

            $script:CheckpointFixtureMetrics = [pscustomobject]@{
                total_tokens = 10; tool_calls = 3; completed_tool_calls = 2
            }
            $keepWatching = Invoke-WatchdogPass $state $validation E
            Assert-True $keepWatching 'Nth declared call in flight terminated the worker'
            Assert-True ($workerState.status -ceq 'running' -and
                $null -eq $workerState.artifact_checkpoint_failed) `
                'In-flight declaration was classified as a checkpoint failure'

            [System.IO.File]::WriteAllText(
                (Join-Path $WorkspaceUnderTest 'evidence.json'), '{}'
            )
            $script:CheckpointFixtureMetrics = [pscustomobject]@{
                total_tokens = 20; tool_calls = 3; completed_tool_calls = 3
            }
            $keepWatching = Invoke-WatchdogPass $state $validation E
            Assert-True $keepWatching 'Exact quiescent checkpoint stopped the worker'
            Assert-True ($null -ne $workerState.artifact_checkpoint_satisfied -and
                $workerState.artifact_checkpoint_satisfied.observed_completed_tool_calls -eq 3) `
                'Watchdog did not persist the exact completed-result receipt'

            [System.IO.File]::Delete((Join-Path $WorkspaceUnderTest 'evidence.json'))
            $script:CheckpointFixtureMetrics = [pscustomobject]@{
                total_tokens = 30; tool_calls = 4; completed_tool_calls = 4
            }
            $keepWatching = Invoke-WatchdogPass $state $validation E
            Assert-True ($keepWatching -and $workerState.status -ceq 'running') `
                'Persisted checkpoint receipt was revoked by later artifact state'

            $workerState.status = 'running'
            $workerState.artifact_checkpoint_satisfied = $null
            $workerState.artifact_checkpoint_failed = $null
            $workerState.stop_reason = $null
            $workerState.stopped_utc = $null
            $stageState.status = 'running'
            $stageState.stop_reason = $null
            $stageState.stopped_utc = $null
            [System.IO.File]::WriteAllText(
                (Join-Path $WorkspaceUnderTest 'evidence.json'), '{}'
            )
            $keepWatching = Invoke-WatchdogPass $state $validation E
            Assert-True (-not $keepWatching -and $workerState.status -ceq 'failed') `
                'Unreceipted overshoot with a late artifact did not fail the worker'
            Assert-True ($workerState.stop_reason -like `
                'artifact_checkpoint_not_satisfied_by_deadline:*') `
                'Watchdog did not preserve the precise checkpoint failure reason'
        } $supervisorPath $behaviorRoot
    }

    Invoke-Test 'live budget decision rejects only values above each exact ceiling' {
        $start = [datetimeoffset]::Parse('2026-01-01T00:00:00Z')
        $budget = [pscustomobject]@{
            max_tokens = 100
            max_tool_calls = 3
            timeout_seconds = 10
        }
        $exact = Get-Wave3BudgetViolation -StartedUtc $start -NowUtc $start.AddSeconds(10) `
            -TotalTokens 100 -ToolCalls 3 -Budget $budget -RunTotalTokens 7500000
        Assert-True ($null -eq $exact) 'Exact budget ceilings must remain permitted'

        $tokens = Get-Wave3BudgetViolation -StartedUtc $start -NowUtc $start `
            -TotalTokens 101 -ToolCalls 0 -Budget $budget
        Assert-True ($tokens.kind -ceq 'worker_total_tokens') 'Token excess was not selected'
        Assert-True ($tokens.observed -eq 101 -and $tokens.limit -eq 100) 'Wrong token excess values'

        $tools = Get-Wave3BudgetViolation -StartedUtc $start -NowUtc $start `
            -TotalTokens 0 -ToolCalls 4 -Budget $budget
        Assert-True ($tools.kind -ceq 'worker_tool_calls') 'Tool excess was not selected'

        $wall = Get-Wave3BudgetViolation -StartedUtc $start -NowUtc $start.AddMilliseconds(10001) `
            -TotalTokens 0 -ToolCalls 0 -Budget $budget
        Assert-True ($wall.kind -ceq 'worker_wall_seconds') 'Wall excess was not selected'

        $run = Get-Wave3BudgetViolation -StartedUtc $start -NowUtc $start `
            -TotalTokens 101 -ToolCalls 4 -Budget $budget -RunTotalTokens 7500001
        Assert-True ($run.kind -ceq 'run_total_tokens') 'Run-wide excess must take precedence'
    }

    Invoke-Test 'worker budget excess isolates only offender while run excess aborts peers' {
        $localViolations = @{
            O01 = [pscustomobject]@{ kind = 'worker_total_tokens'; observed = 226; limit = 225 }
        }
        $localPlan = Get-Wave3BudgetEnforcementPlan -Violations $localViolations `
            -RunningWorkerIds @('O01', 'O02', 'O03', 'O04')
        Assert-True (-not $localPlan.abort_stage) 'Worker-local excess aborted the stage'
        Assert-True (($localPlan.stop_worker_ids -join ',') -ceq 'O01') `
            'Worker-local excess stopped a peer'
        Assert-True (($localPlan.continue_worker_ids -join ',') -ceq 'O02,O03,O04') `
            'Worker-local excess did not preserve all peers'

        $runViolations = @{
            O01 = [pscustomobject]@{ kind = 'run_total_tokens'; observed = 7500001; limit = 7500000 }
        }
        $runPlan = Get-Wave3BudgetEnforcementPlan -Violations $runViolations `
            -RunningWorkerIds @('O01', 'O02', 'O03', 'O04')
        Assert-True $runPlan.abort_stage 'Run-wide excess did not abort the stage'
        Assert-True (($runPlan.stop_worker_ids -join ',') -ceq 'O01,O02,O03,O04') `
            'Run-wide excess did not stop every live peer'
        Assert-True ($runPlan.continue_worker_ids.Count -eq 0) `
            'Run-wide excess left a peer eligible to continue'
    }

    Invoke-Test 'ordinary worker failure preserves peers but identity mismatch aborts them' {
        $ordinary = @{ E01 = 'failed'; E02 = 'running'; E03 = 'completed'; E04 = 'running' }
        $plan = Get-Wave3FailureEnforcementPlan -LiveStatusByWorker $ordinary `
            -StageWorkerIds @('E01', 'E02', 'E03', 'E04')
        Assert-True (-not $plan.abort_stage) 'Ordinary worker failure aborted its peers'
        Assert-True (($plan.peer_ids_to_continue -join ',') -ceq 'E02,E04') `
            'Ordinary worker failure did not preserve live peers'

        $identity = @{ E01 = 'identity_mismatch'; E02 = 'running'; E03 = 'completed'; E04 = 'running' }
        $plan = Get-Wave3FailureEnforcementPlan -LiveStatusByWorker $identity `
            -StageWorkerIds @('E01', 'E02', 'E03', 'E04')
        Assert-True $plan.abort_stage 'Identity mismatch did not abort the stage'
        Assert-True (($plan.peer_ids_to_stop -join ',') -ceq 'E02,E04') `
            'Identity mismatch did not target all live peers'
    }

    Invoke-Test 'only a trusted-running to identity-mismatch transition receives settlement' {
        $settle = Get-Wave3WorkerIdentitySettlementPlan `
            -LiveBefore running -LiveAfter identity_mismatch -SettlementMilliseconds 250
        Assert-True $settle.should_settle `
            'Trusted-running teardown transition did not receive settlement'
        Assert-True ($settle.settlement_milliseconds -eq 250) `
            'Settlement duration changed from the bounded 250 milliseconds'

        foreach ($pair in @(
            @('identity_mismatch', 'identity_mismatch'),
            @('running', 'running'),
            @('running', 'completed'),
            @('running', 'failed'),
            @('running', 'lost'),
            @('pending', 'identity_mismatch')
        )) {
            $plan = Get-Wave3WorkerIdentitySettlementPlan `
                -LiveBefore $pair[0] -LiveAfter $pair[1] -SettlementMilliseconds 250
            Assert-True (-not $plan.should_settle) `
                "Unexpected settlement for $($pair[0]) -> $($pair[1])"
        }

        $supervisorText = Get-Content -LiteralPath $supervisorPath -Raw
        Assert-True ($supervisorText.Contains(
            '$workerIdentitySettlementMilliseconds = 250'
        )) 'Supervisor does not pin the 250-millisecond settlement'
        Assert-True (([regex]::Matches(
            $supervisorText,
            'Start-Sleep -Milliseconds \$settlement\.settlement_milliseconds'
        )).Count -eq 1) 'Supervisor settlement is missing or can loop'
    }

    Invoke-Test 'watchdog settles a trusted teardown transition exactly once and re-observes it' {
        & {
            param($SupervisorUnderTest, $WorkspaceUnderTest)
            . $SupervisorUnderTest -Action Status -RunId 'unit-worker-settlement-import'

            $script:WorkerSettlementSequences = @{}
            $script:WorkerSettlementCalls = @{}
            $script:WorkerSettlementMetricStatuses = @{}
            $script:WorkerSettlementSleeps = @()
            $script:WorkerSettlementStoppedPids = @()

            function Get-LiveWorkerStatus($WorkerState) {
                $workerId = [string]$WorkerState.id
                $callIndex = if ($script:WorkerSettlementCalls.ContainsKey($workerId)) {
                    [int]$script:WorkerSettlementCalls[$workerId]
                }
                else { 0 }
                $sequence = @($script:WorkerSettlementSequences[$workerId])
                if (-not $sequence.Count) {
                    throw "No live-status sequence for settlement fixture worker $workerId"
                }
                if ($callIndex -ge $sequence.Count) {
                    throw "Unexpected extra live-status observation for settlement fixture worker $workerId"
                }
                $script:WorkerSettlementCalls[$workerId] = $callIndex + 1
                return [string]$sequence[$callIndex]
            }

            function Get-WatchdogMetrics(
                $WorkerState,
                [string]$LiveStatus,
                [datetimeoffset]$ObservedAt
            ) {
                $workerId = [string]$WorkerState.id
                if (-not $script:WorkerSettlementMetricStatuses.ContainsKey($workerId)) {
                    $script:WorkerSettlementMetricStatuses[$workerId] =
                        [System.Collections.Generic.List[string]]::new()
                }
                $statusList = [System.Collections.Generic.List[string]](
                    $script:WorkerSettlementMetricStatuses[$workerId]
                )
                $statusList.Add($LiveStatus)
                return [pscustomobject]@{
                    metrics = [pscustomobject]@{
                        total_tokens = [int64]0
                        tool_calls = [int64]0
                        completed_tool_calls = [int64]0
                    }
                    fresh = $true
                }
            }

            function Get-WorkerProcessLifetime(
                $WorkerState,
                [string]$LiveStatus,
                [datetimeoffset]$NowUtc
            ) {
                return [pscustomobject]@{
                    process_start_utc = '2026-01-01T00:00:00.0000000+00:00'
                    process_end_utc = '2026-01-01T00:00:01.0000000+00:00'
                    elapsed_seconds = 1.0
                }
            }

            function Start-Sleep {
                param([int]$Milliseconds)
                $script:WorkerSettlementSleeps += $Milliseconds
            }

            function Stop-Wave3ProcessTree {
                param(
                    [int]$ProcessId,
                    [string]$ExpectedStartUtc,
                    [string]$ExpectedExecutablePath,
                    [string[]]$RequiredCommandLineMarkers
                )
                $script:WorkerSettlementStoppedPids += $ProcessId
                return [pscustomobject]@{ stopped = $true; process_id = $ProcessId }
            }

            function New-WorkerSettlementState([string]$Id, [int]$ProcessId) {
                return [pscustomobject]@{
                    id = $Id
                    stage = 'E'
                    status = 'running'
                    pid = $ProcessId
                    process_start_utc = '2026-01-01T00:00:00Z'
                    process_exit_utc = $null
                    expected_executable_path = 'C:\fixture\pwsh.exe'
                    command_line_markers = @('settlement-fixture')
                    workspace_dir = $WorkspaceUnderTest
                    last_metrics = $null
                    watchdog_checked_utc = $null
                    artifact_checkpoint_satisfied = $null
                    artifact_checkpoint_failed = $null
                    stopped_utc = $null
                    stop_reason = $null
                    budget_exceeded = $null
                }
            }

            function New-WorkerSettlementConfig([string]$Id) {
                return [pscustomobject]@{
                    id = $Id
                    stage = 'E'
                    budget = [pscustomobject]@{
                        max_tokens = [int64]1000
                        max_tool_calls = [int64]10
                        timeout_seconds = 30
                    }
                    required_outputs = @()
                }
            }

            function Invoke-WorkerSettlementFixture(
                [string[]]$PrimarySequence,
                [switch]$IncludeRunningPeer
            ) {
                $primary = New-WorkerSettlementState E01 101
                $workers = @($primary)
                $workerConfigs = @(New-WorkerSettlementConfig E01)
                $script:WorkerSettlementSequences = @{ E01 = @($PrimarySequence) }
                if ($IncludeRunningPeer) {
                    $peer = New-WorkerSettlementState E02 202
                    $workers += $peer
                    $workerConfigs += New-WorkerSettlementConfig E02
                    $script:WorkerSettlementSequences.E02 = @('running', 'running', 'running')
                }
                else { $peer = $null }
                $script:WorkerSettlementCalls = @{}
                $script:WorkerSettlementMetricStatuses = @{}
                $script:WorkerSettlementSleeps = @()
                $script:WorkerSettlementStoppedPids = @()

                $stageState = [pscustomobject]@{
                    id = 'E'
                    status = 'running'
                    watchdog_stopped_utc = $null
                    stopped_utc = $null
                    stop_reason = $null
                }
                $state = [pscustomobject]@{
                    stages = @($stageState)
                    workers = @($workers)
                    actual_token_ceiling = [int64]10000
                }
                $validation = [pscustomobject]@{
                    config = [pscustomobject]@{ workers = @($workerConfigs) }
                }
                $keepWatching = Invoke-WatchdogPass $state $validation E
                return [pscustomobject]@{
                    keep_watching = [bool]$keepWatching
                    primary = $primary
                    peer = $peer
                    stage = $stageState
                    primary_observations = [int]$script:WorkerSettlementCalls.E01
                    primary_metric_statuses =
                        @($script:WorkerSettlementMetricStatuses.E01)
                    sleeps = @($script:WorkerSettlementSleeps)
                    stopped_pids = @($script:WorkerSettlementStoppedPids)
                }
            }

            $completed = Invoke-WorkerSettlementFixture `
                -PrimarySequence @('running', 'identity_mismatch', 'completed') `
                -IncludeRunningPeer
            Assert-True ($completed.keep_watching -and
                $completed.primary.status -ceq 'completed' -and
                $completed.peer.status -ceq 'running' -and
                $completed.stage.status -ceq 'running') `
                'A clean exit receipt after settlement did not complete only that worker'
            Assert-True ($completed.primary_observations -eq 3 -and
                ($completed.sleeps -join ',') -ceq '250') `
                'Clean teardown did not receive exactly one sleep and third observation'
            Assert-True (($completed.primary_metric_statuses -join ',') -ceq `
                'running,completed') `
                "Clean teardown did not refresh metrics against the settled completion receipt: $($completed.primary_metric_statuses -join ',')"
            Assert-True ($completed.stopped_pids.Count -eq 0) `
                'Clean teardown stopped a worker or its running peer'

            $directCompletion = Invoke-WorkerSettlementFixture `
                -PrimarySequence @('running', 'completed')
            Assert-True (-not $directCompletion.keep_watching -and
                $directCompletion.primary.status -ceq 'completed' -and
                $directCompletion.stage.status -ceq 'completed') `
                'A direct completion receipt did not complete the worker and stage'
            Assert-True ($directCompletion.primary_observations -eq 2 -and
                $directCompletion.sleeps.Count -eq 0 -and
                ($directCompletion.primary_metric_statuses -join ',') -ceq `
                    'running,completed') `
                'Direct completion was settled or did not refresh terminal metrics'

            $persistentMismatch = Invoke-WorkerSettlementFixture `
                -PrimarySequence @('running', 'identity_mismatch', 'identity_mismatch') `
                -IncludeRunningPeer
            Assert-True (-not $persistentMismatch.keep_watching -and
                $persistentMismatch.primary.status -ceq 'failed' -and
                $persistentMismatch.stage.status -ceq 'failed') `
                'Persistent identity mismatch did not abort the stage after settlement'
            Assert-True ($persistentMismatch.primary_observations -eq 3 -and
                ($persistentMismatch.sleeps -join ',') -ceq '250') `
                'Persistent mismatch did not receive exactly one sleep and third observation'
            Assert-True (($persistentMismatch.primary_metric_statuses -join ',') -ceq `
                'running,identity_mismatch') `
                'Persistent mismatch did not refresh metrics against its settled identity state'
            Assert-True (($persistentMismatch.stopped_pids -join ',') -ceq '202') `
                'Persistent mismatch did not stop only the verified running peer'

            $initialMismatch = Invoke-WorkerSettlementFixture `
                -PrimarySequence @('identity_mismatch', 'identity_mismatch') `
                -IncludeRunningPeer
            Assert-True (-not $initialMismatch.keep_watching -and
                $initialMismatch.stage.status -ceq 'failed') `
                'An identity mismatch present at the first observation did not abort the stage'
            Assert-True ($initialMismatch.primary_observations -eq 2 -and
                $initialMismatch.sleeps.Count -eq 0) `
                'A pre-existing identity mismatch incorrectly received settlement'
            Assert-True (($initialMismatch.stopped_pids -join ',') -ceq '202') `
                'Pre-existing mismatch did not preserve the uncertain PID while stopping its peer'

            $recovered = Invoke-WorkerSettlementFixture `
                -PrimarySequence @('running', 'identity_mismatch', 'running')
            Assert-True ($recovered.keep_watching -and
                $recovered.primary.status -ceq 'running' -and
                $recovered.stage.status -ceq 'running') `
                'A worker that remained live after settlement was not kept running'
            Assert-True ($recovered.primary_observations -eq 3 -and
                ($recovered.sleeps -join ',') -ceq '250' -and
                $recovered.stopped_pids.Count -eq 0) `
                'Recovered worker did not receive exactly one safe re-observation'
            Assert-True (($recovered.primary_metric_statuses -join ',') -ceq 'running') `
                'Recovered worker unexpectedly refreshed terminal metrics'

            $ordinaryFailure = Invoke-WorkerSettlementFixture `
                -PrimarySequence @('running', 'identity_mismatch', 'failed') `
                -IncludeRunningPeer
            Assert-True ($ordinaryFailure.keep_watching -and
                $ordinaryFailure.primary.status -ceq 'failed' -and
                $ordinaryFailure.peer.status -ceq 'running' -and
                $ordinaryFailure.stage.status -ceq 'running') `
                'Ordinary failure after settlement did not preserve its running peer'
            Assert-True ($ordinaryFailure.primary_observations -eq 3 -and
                ($ordinaryFailure.sleeps -join ',') -ceq '250' -and
                $ordinaryFailure.stopped_pids.Count -eq 0) `
                'Ordinary failure after settlement was not observed exactly once without peer stop'
            Assert-True (($ordinaryFailure.primary_metric_statuses -join ',') -ceq `
                'running,failed') `
                'Ordinary failure did not refresh metrics against its settled terminal state'
        } $supervisorPath (Join-Path $temporaryRoot 'worker-settlement')
    }

    Invoke-Test 'v4 supervisor emits hardened executable O-stage contracts' {
        $supervisorText = Get-Content -LiteralPath $supervisorPath -Raw
        foreach ($requiredText in @(
            'The schema permits no extra, note, helper, or self-check key.',
            'Place each assigned KEY=VALUE marker exactly once as an isolated token',
            'one executable mutation locus as either an exact',
            'Write oracle.json by tool call 10',
            '[0x100ed3c0,0x100ed550)',
            '[0x100ed3f4,0x100ed42c)',
            'include every assigned marker, especially PROVENANCE_SCOPE'
        )) {
            Assert-True ($supervisorText.Contains($requiredText)) `
                "Supervisor is missing O-stage hardening text: $requiredText"
        }
    }

    Invoke-Test 'completed wall budget uses process start through exit receipt' {
        $start = [datetimeoffset]::Parse('2026-01-01T00:00:00Z')
        $exit = $start.AddSeconds(11)
        $lifetime = Get-Wave3ProcessLifetime -ProcessStartUtc $start `
            -NowUtc $start.AddSeconds(100) -Completed -ExitFileLastWriteUtc $exit
        Assert-True ([math]::Abs($lifetime.elapsed_seconds - 11) -lt 0.001) `
            'Completed lifetime did not use the exit receipt'
        $budget = [pscustomobject]@{ max_tokens = 100; max_tool_calls = 3; timeout_seconds = 10 }
        $decision = Get-Wave3BudgetViolation `
            -StartedUtc ([datetimeoffset]::Parse($lifetime.process_start_utc)) `
            -NowUtc ([datetimeoffset]::Parse($lifetime.process_end_utc)) `
            -TotalTokens 0 -ToolCalls 0 -Budget $budget
        Assert-True ($decision.kind -ceq 'worker_wall_seconds') `
            'Process lifetime overage was hidden by session timing'
    }

    Invoke-Test 'identity and fail-closed helpers never kill an uncertain PID' {
        $start = [datetimeoffset]::Parse('2026-01-01T00:00:00Z')
        $trusted = Test-Wave3ProcessIdentityRecord -ExpectedStartUtc $start -ActualStartUtc $start `
            -ExpectedExecutablePath 'C:\tools\pwsh.exe' -ActualExecutablePath 'C:\tools\pwsh.exe' `
            -RequiredCommandLineMarkers @('session-123', 'task.md') `
            -ActualCommandLine 'pwsh.exe session-123 task.md'
        Assert-True $trusted.trusted 'Exact identity should be trusted'
        $mismatch = Test-Wave3ProcessIdentityRecord -ExpectedStartUtc $start -ActualStartUtc $start `
            -ExpectedExecutablePath 'C:\tools\pwsh.exe' -ActualExecutablePath 'C:\tools\pwsh.exe' `
            -RequiredCommandLineMarkers @('session-123', 'task.md') `
            -ActualCommandLine 'pwsh.exe other-session task.md'
        Assert-True (-not $mismatch.trusted) 'Missing session marker should reject identity'
        $uncertain = Get-Wave3FailClosedDecision -WorkerProcessExists $true -IdentityTrusted $false
        Assert-True ($uncertain.action -ceq 'do_not_kill') 'Uncertain PID must never be killed'
        $verified = Get-Wave3FailClosedDecision -WorkerProcessExists $true -IdentityTrusted $true
        Assert-True ($verified.action -ceq 'kill_verified_tree') 'Verified live tree should fail closed'
    }

    Invoke-Test 'session metrics distinguish declared calls from completed tool-result receipts' {
        $sessionDirectory = Join-Path $temporaryRoot 'sessions'
        [System.IO.Directory]::CreateDirectory($sessionDirectory) | Out-Null
        $sessionId = 'unit-E-E01-a1'
        $sessionPath = Join-Path $sessionDirectory ('2026-01-01T00-00-00-000Z_' + $sessionId + '.jsonl')
        $entries = @(
            [ordered]@{ type = 'session'; timestamp = '2026-01-01T00:00:00Z' },
            [ordered]@{
                type = 'message'
                timestamp = '2026-01-01T00:00:01Z'
                message = [ordered]@{
                    role = 'assistant'
                    content = @([ordered]@{ type = 'toolCall'; id = 'call-1'; name = 'read' })
                    usage = [ordered]@{ totalTokens = 100; input = 70; output = 10; cacheRead = 20 }
                }
            },
            [ordered]@{
                type = 'message'
                timestamp = '2026-01-01T00:00:02Z'
                message = [ordered]@{
                    role = 'toolResult'
                    toolCallId = 'call-1'
                    content = @([ordered]@{ type = 'text'; text = 'done' })
                }
            },
            [ordered]@{
                type = 'message'
                timestamp = '2026-01-01T00:00:03Z'
                message = [ordered]@{
                    role = 'assistant'
                    content = @([ordered]@{ type = 'text'; text = '{}' })
                    usage = [ordered]@{ totalTokens = 50; input = 30; output = 20; cacheRead = 0 }
                }
            }
        )
        $lines = @($entries | ForEach-Object { $_ | ConvertTo-Json -Depth 20 -Compress })
        [System.IO.File]::WriteAllText(
            $sessionPath,
            (($lines -join "`n") + "`n"),
            [System.Text.UTF8Encoding]::new($false)
        )
        $metrics = Get-Wave3SessionMetrics -SessionDirectory $sessionDirectory -SessionId $sessionId
        Assert-True ($metrics.total_tokens -eq 150) 'Wrong total-token count'
        Assert-True ($metrics.input_tokens -eq 100) 'Wrong input-token count'
        Assert-True ($metrics.output_tokens -eq 30) 'Wrong output-token count'
        Assert-True ($metrics.cache_read_tokens -eq 20) 'Wrong cache-read count'
        Assert-True ($metrics.tool_calls -eq 1) 'Wrong tool-call count'
        Assert-True ($metrics.completed_tool_calls -eq 1) 'Wrong completed tool-call count'
        Assert-True ($metrics.assistant_turns -eq 2) 'Wrong assistant-turn count'
        Assert-True ($metrics.parsed_byte_count -eq $metrics.byte_count) `
            'Complete session should parse its full snapshot'
        Assert-True ($metrics.first_timestamp_utc -ceq '2026-01-01T00:00:00.0000000+00:00') `
            'First timestamp should preserve the source UTC instant'
        Assert-True ($metrics.last_timestamp_utc -ceq '2026-01-01T00:00:03.0000000+00:00') `
            'Last timestamp should preserve the source UTC instant'
    }

    Invoke-Test 'completed-call receipts require exact declared IDs and are unique' {
        foreach ($mutation in @('unknown_result', 'duplicate_result', 'missing_declaration_id')) {
            $sessionDirectory = Join-Path $temporaryRoot "receipt-$mutation"
            [System.IO.Directory]::CreateDirectory($sessionDirectory) | Out-Null
            $sessionId = "unit-receipt-$mutation"
            $declaration = [ordered]@{
                type = 'message'; timestamp = '2026-01-01T00:00:01Z'
                message = [ordered]@{
                    role = 'assistant'
                    content = @([ordered]@{
                        type = 'toolCall'
                        id = if ($mutation -eq 'missing_declaration_id') { $null } else { 'call-1' }
                        name = 'read'
                    })
                    usage = [ordered]@{
                        totalTokens = 1; input = 1; output = 0; cacheRead = 0
                    }
                }
            }
            $resultId = if ($mutation -eq 'unknown_result') { 'call-2' } else { 'call-1' }
            $result = [ordered]@{
                type = 'message'; timestamp = '2026-01-01T00:00:02Z'
                message = [ordered]@{
                    role = 'toolResult'; toolCallId = $resultId
                    content = @([ordered]@{ type = 'text'; text = 'done' })
                }
            }
            $entries = @($declaration, $result)
            if ($mutation -eq 'duplicate_result') { $entries += $result }
            $text = (@($entries | ForEach-Object {
                $_ | ConvertTo-Json -Depth 20 -Compress
            }) -join "`n") + "`n"
            [System.IO.File]::WriteAllText(
                (Join-Path $sessionDirectory ("x_" + $sessionId + '.jsonl')),
                $text,
                [System.Text.UTF8Encoding]::new($false)
            )
            $caught = $false
            try {
                Get-Wave3SessionMetrics -SessionDirectory $sessionDirectory `
                    -SessionId $sessionId | Out-Null
            }
            catch { $caught = $true }
            Assert-True $caught "Malformed completion receipt $mutation was accepted"
        }
    }

    Invoke-Test 'live session snapshot shares access and ignores an incomplete tail' {
        $sessionDirectory = Join-Path $temporaryRoot 'live-sessions'
        [System.IO.Directory]::CreateDirectory($sessionDirectory) | Out-Null
        $sessionId = 'unit-I-I01-a1'
        $sessionPath = Join-Path $sessionDirectory `
            ('2026-01-01T00-00-00-000Z_' + $sessionId + '.jsonl')
        $first = [ordered]@{
            type = 'message'
            timestamp = '2026-01-01T00:00:01Z'
            message = [ordered]@{
                role = 'assistant'
                content = @([ordered]@{ type = 'text'; text = 'first' })
                usage = [ordered]@{ totalTokens = 25; input = 15; output = 10; cacheRead = 0 }
            }
        } | ConvertTo-Json -Depth 20 -Compress
        $second = [ordered]@{
            type = 'message'
            timestamp = '2026-01-01T00:00:02Z'
            message = [ordered]@{
                role = 'assistant'
                content = @([ordered]@{ type = 'toolCall'; id = 'live-call'; name = 'write' })
                usage = [ordered]@{ totalTokens = 75; input = 50; output = 15; cacheRead = 10 }
            }
        } | ConvertTo-Json -Depth 20 -Compress
        $third = [ordered]@{
            type = 'message'
            timestamp = '2026-01-01T00:00:03Z'
            message = [ordered]@{
                role = 'toolResult'
                toolCallId = 'live-call'
                content = @([ordered]@{ type = 'text'; text = 'written' })
            }
        } | ConvertTo-Json -Depth 20 -Compress
        $encoding = [System.Text.UTF8Encoding]::new($false)
        $writerShare = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
        $writer = [System.IO.FileStream]::new(
            $sessionPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            $writerShare
        )
        try {
            $prefix = $encoding.GetBytes($first + "`n" + $second.Substring(0, 20))
            $writer.Write($prefix, 0, $prefix.Length)
            $writer.Flush()

            $partial = Get-Wave3SessionMetrics -SessionDirectory $sessionDirectory `
                -SessionId $sessionId -AllowIncompleteTail
            Assert-True ($partial.total_tokens -eq 25) `
                'Live snapshot parsed an incomplete JSONL tail'
            Assert-True ($partial.parsed_byte_count -lt $partial.byte_count) `
                'Live snapshot did not report its ignored tail'

            $suffix = $encoding.GetBytes($second.Substring(20) + "`n")
            $writer.Write($suffix, 0, $suffix.Length)
            $writer.Flush()

            $complete = Get-Wave3SessionMetrics -SessionDirectory $sessionDirectory `
                -SessionId $sessionId -AllowIncompleteTail
            Assert-True ($complete.total_tokens -eq 100) `
                'Completed live record was not counted'
            Assert-True ($complete.tool_calls -eq 1) `
                'Completed live tool call was not counted'
            Assert-True ($complete.completed_tool_calls -eq 0) `
                'In-flight declaration was counted as a completed tool call'
            Assert-True ($complete.parsed_byte_count -eq $complete.byte_count) `
                'Completed live snapshot should have no ignored tail'

            $receipt = $encoding.GetBytes($third + "`n")
            $writer.Write($receipt, 0, $receipt.Length)
            $writer.Flush()
            $receipted = Get-Wave3SessionMetrics -SessionDirectory $sessionDirectory `
                -SessionId $sessionId -AllowIncompleteTail
            Assert-True ($receipted.tool_calls -eq 1 -and
                $receipted.completed_tool_calls -eq 1) `
                'Matching toolResult did not complete exactly one declaration'
        }
        finally {
            $writer.Dispose()
        }
    }

    Invoke-Test 'terminal session parses a valid final record without LF' {
        $sessionDirectory = Join-Path $temporaryRoot 'terminal-no-lf'
        [System.IO.Directory]::CreateDirectory($sessionDirectory) | Out-Null
        $sessionId = 'unit-R-R01-a1'
        $sessionPath = Join-Path $sessionDirectory ('x_' + $sessionId + '.jsonl')
        $entry = [ordered]@{
            type = 'message'
            timestamp = '2026-01-01T00:00:01Z'
            message = [ordered]@{
                role = 'assistant'
                content = @()
                usage = [ordered]@{ totalTokens = 99; input = 60; output = 19; cacheRead = 20 }
            }
        } | ConvertTo-Json -Depth 20 -Compress
        [System.IO.File]::WriteAllText($sessionPath, $entry,
            [System.Text.UTF8Encoding]::new($false))

        $live = Get-Wave3SessionMetrics -SessionDirectory $sessionDirectory `
            -SessionId $sessionId -AllowIncompleteTail
        $terminal = Get-Wave3SessionMetrics -SessionDirectory $sessionDirectory `
            -SessionId $sessionId
        Assert-True ($live.total_tokens -eq 0) `
            'Live reader should ignore a non-newline-terminated tail'
        Assert-True ($terminal.total_tokens -eq 99) `
            'Strict terminal reader discarded a valid final record'
    }

    Invoke-Test 'session metrics reject malformed complete JSON and oversized snapshots' {
        $sessionDirectory = Join-Path $temporaryRoot 'invalid-sessions'
        [System.IO.Directory]::CreateDirectory($sessionDirectory) | Out-Null
        $sessionId = 'unit-G-G01-a1'
        $sessionPath = Join-Path $sessionDirectory ('x_' + $sessionId + '.jsonl')
        [System.IO.File]::WriteAllText($sessionPath, "{bad}`n",
            [System.Text.UTF8Encoding]::new($false))
        $caught = $false
        try {
            Get-Wave3SessionMetrics -SessionDirectory $sessionDirectory `
                -SessionId $sessionId -AllowIncompleteTail | Out-Null
        }
        catch { $caught = $true }
        Assert-True $caught 'Malformed newline-complete JSON was ignored'

        $stream = [System.IO.FileStream]::new($sessionPath,
            [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::ReadWrite)
        try { $stream.SetLength(32MB + 1) }
        finally { $stream.Dispose() }
        $caught = $false
        try {
            Get-Wave3SessionMetrics -SessionDirectory $sessionDirectory `
                -SessionId $sessionId -AllowIncompleteTail | Out-Null
        }
        catch { $caught = $true }
        Assert-True $caught 'Oversized session snapshot was accepted'
    }

    Invoke-Test 'session metrics reject counter regression and same-length mutation' {
        $previous = [pscustomobject]@{
            session_sha256 = ('a' * 64); byte_count = 100; parsed_byte_count = 90
            total_tokens = 50; input_tokens = 30; output_tokens = 10
            cache_read_tokens = 10; assistant_turns = 2; tool_calls = 1
            completed_tool_calls = 1
        }
        $current = Copy-JsonObject $previous
        $current.byte_count = 101
        $current.parsed_byte_count = 91
        $current.total_tokens = 51
        Assert-True (Assert-Wave3MonotonicSessionMetrics $previous $current) `
            'Growing session metrics should be accepted'

        $regressed = Copy-JsonObject $current
        $regressed.tool_calls = 0
        $caught = $false
        try { Assert-Wave3MonotonicSessionMetrics $previous $regressed | Out-Null }
        catch { $caught = $true }
        Assert-True $caught 'Regressed tool-call count was accepted'

        $regressedCompletion = Copy-JsonObject $current
        $regressedCompletion.completed_tool_calls = 0
        $caught = $false
        try {
            Assert-Wave3MonotonicSessionMetrics $previous $regressedCompletion | Out-Null
        }
        catch { $caught = $true }
        Assert-True $caught 'Regressed completed-tool-call count was accepted'

        $mutated = Copy-JsonObject $previous
        $mutated.session_sha256 = ('b' * 64)
        $caught = $false
        try { Assert-Wave3MonotonicSessionMetrics $previous $mutated | Out-Null }
        catch { $caught = $true }
        Assert-True $caught 'Same-length session mutation was accepted'
    }

    Invoke-Test 'full-tree stop terminates the wrapper and its child' {
        $childPidPath = Join-Path $temporaryRoot 'tree-child.pid'
        $pwshPath = (Get-Command pwsh.exe).Source
        $quotedPwsh = $pwshPath.Replace("'", "''")
        $quotedPidPath = $childPidPath.Replace("'", "''")
        $wrapperCommand = @"
`$child = Start-Process -FilePath '$quotedPwsh' -ArgumentList @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30') -WindowStyle Hidden -PassThru
[System.IO.File]::WriteAllText('$quotedPidPath', [string]`$child.Id)
Wait-Process -Id `$child.Id
"@
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $pwshPath
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        foreach ($argument in @('-NoProfile', '-NonInteractive', '-Command', $wrapperCommand)) {
            $startInfo.ArgumentList.Add($argument)
        }
        $wrapper = [System.Diagnostics.Process]::Start($startInfo)
        $childPid = $null
        try {
            foreach ($unused in 1..100) {
                if (Test-Path -LiteralPath $childPidPath -PathType Leaf) {
                    $childPid = [int](Get-Content -LiteralPath $childPidPath -Raw)
                    break
                }
                Start-Sleep -Milliseconds 50
            }
            Assert-True ($null -ne $childPid) 'Child PID was not published'
            $startUtc = ([datetimeoffset]$wrapper.StartTime.ToUniversalTime()).ToString('o')
            Stop-Wave3ProcessTree -ProcessId $wrapper.Id -ExpectedStartUtc $startUtc `
                -ExpectedExecutablePath $pwshPath -RequiredCommandLineMarkers @($childPidPath) | Out-Null
            $wrapper.WaitForExit(5000) | Out-Null
            Assert-True ($null -eq (Get-Process -Id $wrapper.Id -ErrorAction SilentlyContinue)) `
                'Wrapper survived full-tree stop'
            Assert-True ($null -eq (Get-Process -Id $childPid -ErrorAction SilentlyContinue)) `
                'Child survived full-tree stop'
        }
        finally {
            if ($null -ne $childPid) {
                Stop-Process -Id $childPid -Force -ErrorAction SilentlyContinue
            }
            Stop-Process -Id $wrapper.Id -Force -ErrorAction SilentlyContinue
            $wrapper.Dispose()
        }
    }

    Invoke-Test 'evidence JSON schema accepts exact report and rejects prose' {
        $documentPath = Join-Path $temporaryRoot 'evidence.json'
        $document = [ordered]@{
            worker_id = 'E01'
            stage = 'E'
            conclusion = 'Pinned fact.'
            claims = @([ordered]@{
                fact_id = 'raw.byte.1'
                kind = 'raw_bytes'
                value = '90'
                source_path = 'fixture.bin'
                source_sha256 = ('0' * 64)
                locator = 'offset 0'
                extractor_command = 'Format-Hex fixture.bin'
                inference = $false
            })
            blockers = @()
        }
        Write-JsonFile $documentPath $document
        Test-Wave3JsonDocument -DocumentPath $documentPath `
            -SchemaPath (Join-Path $PSScriptRoot 'pi_wave3_evidence.schema.json') | Out-Null
        $markdown = '```json' + [Environment]::NewLine + '{}' + [Environment]::NewLine + '```'
        [System.IO.File]::WriteAllText($documentPath, $markdown, [System.Text.UTF8Encoding]::new($false))
        $caught = $false
        try {
            Test-Wave3JsonDocument -DocumentPath $documentPath `
                -SchemaPath (Join-Path $PSScriptRoot 'pi_wave3_evidence.schema.json') | Out-Null
        }
        catch { $caught = $true }
        Assert-True $caught 'Markdown-wrapped JSON should fail validation'
    }

    Invoke-Test 'evidence claims require unique IDs and exact admitted hashes' {
        $manifest = [pscustomobject]@{
            declared_inputs = @([pscustomobject]@{
                path = 'fixture.bin'
                sha256 = ('a' * 64)
            })
        }
        $document = [pscustomobject]@{
            worker_id = 'E01'
            claims = @([pscustomobject]@{
                fact_id = 'E01.fact.one'
                source_path = 'fixture.bin'
                source_sha256 = ('a' * 64)
            })
        }
        Assert-Wave3EvidenceSources -Document $document -ContextManifest $manifest | Out-Null

        $wrongHash = Copy-JsonObject $document
        $wrongHash.claims[0].source_sha256 = ('b' * 64)
        $caught = $false
        try { Assert-Wave3EvidenceSources -Document $wrongHash -ContextManifest $manifest | Out-Null }
        catch { $caught = $true }
        Assert-True $caught 'Wrong source hash should fail validation'

        $undeclared = Copy-JsonObject $document
        $undeclared.claims[0].source_path = 'other.bin'
        $caught = $false
        try { Assert-Wave3EvidenceSources -Document $undeclared -ContextManifest $manifest | Out-Null }
        catch { $caught = $true }
        Assert-True $caught 'Undeclared evidence source should fail validation'

        $absolute = Copy-JsonObject $document
        $absolute.claims[0].source_path = 'X:/decompilation/fixture.bin'
        $caught = $false
        try { Assert-Wave3EvidenceSources -Document $absolute -ContextManifest $manifest | Out-Null }
        catch { $caught = $true }
        Assert-True $caught 'Absolute evidence source should fail validation'

        $wrongPrefix = Copy-JsonObject $document
        $wrongPrefix.claims[0].fact_id = 'fact.one'
        $caught = $false
        try { Assert-Wave3EvidenceSources -Document $wrongPrefix -ContextManifest $manifest | Out-Null }
        catch { $caught = $true }
        Assert-True $caught 'Non-worker-prefixed fact ID should fail validation'

        $duplicate = Copy-JsonObject $document
        $duplicate.claims = @($duplicate.claims[0], $duplicate.claims[0])
        $caught = $false
        try { Assert-Wave3EvidenceSources -Document $duplicate -ContextManifest $manifest | Out-Null }
        catch { $caught = $true }
        Assert-True $caught 'Duplicate fact IDs should fail validation'
    }
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

Write-Output "passed=$script:Passed failed=$script:Failed"
if ($script:Failed) { exit 1 }
