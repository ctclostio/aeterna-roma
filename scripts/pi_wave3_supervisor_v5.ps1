#requires -Version 7.4

[CmdletBinding()]
param(
    [ValidateSet('StartStage', 'Status', 'Validate', 'Collect', 'Stop', 'Watchdog')]
    [string]$Action = 'Status',
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$')]
    [string]$RunId = '20260824-wave3',
    [ValidateSet('E', 'O', 'I', 'R', 'G')]
    [string]$Stage,
    [string]$ConfigPath,
    [string]$PiCommand
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $PSScriptRoot 'pi_wave3_startup_abi_v6.json'
}
$configSchemaPath = Join-Path $PSScriptRoot 'pi_wave3_config_v3.schema.json'
$commonModulePath = Join-Path $PSScriptRoot 'pi_wave3_common_v2.psm1'
$workerScript = Join-Path $PSScriptRoot 'pi_swarm_worker_v5.ps1'
Import-Module -Name $commonModulePath -Force

$runRoot = Join-Path $repositoryRoot (Join-Path 'out\pi-swarm' $RunId)
$statePath = Join-Path $runRoot 'state.json'
$lockPath = Join-Path $runRoot '.supervisor.lock'
$stageSnapshotRoot = Join-Path $runRoot 'stage-config'
$promptRoot = Join-Path $runRoot 'prompts'
$reportRoot = Join-Path $runRoot 'reports'
$sessionRoot = Join-Path $runRoot 'sessions'
$workspaceRoot = Join-Path $runRoot 'workspaces'
$contextRoot = Join-Path $runRoot 'context'
$manifestRoot = Join-Path $runRoot 'manifests'
$watchdogRoot = Join-Path $runRoot 'watchdog'
$watchdogPollMilliseconds = 2000
$watchdogLockStarvationSeconds = 10
$watchdogHeartbeatMaxAgeSeconds = 10
$watchdogMetricsStaleGraceSeconds = 10
$watchdogStartupHandshakeSeconds = 10
$workerIdentitySettlementMilliseconds = 250

function Get-UtcNowText {
    return [datetimeoffset]::UtcNow.ToString('o')
}

function Get-RunRelativePath([string]$Path) {
    return [System.IO.Path]::GetRelativePath($runRoot, $Path).Replace('\', '/')
}

function Resolve-WorkerSessionDirectory(
    [string]$StageSessionRoot,
    [string]$WorkerId
) {
    if ($WorkerId -notmatch '^[EOIRG][0-9]{2}$') {
        throw "Invalid worker ID for session isolation: $WorkerId"
    }
    return Resolve-Wave3ContainedPath -Root $StageSessionRoot `
        -RelativePath $WorkerId
}

function Read-State {
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        throw "Wave-3 state does not exist: $statePath"
    }
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -Depth 100
    Assert-Wave3FrozenHarness -State $state -SupervisorPath $PSCommandPath `
        -CommonModulePath $commonModulePath -WorkerScriptPath $workerScript | Out-Null
    return $state
}

function Write-State($State, $Validation) {
    Assert-Wave3FrozenHarness -State $State -SupervisorPath $PSCommandPath `
        -CommonModulePath $commonModulePath -WorkerScriptPath $workerScript | Out-Null
    Assert-StateMatchesConfig $State $Validation
    $State.updated_utc = Get-UtcNowText
    Write-Wave3AtomicJson -LiteralPath $statePath -Value $State
}

function Open-RunLock {
    [System.IO.Directory]::CreateDirectory($runRoot) | Out-Null
    try {
        return [System.IO.FileStream]::new(
            $lockPath,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None
        )
    }
    catch {
        throw "Another wave-3 supervisor action owns the run lock: $lockPath"
    }
}

function Get-ValidatedConfig {
    return Read-Wave3Config -ConfigPath $ConfigPath -SchemaPath $configSchemaPath `
        -RepositoryRoot $repositoryRoot
}

function Assert-StateMatchesConfig($State, $Validation) {
    Assert-Wave3FrozenState -State $State -Validation $Validation `
        -ExpectedRunId $RunId -ExpectedRunRoot $runRoot `
        -ExpectedRepositoryRoot $repositoryRoot -ConfigSchemaPath $configSchemaPath | Out-Null
}

function New-InitialState($Validation) {
    $config = $Validation.config
    $stageRecords = foreach ($stageConfig in $config.stages) {
        [ordered]@{
            id = [string]$stageConfig.id
            depends_on = @($stageConfig.depends_on | ForEach-Object { [string]$_ })
            status = 'pending'
            started_utc = $null
            stopped_utc = $null
            stop_reason = $null
            validated_utc = $null
            watchdog_pid = $null
            watchdog_start_utc = $null
            watchdog_stopped_utc = $null
            watchdog_expected_executable_path = $null
            watchdog_command_markers = @()
            watchdog_heartbeat_file = $null
            watchdog_error_file = $null
            watchdog_exit_file = $null
            stage_config_file = $null
            stage_config_sha256 = $null
            manifest_file = $null
            manifest_sha256 = $null
        }
    }
    $workerRecords = foreach ($workerConfig in $config.workers) {
        [ordered]@{
            id = [string]$workerConfig.id
            stage = [string]$workerConfig.stage
            role = [string]$workerConfig.role
            status = 'pending'
            attempt = 0
            pid = $null
            process_start_utc = $null
            process_exit_utc = $null
            expected_executable_path = $null
            command_line_markers = @()
            started_utc = $null
            stopped_utc = $null
            stop_reason = $null
            budget_exceeded = $null
            artifact_checkpoint_satisfied = $null
            artifact_checkpoint_failed = $null
            last_metrics = $null
            watchdog_checked_utc = $null
            metrics_stale_since_utc = $null
            metrics_stale_error = $null
            session_id = $null
            session_directory = $null
            context_manifest = $null
            context_manifest_sha256 = $null
            workspace_dir = $null
            prompt_file = $null
            output_file = $null
            error_file = $null
            exit_file = $null
            launch_receipt_file = $null
            budget = $workerConfig.budget
        }
    }
    return [ordered]@{
        state_version = 3
        run_id = $RunId
        repository_root = $repositoryRoot
        run_root = $runRoot
        model = [string]$config.model
        config_path = $Validation.config_path
        config_sha256 = $Validation.config_sha256
        config_schema_sha256 = Get-Wave3Sha256 -LiteralPath $configSchemaPath
        supervisor_sha256 = Get-Wave3Sha256 -LiteralPath $PSCommandPath
        common_module_sha256 = Get-Wave3Sha256 -LiteralPath $commonModulePath
        worker_script_sha256 = Get-Wave3Sha256 -LiteralPath $workerScript
        total_token_budget = [int64]$Validation.total_token_budget
        actual_token_ceiling = [int64]$Validation.total_token_budget
        created_utc = Get-UtcNowText
        updated_utc = Get-UtcNowText
        stages = @($stageRecords)
        workers = @($workerRecords)
    }
}

function Get-StateStage($State, [string]$StageId) {
    $matches = @($State.stages | Where-Object id -eq $StageId)
    if ($matches.Count -ne 1) { throw "State has no unique stage $StageId" }
    return $matches[0]
}

function Get-StateWorker($State, [string]$WorkerId) {
    $matches = @($State.workers | Where-Object id -eq $WorkerId)
    if ($matches.Count -ne 1) { throw "State has no unique worker $WorkerId" }
    return $matches[0]
}

function Get-WorkerProcessIdentity($WorkerState) {
    if ($null -eq $WorkerState.pid -or
        [string]::IsNullOrWhiteSpace([string]$WorkerState.process_start_utc) -or
        [string]::IsNullOrWhiteSpace([string]$WorkerState.expected_executable_path) -or
        -not @($WorkerState.command_line_markers).Count) {
        return [pscustomobject]@{ exists = $false; trusted = $false; reason = 'identity_state_incomplete' }
    }
    return Get-Wave3LiveProcessIdentity -ProcessId ([int]$WorkerState.pid) `
        -ExpectedStartUtc ([string]$WorkerState.process_start_utc) `
        -ExpectedExecutablePath ([string]$WorkerState.expected_executable_path) `
        -RequiredCommandLineMarkers @($WorkerState.command_line_markers | ForEach-Object { [string]$_ })
}

function Test-WorkerProcessIdentity($WorkerState) {
    return [bool](Get-WorkerProcessIdentity $WorkerState).trusted
}

function Get-WatchdogProcessIdentity($StageState) {
    if ($null -eq $StageState.watchdog_pid -or
        [string]::IsNullOrWhiteSpace([string]$StageState.watchdog_start_utc) -or
        [string]::IsNullOrWhiteSpace([string]$StageState.watchdog_expected_executable_path) -or
        -not @($StageState.watchdog_command_markers).Count) {
        return [pscustomobject]@{ exists = $false; trusted = $false; reason = 'watchdog_identity_state_incomplete' }
    }
    return Get-Wave3LiveProcessIdentity -ProcessId ([int]$StageState.watchdog_pid) `
        -ExpectedStartUtc ([string]$StageState.watchdog_start_utc) `
        -ExpectedExecutablePath ([string]$StageState.watchdog_expected_executable_path) `
        -RequiredCommandLineMarkers @($StageState.watchdog_command_markers | ForEach-Object { [string]$_ })
}

function Assert-WatchdogInvocationOwner($StageState, [int]$InvocationPid) {
    if ([string]$StageState.status -notin @('launching', 'running')) {
        throw "watchdog_stage_not_active:stage=$($StageState.id);status=$($StageState.status)"
    }
    $expectedPid = if ($null -eq $StageState.watchdog_pid) {
        '<unset>'
    }
    else { [string][int]$StageState.watchdog_pid }
    if ($null -eq $StageState.watchdog_pid -or
        [int]$StageState.watchdog_pid -ne $InvocationPid) {
        throw "watchdog_invocation_pid_mismatch:stage=$($StageState.id);expected=$expectedPid;actual=$InvocationPid"
    }
}

function Get-LiveWorkerStatus($WorkerState) {
    if ([string]$WorkerState.status -eq 'validated') { return 'validated' }
    if ([string]$WorkerState.status -eq 'stopped') { return 'stopped' }
    if ([string]$WorkerState.status -eq 'budget_exceeded') { return 'budget_exceeded' }
    if ([string]$WorkerState.status -eq 'failed') { return 'failed' }
    if ([string]$WorkerState.status -eq 'completed') { return 'completed' }
    if (-not [string]::IsNullOrWhiteSpace([string]$WorkerState.exit_file) -and
        (Test-Path -LiteralPath $WorkerState.exit_file -PathType Leaf)) {
        $text = (Get-Content -LiteralPath $WorkerState.exit_file -Raw).Trim()
        $exitCode = 0
        if (-not [int]::TryParse($text, [ref]$exitCode)) { return 'failed' }
        if ($exitCode -eq 0) { return 'completed' }
        return 'failed'
    }
    $identity = Get-WorkerProcessIdentity $WorkerState
    if ($identity.trusted) { return 'running' }
    if ($identity.exists) { return 'identity_mismatch' }
    if ([string]$WorkerState.status -eq 'pending') { return 'pending' }
    if ([string]$WorkerState.status -eq 'launch_failed') { return 'launch_failed' }
    return 'lost'
}

function Get-WorkerProcessLifetime($WorkerState, [string]$LiveStatus, [datetimeoffset]$NowUtc) {
    if ([string]::IsNullOrWhiteSpace([string]$WorkerState.process_start_utc)) {
        throw "Worker $($WorkerState.id) has no process_start_utc"
    }
    $completed = $LiveStatus -in @('completed', 'failed')
    $exitLastWrite = $null
    if ($completed) {
        if ([string]::IsNullOrWhiteSpace([string]$WorkerState.exit_file) -or
            -not (Test-Path -LiteralPath $WorkerState.exit_file -PathType Leaf)) {
            throw "Completed worker $($WorkerState.id) has no exit file"
        }
        $exitLastWrite = [datetimeoffset](Get-Item -LiteralPath $WorkerState.exit_file).LastWriteTimeUtc
    }
    $persistedExit = if ([string]::IsNullOrWhiteSpace([string]$WorkerState.process_exit_utc)) {
        $null
    }
    else { [Nullable[datetimeoffset]]([datetimeoffset]::Parse([string]$WorkerState.process_exit_utc)) }
    return Get-Wave3ProcessLifetime `
        -ProcessStartUtc ([datetimeoffset]::Parse([string]$WorkerState.process_start_utc)) `
        -NowUtc $NowUtc -Completed:$completed `
        -ExitFileLastWriteUtc $exitLastWrite -PersistedExitUtc $persistedExit
}

function Assert-DependencyManifests($State, $StageConfig) {
    $documents = @()
    foreach ($dependencyId in @($StageConfig.depends_on)) {
        $dependency = Get-StateStage $State ([string]$dependencyId)
        if ([string]$dependency.status -ne 'validated') {
            throw "Stage $($StageConfig.id) requires validated stage $dependencyId"
        }
        if (-not (Test-Path -LiteralPath $dependency.manifest_file -PathType Leaf)) {
            throw "Dependency manifest is missing for stage $dependencyId"
        }
        $actualHash = Get-Wave3Sha256 -LiteralPath $dependency.manifest_file
        if ($actualHash -cne [string]$dependency.manifest_sha256) {
            throw "Dependency manifest changed for stage $dependencyId"
        }
        $document = Get-Content -LiteralPath $dependency.manifest_file -Raw |
            ConvertFrom-Json -Depth 100
        if ([string]$document.stage -cne [string]$dependencyId) {
            throw "Dependency manifest identity mismatch for stage $dependencyId"
        }
        if ([string]$document.run_id -cne $RunId -or
            [string]$document.config_sha256 -cne [string]$State.config_sha256 -or
            [string]$document.stage_config_sha256 -cne [string]$dependency.stage_config_sha256) {
            throw "Dependency manifest provenance mismatch for stage $dependencyId"
        }
        $documents += $document
    }
    return Get-Wave3DependencyArtifactIndex -StageManifests $documents -RunRoot $runRoot
}

function New-ContextManifest($State, $Validation, $WorkerConfig, $StageConfig, [string]$StageConfigHash) {
    $inputs = foreach ($relativePath in @($WorkerConfig.context_files)) {
        $absolutePath = Resolve-Wave3ContainedPath -Root $repositoryRoot `
            -RelativePath ([string]$relativePath) -MustExist -PathType Leaf
        $item = Get-Item -LiteralPath $absolutePath
        [ordered]@{
            path = ([string]$relativePath).Replace('\', '/')
            sha256 = Get-Wave3Sha256 -LiteralPath $absolutePath
            byte_count = [int64]$item.Length
        }
    }
    $schemas = foreach ($requiredOutput in @($WorkerConfig.required_outputs)) {
        if ($null -eq $requiredOutput.schema) { continue }
        $absolutePath = Resolve-Wave3ContainedPath -Root $repositoryRoot `
            -RelativePath ([string]$requiredOutput.schema) -MustExist -PathType Leaf
        $item = Get-Item -LiteralPath $absolutePath
        [ordered]@{
            path = ([string]$requiredOutput.schema).Replace('\', '/')
            sha256 = Get-Wave3Sha256 -LiteralPath $absolutePath
            byte_count = [int64]$item.Length
        }
    }
    $dependencies = foreach ($dependencyId in @($StageConfig.depends_on)) {
        $dependency = Get-StateStage $State ([string]$dependencyId)
        [ordered]@{
            stage = [string]$dependencyId
            path = Get-RunRelativePath ([string]$dependency.manifest_file)
            sha256 = [string]$dependency.manifest_sha256
        }
    }
    $manifest = [ordered]@{
        schema_version = 1
        run_id = $RunId
        worker_id = [string]$WorkerConfig.id
        stage = [string]$WorkerConfig.stage
        config_sha256 = [string]$Validation.config_sha256
        stage_config_sha256 = $StageConfigHash
        generated_utc = Get-UtcNowText
        declared_inputs = @($inputs)
        validation_schemas = @($schemas)
        dependency_stage_manifests = @($dependencies)
    }
    $manifestPath = Join-Path $contextRoot (Join-Path ([string]$WorkerConfig.stage) `
        (([string]$WorkerConfig.id) + '.json'))
    Write-Wave3AtomicJson -LiteralPath $manifestPath -Value $manifest
    return [pscustomobject]@{
        path = $manifestPath
        sha256 = Get-Wave3Sha256 -LiteralPath $manifestPath
    }
}

function Assert-ContextManifestCurrent($WorkerState) {
    if (-not (Test-Path -LiteralPath $WorkerState.context_manifest -PathType Leaf)) {
        throw "Context manifest is missing for worker $($WorkerState.id)"
    }
    if ((Get-Wave3Sha256 -LiteralPath $WorkerState.context_manifest) -cne
        [string]$WorkerState.context_manifest_sha256) {
        throw "Context manifest changed for worker $($WorkerState.id)"
    }
    $manifest = Get-Content -LiteralPath $WorkerState.context_manifest -Raw | ConvertFrom-Json -Depth 100
    foreach ($entry in @($manifest.declared_inputs) + @($manifest.validation_schemas)) {
        $absolutePath = Resolve-Wave3ContainedPath -Root $repositoryRoot `
            -RelativePath ([string]$entry.path) -MustExist -PathType Leaf
        if ((Get-Wave3Sha256 -LiteralPath $absolutePath) -cne [string]$entry.sha256) {
            throw "Frozen context input changed for worker $($WorkerState.id): $($entry.path)"
        }
        if ((Get-Item -LiteralPath $absolutePath).Length -ne [int64]$entry.byte_count) {
            throw "Frozen context input size changed for worker $($WorkerState.id): $($entry.path)"
        }
    }
    foreach ($dependency in @($manifest.dependency_stage_manifests)) {
        $absolutePath = Resolve-Wave3ContainedPath -Root $runRoot `
            -RelativePath ([string]$dependency.path) -MustExist -PathType Leaf
        if ((Get-Wave3Sha256 -LiteralPath $absolutePath) -cne [string]$dependency.sha256) {
            throw "Dependency stage manifest changed for worker $($WorkerState.id): $($dependency.stage)"
        }
    }
    return $manifest
}

function Get-WorkerPrompt($Config, $WorkerConfig, $WorkerState) {
    $requiredLines = foreach ($requiredOutput in @($WorkerConfig.required_outputs)) {
        $schemaAbsolute = if ($null -ne $requiredOutput.schema) {
            Resolve-Wave3ContainedPath -Root $repositoryRoot `
                -RelativePath ([string]$requiredOutput.schema) -MustExist -PathType Leaf
        }
        else { 'none' }
        "- $($requiredOutput.name): $($WorkerState.workspace_dir)\$($requiredOutput.path); format=$($requiredOutput.format); schema=$schemaAbsolute; max_bytes=$($requiredOutput.max_bytes)"
    }
    $writePolicy = @"
Pi starts in your isolated writable directory:
$($WorkerState.workspace_dir)

The repository source root is:
$repositoryRoot

Treat the repository source root as read-only. Use absolute paths below that root
for admitted source reads, and do not create, edit, delete, rename, or format any
repository source file. Do not write anywhere except your isolated writable
directory. Put every required artifact below that directory.

The workspace artifact is the deliverable and transport; final chat is not. Before
finishing, write the artifact, re-read it from disk, parse it as exact JSON, and
validate it against the absolute schema path shown below (Test-Json -SchemaFile is
available through PowerShell when that tool is allowed). Correct the file until it
validates. In final chat, report only that the on-disk artifact is ready; do not
paste the artifact there.
"@

    $reviewText = if (@($WorkerConfig.review_targets).Count) {
        "Review targets: $(@($WorkerConfig.review_targets) -join ', ')"
    }
    else { 'Review targets: none' }
    $requirementText = if ($null -ne $Config.PSObject.Properties['allowed_requirement_ids']) {
        $coverageRule = switch ([string]$WorkerConfig.stage) {
            'O' { 'The validated O-stage union must cover every listed ID.' }
            'I' { 'submission.json requirement_ids must contain exactly the complete listed set.' }
            'R' { 'Every finding must cite only a listed ID; zero-findings passes remain valid.' }
            'G' { 'integration_manifest.json requirement_ids must contain exactly the complete listed set.' }
            default { 'These IDs do not replace evidence fact_id values.' }
        }
        "Canonical requirement IDs: $(@($Config.allowed_requirement_ids) -join ', '). $coverageRule"
    }
    else { 'Canonical requirement IDs: not configured for this wave' }
    $artifactCheckpointText = if (
        $null -ne $WorkerConfig.budget.PSObject.Properties['artifact_checkpoint_tool_calls']
    ) {
        "at least one safe, nonempty required workspace artifact must be externally observed no later than completed tool result $($WorkerConfig.budget.artifact_checkpoint_tool_calls)"
    }
    else { 'disabled' }

    $stageGuidance = switch ([string]$WorkerConfig.stage) {
        'E' {
@"
For E-stage claims, copy source_path and source_sha256 exactly from declared_inputs
in the frozen context manifest. source_path is the repository-relative manifest
string, never the absolute path used to read that file; an X:/... or other absolute
source_path will fail admission. Never cite an undeclared or transitively discovered
file. Prefix every fact_id with your exact worker ID and a dot (for example,
$($WorkerConfig.id).fact-name), and use each fact_id exactly once. Before finishing,
compare every distinct source_path against declared_inputs.path
with exact case and separators. The blockers array is only for a contradiction or missing admitted evidence
that makes the next stage unsafe; files that implementation is expected to create
are planned work, not blockers. Prefer 6-12 claims and never exceed 16; blockers
may never exceed 8. Each claim must be atomic and supported entirely by its single
source_path/source_sha256; split multi-source facts. The conclusion may summarize
identified claims but may introduce no new facts. Use only reproducible read/grep
recipes from your allowed tools, never PowerShell commands or pseudo-commands.
"@
        }
        'O' {
$oracleRoleGuidance = switch ([string]$WorkerConfig.id) {
    'O02' {
@"
For O02, the 400-byte body is the half-open interval [0x100ed3c0,0x100ed550):
the last decoded byte is 0x100ed54f and 0x100ed550 is end-exclusive. Do not
invent a count of internal call targets; derive every relative-flow fact from
the complete decode. T6 must authenticate the exact pristine per-row ESP-delta
vector as well as guest-coordinate opacity, and its one deterministic mutation
changes that complete vector to zeroes so the same test necessarily fails.
For the final C3-to-C20400 mutation, state that the disposable byte sequence
grows from one byte to three and require fail-closed size/coverage and return-
contract rejection rather than pretending it is a same-width replacement.
"@
    }
    'O03' {
@"
For O03, the empty prefix ends at exactly 0x100ef347 end-exclusive; do not say
the stop coordinate is below that value. Exclude raw admitted-slice bytes at
and after that coordinate while still allowing explicit exclusion metadata to
cite the allocator call at 0x100ef354. The authenticated 56-byte parent window
is [0x100ed3f4,0x100ed42c), not an interval ending at 0x100ed42b. Keep the
canonical-index authority restraint entirely in its assigned exact marker;
do not restate index/raw-offset/raw-hash relationships in nearby prose. Keep
the test-only 0x100f1c10 restraint entirely in its assigned exact marker and
do not narrate a native delegation relationship involving that address.
"@
    }
    'O04' {
@"
For O04, include every assigned marker, especially PROVENANCE_SCOPE for T1 and
BUILD_TESTING_CHECK for T7. T2's bad base must be represented only as a fixed
mutated data value, not narrated as a valid rel32 computation. T4's bad EBX
classification must likewise use a neutral fixed mutant value at its locus;
do not assert that classification as prose. Recheck that T8 has no key beyond
test_id, requirement_ids, description, procedure, expected, and mutant_ids.
"@
    }
    default { '' }
}
@"
For O-stage output, write exactly 8 tests and exactly 8 mutants. Prefix every ID
with your worker ID. The only permitted IDs are exactly $($WorkerConfig.id).T1 through
$($WorkerConfig.id).T8 and $($WorkerConfig.id).M1 through $($WorkerConfig.id).M8:
use a dot, no zero padding, no descriptive suffix, and no alternate separator. Pair
them one-to-one: test N names only mutant N, and mutant N names only test N as its
expected killer. Set blockers to [] unless admitted sources
logically contradict the contract; tool limits and planned work are not blockers.
The document keys are exactly worker_id, stage, tests, mutants, and blockers.
Every test has exactly test_id, requirement_ids, description, procedure, expected,
and mutant_ids. Every mutant has exactly mutant_id, critical, description, and
expected_killer_ids. The schema permits no extra, note, helper, or self-check key.

Place each assigned KEY=VALUE marker exactly once as an isolated token followed
by whitespace or one sentence-final period. Never append a colon or another
marker character, never emit a variant, and never use any unassigned KEY=VALUE
token. Let the exact marker carry its negative/authority restraint instead of
restating that restraint in nearby prose as though the forbidden condition were
true.

Each paired procedure must name one executable mutation locus as either an exact
disposable relative file plus byte offset/length or an exact JSON Pointer. Give
the exact pristine before value and exact mutated after value, state that every
other byte/field is unchanged, run the unchanged checker, require pristine PASS,
then require the paired mutant FAIL. "Mutate verifier outputs", "change the
logic", families of choices, and unnamed copies are not executable loci. When a
known-bad after-state would read like an accepted technical claim, encode it as
a neutral exact data token at the fixed locus and let the exact mutant description
define its meaning; do not assert the bad state in narrative prose.

Avoid backslash escapes in prose and write the words "NUL code unit" instead of
\0. Read the schema before writing and manually check exact JSON because PowerShell
is intentionally unavailable. Write oracle.json by tool call 10, re-read it
exactly once, report only readiness, and finish no later than tool call 12.

$oracleRoleGuidance
"@
        }
        'I' {
@"
For I-stage output, write every required complete source file before submission.json.
The files array must enumerate the exact relative path, SHA-256, and byte count of
each payload deliverable and must exclude submission.json itself. Start writing
source no later than tool call 8. Complete source, build, tests, and cleanup by tool
call 18 before hashing the final files. Write and re-read submission.json by tool
call 20, then finish no later than tool call 22. Keep candidate-owned tests separate
from acceptance claims. Planning or optional exploration never justifies missing
these earlier delivery checkpoints.
"@
        }
        'R' {
@"
For R-stage output, review exactly the assigned candidates and keep executable
reproducers as self-contained command strings in findings.json. Remove transient
fixtures and binaries before finishing: the workspace must persist only findings.json.
Each finding's candidate_sha256 must be the admitted dependency-artifact hash of that
candidate's submission.json. Each review permits at most 32 tests and 16 findings.
Write findings.json by tool call 18, re-read it by tool call 20, and finish immediately.
"@
        }
        'G' {
@"
For G-stage output, validate every selected component hash and enumerate every
complete payload file with exact relative path, SHA-256, and byte count; exclude
integration_manifest.json itself. Do not treat candidate-owned tests or another
integrator as the acceptance oracle.
Select an I-stage candidate only when both R-stage reviewers configured for that
candidate report verdict=pass for its exact authenticated submission hash.
Use milestone $(if ($null -ne $Config.PSObject.Properties['milestone']) { [string]$Config.milestone } else { 'entry-policy-dynamic-probe-v1' }) exactly. Select at least one artifact
from each of E, O, I, and R; list every dependency worker actually used at most once.
Every reported test exit_code must be 0 and unresolved_decisions must be []. Complete
source, build, tests, and cleanup by tool call 22 before hashing final files. Write
integration_manifest.json by tool call 24, re-read it by tool call 26, and finish no
later than tool call 28. Begin concrete component selection and source writing no
later than tool call 10.
"@
        }
    }

    return @"
$($Config.prompt_preamble)

You are Pi wave-3 worker $($WorkerConfig.id), role $($WorkerConfig.role), stage $($WorkerConfig.stage).
This is a fresh, isolated session. Do not continue or rely on any earlier Pi session.

Execution envelope:
- Model: $($Config.model)
- Thinking: $($WorkerConfig.thinking)
- Tools: $(@($WorkerConfig.tools) -join ',')
- Token budget: $($WorkerConfig.budget.max_tokens)
- Wall-time budget: $($WorkerConfig.budget.timeout_seconds) seconds
- Tool-call budget: $($WorkerConfig.budget.max_tool_calls)
- Externally enforced artifact checkpoint: $artifactCheckpointText
- Captured-output budget: $($WorkerConfig.budget.max_output_bytes) bytes
- Frozen context manifest: $($WorkerState.context_manifest)
- $reviewText
- $requirementText
- Frozen milestone: $(if ($null -ne $Config.PSObject.Properties['milestone']) { [string]$Config.milestone } else { 'not configured for this wave' })

Read the frozen context manifest first. Treat only its hash-pinned inputs and
dependency manifests as admitted evidence. Distinguish direct facts from
inference. Stop early enough to produce a valid deliverable within every budget.

Batch independent reads into the same assistant turn. Follow the stage-specific
finalization deadline, re-read the finished artifact only once, and do not spend
post-artifact turns on optional exploration.

For an enabled artifact checkpoint, a toolCall declaration is not a completion.
The supervisor counts its matching toolResult receipt. It may record a safe,
nonempty artifact early or at an exact, quiescent deadline. If the first safe
observation arrives after the configured completed-result count, the checkpoint
fails conservatively; a later write cannot cure it. Write the checkpoint artifact
early enough for external observation, and never rely on an in-flight call at the
deadline.

$writePolicy
Required outputs:
$($requiredLines -join "`n")

Task:
$($WorkerConfig.task)

Final stage-specific requirements (these supersede any looser deadline in the
task text above):
$stageGuidance
"@
}

function Start-WorkerProcess($WorkerConfig, $WorkerState, [string]$Model) {
    $resolvedPi = if ([string]::IsNullOrWhiteSpace($PiCommand)) {
        (Get-Command pi.cmd -ErrorAction Stop).Source
    }
    else {
        (Get-Command $PiCommand -ErrorAction Stop).Source
    }
    $pwsh = (Get-Command pwsh.exe -ErrorAction Stop).Source
    if (-not [System.IO.Path]::GetFullPath($pwsh).Equals(
        [System.IO.Path]::GetFullPath([string]$WorkerState.expected_executable_path),
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Worker launch executable changed after identity was frozen"
    }
    $arguments = @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $workerScript,
        '-PiCommand', $resolvedPi,
        '-Model', $Model,
        '-RepositoryRoot', $repositoryRoot,
        '-TaskFile', $WorkerState.prompt_file,
        '-OutputFile', $WorkerState.output_file,
        '-ErrorFile', $WorkerState.error_file,
        '-ExitFile', $WorkerState.exit_file,
        '-LaunchReceiptFile', $WorkerState.launch_receipt_file,
        '-SessionDirectory', $WorkerState.session_directory,
        '-SessionId', $WorkerState.session_id,
        '-WorkerName', $WorkerState.session_id,
        '-ToolAllowlist', (@($WorkerConfig.tools) -join ','),
        '-ThinkingLevel', ([string]$WorkerConfig.thinking)
    )
    if (-not [string]::IsNullOrWhiteSpace([string]$WorkerState.workspace_dir)) {
        $arguments += @('-WorkingDirectory', [string]$WorkerState.workspace_dir)
    }
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $pwsh
    $startInfo.WorkingDirectory = if (
        -not [string]::IsNullOrWhiteSpace([string]$WorkerState.workspace_dir)
    ) { [string]$WorkerState.workspace_dir } else { $repositoryRoot }
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    foreach ($argument in $arguments) { $startInfo.ArgumentList.Add([string]$argument) }
    $process = [System.Diagnostics.Process]::Start($startInfo)
    if ($null -eq $process) { throw "Failed to start worker $($WorkerConfig.id)" }
    return $process
}

function Set-WorkerLaunchFailure(
    $WorkerState,
    [string]$Reason,
    [string]$FailedUtc
) {
    $WorkerState.status = 'launch_failed'
    $WorkerState.stopped_utc = $FailedUtc
    $WorkerState.stop_reason = "worker_launch_failed:$Reason"
    $WorkerState.budget_exceeded = $null
}

function Get-WorkspaceInventory([string]$WorkspacePath) {
    Assert-Wave3SafeDirectoryTree -LiteralPath $WorkspacePath -BoundaryPath $runRoot | Out-Null
    $items = @(Get-ChildItem -LiteralPath $WorkspacePath -Recurse -Force -ErrorAction Stop)
    $reparse = @($items | Where-Object {
        ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    })
    if ($reparse.Count) {
        throw "Workspace contains a reparse point: $($reparse[0].FullName)"
    }
    return @($items | Where-Object { $_ -is [System.IO.FileInfo] } | Sort-Object FullName | ForEach-Object {
        [ordered]@{
            path = [System.IO.Path]::GetRelativePath($WorkspacePath, $_.FullName).Replace('\', '/')
            sha256 = Get-Wave3Sha256 -LiteralPath $_.FullName
            byte_count = [int64]$_.Length
        }
    })
}

function Assert-DeclaredFileManifest($Document, [string]$WorkspacePath, [string]$WorkerId) {
    if ($null -eq $Document.PSObject.Properties['files']) { return }
    $declaredPaths = @($Document.files | ForEach-Object {
        ([string]$_.path).Replace('\', '/')
    })
    if (@($declaredPaths | Sort-Object -Unique).Count -ne $declaredPaths.Count) {
        throw "Worker $WorkerId declares duplicate file paths"
    }
    foreach ($declaredFile in @($Document.files)) {
        $absolutePath = Resolve-Wave3ContainedPath -Root $WorkspacePath `
            -RelativePath ([string]$declaredFile.path) -MustExist -PathType Leaf
        $actualHash = Get-Wave3Sha256 -LiteralPath $absolutePath
        $actualBytes = (Get-Item -LiteralPath $absolutePath).Length
        if ($actualHash -cne [string]$declaredFile.sha256 -or
            $actualBytes -ne [int64]$declaredFile.byte_count) {
            throw "Worker $WorkerId declared a false hash or size for $($declaredFile.path)"
        }
    }
}

function Resolve-WorkerOutputs($WorkerConfig, $WorkerState) {
    $artifacts = @()
    $documents = @()
    if ((Get-Item -LiteralPath $WorkerState.output_file).Length -gt
        [int64]$WorkerConfig.budget.max_output_bytes) {
        throw "Worker $($WorkerConfig.id) exceeded its captured-output budget"
    }
    foreach ($requiredOutput in @($WorkerConfig.required_outputs)) {
        $artifactPath = if ($requiredOutput.source -eq 'report') {
            [string]$WorkerState.output_file
        }
        else {
            Resolve-Wave3ContainedPath -Root ([string]$WorkerState.workspace_dir) `
                -RelativePath ([string]$requiredOutput.path) -MustExist -PathType Leaf
        }
        $item = Get-Item -LiteralPath $artifactPath -Force
        Assert-Wave3ArtifactFile -LiteralPath $artifactPath | Out-Null
        if ($item.Length -gt [int64]$requiredOutput.max_bytes) {
            throw "Required output $($requiredOutput.name) exceeds max_bytes"
        }

        $document = $null
        if ($requiredOutput.format -eq 'json') {
            $schemaPath = Resolve-Wave3ContainedPath -Root $repositoryRoot `
                -RelativePath ([string]$requiredOutput.schema) -MustExist -PathType Leaf
            Test-Wave3JsonDocument -DocumentPath $artifactPath -SchemaPath $schemaPath | Out-Null
            $document = Get-Content -LiteralPath $artifactPath -Raw | ConvertFrom-Json -Depth 100
            if ($null -ne $document.PSObject.Properties['worker_id'] -and
                [string]$document.worker_id -cne [string]$WorkerConfig.id) {
                throw "Output identity mismatch for worker $($WorkerConfig.id)"
            }
            if ($null -ne $document.PSObject.Properties['stage'] -and
                [string]$document.stage -cne [string]$WorkerConfig.stage) {
                throw "Output stage mismatch for worker $($WorkerConfig.id)"
            }
            if ($requiredOutput.source -eq 'workspace') {
                Assert-DeclaredFileManifest -Document $document `
                    -WorkspacePath ([string]$WorkerState.workspace_dir) -WorkerId ([string]$WorkerConfig.id)
            }
            $documents += [pscustomobject]@{ name = [string]$requiredOutput.name; value = $document }
        }

        $artifacts += [ordered]@{
            name = [string]$requiredOutput.name
            source = [string]$requiredOutput.source
            path = Get-RunRelativePath $artifactPath
            sha256 = Get-Wave3Sha256 -LiteralPath $artifactPath
            byte_count = [int64]$item.Length
            format = [string]$requiredOutput.format
            schema = if ($null -ne $requiredOutput.schema) { [string]$requiredOutput.schema } else { $null }
        }
    }
    $inventory = @(Get-WorkspaceInventory ([string]$WorkerState.workspace_dir))
    if ($null -ne $WorkerConfig.PSObject.Properties['expected_workspace_files']) {
        Assert-Wave3ExactWorkspacePathSet -Inventory $inventory `
            -ExpectedPaths @($WorkerConfig.expected_workspace_files | ForEach-Object {
                ([string]$_).Replace('\', '/')
            }) -WorkerId ([string]$WorkerConfig.id) | Out-Null
    }
    if ([string]$WorkerConfig.stage -in @('E', 'O', 'R')) {
        $expectedPath = ([string]$WorkerConfig.required_outputs[0].path).Replace('\', '/')
        Assert-Wave3ExactWorkspaceInventory -Inventory $inventory `
            -ExpectedPath $expectedPath -WorkerId ([string]$WorkerConfig.id) | Out-Null
    }
    elseif ([string]$WorkerConfig.stage -in @('I', 'G')) {
        $declaredPaths = @($documents | ForEach-Object {
            $_.value.files | ForEach-Object { ([string]$_.path).Replace('\', '/') }
        })
        $manifestPaths = @($WorkerConfig.required_outputs | Where-Object source -eq 'workspace' |
            ForEach-Object { ([string]$_.path).Replace('\', '/') })
        Assert-Wave3ExactWorkspacePathSet -Inventory $inventory `
            -ExpectedPaths @($manifestPaths + $declaredPaths) `
            -WorkerId ([string]$WorkerConfig.id) | Out-Null
    }
    return [pscustomobject]@{ artifacts = @($artifacts); documents = @($documents) }
}

function Assert-StageDocuments(
    $StageId,
    $WorkerConfigs,
    $ResolvedOutputs,
    $DependencyArtifactIndex,
    $AllowedRequirementIds,
    $ExpectedMilestone
) {
    $allDocuments = @($ResolvedOutputs | ForEach-Object { $_.documents | ForEach-Object value })
    if ($StageId -in @('E', 'O')) {
        foreach ($document in $allDocuments) {
            if (@($document.blockers).Count) {
                throw "Stage $StageId has unresolved blockers in $($document.worker_id)"
            }
        }
    }
    if ($StageId -eq 'E') {
        $facts = @{}
        foreach ($document in $allDocuments) {
            foreach ($claim in @($document.claims)) {
                $key = [string]$claim.fact_id
                $value = $claim.value | ConvertTo-Json -Depth 100 -Compress
                if ($facts.ContainsKey($key) -and $facts[$key] -cne $value) {
                    throw "Conflicting E-stage values for fact_id $key"
                }
                $facts[$key] = $value
            }
        }
    }
    elseif ($StageId -eq 'O') {
        Assert-Wave3OracleReciprocity -Documents @($allDocuments) | Out-Null
    }
    elseif ($StageId -eq 'R') {
        foreach ($workerConfig in $WorkerConfigs) {
            $workerOutput = @($ResolvedOutputs | Where-Object worker_id -eq $workerConfig.id)[0]
            $document = @($workerOutput.documents | ForEach-Object value)[0]
            $actualTargets = @($document.reviews | ForEach-Object { [string]$_.candidate_id } | Sort-Object)
            $expectedTargets = @($workerConfig.review_targets | ForEach-Object { [string]$_ } | Sort-Object)
            if (($actualTargets -join ',') -cne ($expectedTargets -join ',')) {
                throw "Reviewer $($workerConfig.id) did not report exactly its assigned targets"
            }
        }
        Assert-Wave3DependencyArtifactReferences -StageId R -Documents $allDocuments `
            -ArtifactIndex $DependencyArtifactIndex | Out-Null
    }
    elseif ($StageId -in @('I', 'G')) {
        foreach ($document in $allDocuments) {
            if ($null -ne $document.PSObject.Properties['unresolved_decisions'] -and
                @($document.unresolved_decisions).Count) {
                throw "Worker $($document.worker_id) has unresolved decisions"
            }
            if ($null -ne $document.PSObject.Properties['tests']) {
                $failedTests = @($document.tests | Where-Object { [int]$_.exit_code -ne 0 })
                if ($failedTests.Count) { throw "Worker $($document.worker_id) reports failed tests" }
            }
        }
        if ($StageId -eq 'G' -and $allDocuments.Count -eq 2) {
            $firstMilestone = [string]$allDocuments[0].milestone
            $secondMilestone = [string]$allDocuments[1].milestone
            if ($firstMilestone -cne $secondMilestone) {
                throw 'The two G-stage integrators selected different milestones'
            }
        }
        if ($StageId -eq 'G') {
            Assert-Wave3DependencyArtifactReferences -StageId G -Documents $allDocuments `
                -ArtifactIndex $DependencyArtifactIndex | Out-Null
        }
    }
    if ($null -ne $AllowedRequirementIds -and $StageId -in @('O', 'I', 'R', 'G')) {
        Assert-Wave3RequirementIds -StageId $StageId -Documents $allDocuments `
            -AllowedRequirementIds @($AllowedRequirementIds) | Out-Null
    }
    if ($null -ne $ExpectedMilestone -and $StageId -in @('I', 'G')) {
        Assert-Wave3Milestone -Documents $allDocuments `
            -ExpectedMilestone ([string]$ExpectedMilestone) | Out-Null
    }
}

function Validate-Stage($State, $Validation, [string]$StageId) {
    $config = $Validation.config
    $allowedRequirementIds = if (
        $null -ne $config.PSObject.Properties['allowed_requirement_ids']
    ) { @($config.allowed_requirement_ids) } else { $null }
    $expectedMilestone = if ($null -ne $config.PSObject.Properties['milestone']) {
        [string]$config.milestone
    } else { $null }
    $stageConfig = @($config.stages | Where-Object id -eq $StageId)[0]
    $stageState = Get-StateStage $State $StageId
    $semanticGateConfigs = @(
        if ($null -ne $config.PSObject.Properties['semantic_gates']) {
            $config.semantic_gates | Where-Object stage -ceq $StageId
        }
    )
    if ($semanticGateConfigs.Count -gt 1) {
        throw "Stage $StageId has more than one semantic gate"
    }
    if ([string]$stageState.status -eq 'validated') {
        if (-not (Test-Path -LiteralPath $stageState.manifest_file -PathType Leaf) -or
            (Get-Wave3Sha256 -LiteralPath $stageState.manifest_file) -cne [string]$stageState.manifest_sha256) {
            throw "Validated stage manifest is missing or changed: $StageId"
        }
        if ($semanticGateConfigs.Count -eq 1) {
            $publishedManifest = Get-Content -LiteralPath $stageState.manifest_file -Raw |
                ConvertFrom-Json -Depth 100
            $publishedGate = $publishedManifest.PSObject.Properties['semantic_gate']
            $gateConfig = $semanticGateConfigs[0]
            $requiredReceiptFields = @(
                'stage', 'script', 'script_sha256', 'workspace_root',
                'exit_code', 'stdout', 'stderr'
            )
            $receiptMissingFields = if ($null -eq $publishedGate) {
                @($requiredReceiptFields)
            }
            else {
                @($requiredReceiptFields | Where-Object {
                    $null -eq $publishedGate.Value.PSObject.Properties[$_]
                })
            }
            if ($receiptMissingFields.Count -or
                [int]$publishedGate.Value.exit_code -ne 0 -or
                [string]$publishedGate.Value.stage -cne $StageId -or
                [string]$publishedGate.Value.script -cne [string]$gateConfig.script -or
                [string]$publishedGate.Value.script_sha256 -cne [string]$gateConfig.script_sha256 -or
                [string]$publishedGate.Value.workspace_root -cne [string]$gateConfig.workspace_root) {
                throw "Validated stage manifest has no matching semantic-gate receipt: $StageId"
            }
        }
        return $stageState
    }
    $dependencyArtifactIndex = Assert-DependencyManifests $State $stageConfig
    $workerConfigs = @($config.workers | Where-Object stage -eq $StageId | Sort-Object id)
    $workerEntries = @()
    $resolvedOutputs = @()
    foreach ($workerConfig in $workerConfigs) {
        $workerState = Get-StateWorker $State ([string]$workerConfig.id)
        $liveStatus = Get-LiveWorkerStatus $workerState
        if ($liveStatus -ne 'completed') {
            throw "Cannot validate ${StageId}: worker $($workerConfig.id) is $liveStatus"
        }
        Assert-ContextManifestCurrent $workerState | Out-Null
        $exitCode = [int](Get-Content -LiteralPath $workerState.exit_file -Raw).Trim()
        if ($exitCode -ne 0) { throw "Worker $($workerConfig.id) exit code is $exitCode" }
        $metrics = Get-Wave3SessionMetrics -SessionDirectory $workerState.session_directory `
            -SessionId $workerState.session_id
        if ($metrics.total_tokens -gt [int64]$workerConfig.budget.max_tokens) {
            throw "Worker $($workerConfig.id) exceeded its token budget"
        }
        if ($metrics.tool_calls -gt [int64]$workerConfig.budget.max_tool_calls) {
            throw "Worker $($workerConfig.id) exceeded its tool-call budget"
        }
        if ($null -ne $workerConfig.budget.PSObject.Properties['artifact_checkpoint_tool_calls'] -and
            $null -eq $workerState.artifact_checkpoint_satisfied) {
            throw "Worker $($workerConfig.id) has no persisted artifact-checkpoint receipt"
        }
        $lifetime = Get-WorkerProcessLifetime $workerState $liveStatus ([datetimeoffset]::UtcNow)
        if ([double]$lifetime.elapsed_seconds -gt [int]$workerConfig.budget.timeout_seconds) {
            throw "Worker $($workerConfig.id) exceeded its wall-time budget"
        }

        $outputs = Resolve-WorkerOutputs $workerConfig $workerState
        if ($StageId -eq 'E') {
            $contextManifest = Assert-ContextManifestCurrent $workerState
            foreach ($document in @($outputs.documents | ForEach-Object value)) {
                Assert-Wave3EvidenceSources -Document $document `
                    -ContextManifest $contextManifest | Out-Null
            }
        }
        $resolvedOutputs += [pscustomobject]@{
            worker_id = [string]$workerConfig.id
            documents = $outputs.documents
        }
        $inventory = if (-not [string]::IsNullOrWhiteSpace([string]$workerState.workspace_dir)) {
            Get-WorkspaceInventory ([string]$workerState.workspace_dir)
        }
        else { @() }
        $workerEntries += [ordered]@{
            id = [string]$workerConfig.id
            role = [string]$workerConfig.role
            session_id = [string]$workerState.session_id
            budget = $workerConfig.budget
            metrics = $metrics
            process_lifetime = $lifetime
            context_manifest = Get-RunRelativePath ([string]$workerState.context_manifest)
            context_manifest_sha256 = [string]$workerState.context_manifest_sha256
            artifacts = @($outputs.artifacts)
            workspace_path = Get-RunRelativePath ([string]$workerState.workspace_dir)
            workspace_inventory = @($inventory)
        }
    }
    Assert-StageDocuments -StageId $StageId -WorkerConfigs $workerConfigs `
        -ResolvedOutputs $resolvedOutputs -DependencyArtifactIndex $dependencyArtifactIndex `
        -AllowedRequirementIds $allowedRequirementIds -ExpectedMilestone $expectedMilestone

    $reviewerConsensusReceipt = $null
    if ($StageId -eq 'G') {
        $integrationDocuments = @($resolvedOutputs | ForEach-Object {
            $_.documents | ForEach-Object value
        })
        $reviewerConfigs = @($config.workers | Where-Object stage -eq 'R' | Sort-Object id)
        $reviewerConsensusReceipt = Assert-Wave3SelectedCandidateReviewConsensus `
            -Documents $integrationDocuments -ReviewerConfigs $reviewerConfigs `
            -ArtifactIndex $dependencyArtifactIndex
    }

    $semanticGateReceipt = $null
    if ($semanticGateConfigs.Count -eq 1) {
        $semanticGateReceipt = Invoke-Wave3SemanticGate `
            -GateConfig $semanticGateConfigs[0] -RepositoryRoot $repositoryRoot `
            -WorkspaceRoot $workspaceRoot
    }

    $dependencyEntries = foreach ($dependencyId in @($stageConfig.depends_on)) {
        $dependency = Get-StateStage $State ([string]$dependencyId)
        [ordered]@{
            stage = [string]$dependencyId
            path = Get-RunRelativePath ([string]$dependency.manifest_file)
            sha256 = [string]$dependency.manifest_sha256
        }
    }
    $manifest = [ordered]@{
        schema_version = 1
        run_id = $RunId
        stage = $StageId
        model = [string]$config.model
        config_sha256 = [string]$Validation.config_sha256
        stage_config_sha256 = [string]$stageState.stage_config_sha256
        validated_utc = Get-UtcNowText
        dependencies = @($dependencyEntries)
        workers = @($workerEntries)
    }
    if ($null -ne $semanticGateReceipt) {
        $manifest['semantic_gate'] = $semanticGateReceipt
    }
    if ($null -ne $reviewerConsensusReceipt) {
        $manifest['reviewer_consensus'] = $reviewerConsensusReceipt
    }
    $manifestPath = Join-Path $manifestRoot ($StageId + '.manifest.json')
    Write-Wave3AtomicJson -LiteralPath $manifestPath -Value $manifest
    $stageState.status = 'validated'
    $stageState.validated_utc = Get-UtcNowText
    $stageState.manifest_file = $manifestPath
    $stageState.manifest_sha256 = Get-Wave3Sha256 -LiteralPath $manifestPath
    foreach ($workerConfig in $workerConfigs) {
        (Get-StateWorker $State ([string]$workerConfig.id)).status = 'validated'
    }
    Write-State $State $Validation
    return $stageState
}

function Test-TransientMetricsError($ErrorRecord) {
    $exception = $ErrorRecord.Exception
    while ($null -ne $exception) {
        if ($exception -is [System.IO.IOException]) { return $true }
        $exception = $exception.InnerException
    }
    return $false
}

function Test-NoSessionFileMetricsError($ErrorRecord) {
    return $ErrorRecord.Exception.Message -like `
        'Expected one session JSONL for *; found 0'
}

function Get-WatchdogMetrics(
    $WorkerState,
    [string]$LiveStatus,
    [datetimeoffset]$ObservedAt
) {
    if ([string]::IsNullOrWhiteSpace([string]$WorkerState.session_directory) -or
        [string]::IsNullOrWhiteSpace([string]$WorkerState.session_id)) {
        return [pscustomobject]@{
            metrics = $null
            fresh = $false
            terminal_failure_reason = $null
        }
    }
    $liveRead = $LiveStatus -eq 'running'
    try {
        $parameters = @{
            SessionDirectory = [string]$WorkerState.session_directory
            SessionId = [string]$WorkerState.session_id
        }
        if ($liveRead) { $parameters.AllowIncompleteTail = $true }
        $metrics = Get-Wave3SessionMetrics @parameters
        if ($null -ne $WorkerState.last_metrics) {
            Assert-Wave3MonotonicSessionMetrics `
                -Previous $WorkerState.last_metrics -Current $metrics | Out-Null
        }
        $WorkerState.metrics_stale_since_utc = $null
        $WorkerState.metrics_stale_error = $null
        return [pscustomobject]@{
            metrics = $metrics
            fresh = $true
            terminal_failure_reason = $null
        }
    }
    catch {
        $noSessionFile = Test-NoSessionFileMetricsError $_
        if ($noSessionFile -and $null -ne $WorkerState.last_metrics) {
            # Once telemetry has been observed, disappearance of the sole
            # authenticated session is an integrity failure, never a return
            # to the pre-first-response pending state.
            throw
        }
        if (-not $liveRead) {
            if ($noSessionFile -and $LiveStatus -eq 'completed' -and
                $null -eq $WorkerState.last_metrics) {
                # Pi intentionally delays creating the JSONL until a complete
                # assistant turn. A wrapper that exits zero without ever
                # publishing that telemetry is an ordinary worker failure,
                # not a watchdog-wide integrity failure.
                $WorkerState.metrics_stale_error = $_.Exception.Message
                return [pscustomobject]@{
                    metrics = $WorkerState.last_metrics
                    fresh = $false
                    terminal_failure_reason = 'telemetry_missing_after_exit'
                }
            }
            if ($noSessionFile -and
                $LiveStatus -in @(
                    'failed', 'lost', 'launch_failed',
                    'budget_exceeded', 'stopped'
                )) {
                # An ordinary failed process may die before Pi creates a
                # session. Preserve peer isolation; the worker still cannot
                # validate and receives no unobserved metric credit.
                $WorkerState.metrics_stale_error = $_.Exception.Message
                return [pscustomobject]@{
                    metrics = $WorkerState.last_metrics
                    fresh = $false
                    terminal_failure_reason = $null
                }
            }
            throw
        }
        if (-not $noSessionFile -and -not (Test-TransientMetricsError $_)) {
            throw
        }
        if ([string]::IsNullOrWhiteSpace([string]$WorkerState.metrics_stale_since_utc)) {
            $WorkerState.metrics_stale_since_utc = if ($noSessionFile) {
                [string]$WorkerState.process_start_utc
            }
            else {
                $ObservedAt.ToString('o')
            }
        }
        $WorkerState.metrics_stale_error = $_.Exception.Message
        if (-not $noSessionFile) {
            $staleSince = [datetimeoffset]::Parse(
                [string]$WorkerState.metrics_stale_since_utc
            ).ToUniversalTime()
            if (($ObservedAt.ToUniversalTime() - $staleSince).TotalSeconds -gt
                $watchdogMetricsStaleGraceSeconds) {
                throw "Session metrics remained unavailable for more than $watchdogMetricsStaleGraceSeconds seconds: $($_.Exception.Message)"
            }
        }
        return [pscustomobject]@{
            metrics = $WorkerState.last_metrics
            fresh = $false
            terminal_failure_reason = $null
        }
    }
}

function Stop-WatchdogWorker(
    $WorkerState,
    [string]$Reason,
    $BudgetExceeded,
    [ValidateSet('stopped', 'failed')][string]$TerminalStatus = 'stopped'
) {
    if ((Get-LiveWorkerStatus $WorkerState) -eq 'running') {
        Stop-Wave3ProcessTree -ProcessId ([int]$WorkerState.pid) `
            -ExpectedStartUtc ([string]$WorkerState.process_start_utc) `
            -ExpectedExecutablePath ([string]$WorkerState.expected_executable_path) `
            -RequiredCommandLineMarkers @($WorkerState.command_line_markers) | Out-Null
    }
    $WorkerState.stopped_utc = Get-UtcNowText
    $WorkerState.stop_reason = $Reason
    $WorkerState.budget_exceeded = $BudgetExceeded
    $WorkerState.status = if ($null -ne $BudgetExceeded) { 'budget_exceeded' } else { $TerminalStatus }
}

function Invoke-WatchdogPass($State, $Validation, [string]$StageId) {
    $stageState = Get-StateStage $State $StageId
    if ([string]$stageState.status -notin @('launching', 'running')) {
        if ($null -eq $stageState.watchdog_stopped_utc) {
            $stageState.watchdog_stopped_utc = Get-UtcNowText
        }
        return $false
    }

    $now = [datetimeoffset]::UtcNow
    $observedUtc = $now.ToString('o')
    $metricsByWorker = @{}
    $freshMetricsByWorker = @{}
    $liveByWorker = @{}
    $runTotalTokens = [int64]0
    foreach ($workerState in $State.workers) {
        if ([string]$workerState.stage -eq $StageId) {
            $liveBefore = Get-LiveWorkerStatus $workerState
            $observation = Get-WatchdogMetrics $workerState $liveBefore $now
            $liveAfter = Get-LiveWorkerStatus $workerState
            $settlement = Get-Wave3WorkerIdentitySettlementPlan `
                -LiveBefore $liveBefore -LiveAfter $liveAfter `
                -SettlementMilliseconds $workerIdentitySettlementMilliseconds
            if ($settlement.should_settle) {
                Start-Sleep -Milliseconds $settlement.settlement_milliseconds
                $liveAfter = Get-LiveWorkerStatus $workerState
            }
            if ($liveBefore -eq 'running' -and $liveAfter -ne 'running') {
                # The worker stopped while its live snapshot was being read.
                # Re-read strictly before any terminal budget decision.
                $observation = Get-WatchdogMetrics $workerState $liveAfter $now
            }
            $terminalFailureProperty =
                $observation.PSObject.Properties['terminal_failure_reason']
            if ($null -ne $terminalFailureProperty -and
                -not [string]::IsNullOrWhiteSpace(
                    [string]$terminalFailureProperty.Value
                )) {
                $workerState.status = 'failed'
                $workerState.stopped_utc = $observedUtc
                $workerState.stop_reason = [string]$terminalFailureProperty.Value
                $liveAfter = 'failed'
            }
            $liveByWorker[[string]$workerState.id] = $liveAfter
            $freshMetricsByWorker[[string]$workerState.id] = [bool]$observation.fresh
        }
        else {
            $observation = [pscustomobject]@{
                metrics = $workerState.last_metrics
                fresh = $false
            }
        }
        $metrics = $observation.metrics
        if ($null -ne $metrics) {
            $metricsByWorker[[string]$workerState.id] = $metrics
            if ($observation.fresh) {
                $workerState.last_metrics = $metrics
                $workerState.watchdog_checked_utc = $observedUtc
            }
            $runTotalTokens += [int64]$metrics.total_tokens
        }
    }

    $workerConfigs = @($Validation.config.workers | Where-Object stage -eq $StageId | Sort-Object id)
    $violations = @{}
    $artifactCheckpointFailures = @{}
    foreach ($workerConfig in $workerConfigs) {
        $workerState = Get-StateWorker $State ([string]$workerConfig.id)
        $live = [string]$liveByWorker[[string]$workerConfig.id]
        if ($live -notin @('running', 'completed')) { continue }

        $metrics = $metricsByWorker[[string]$workerConfig.id]
        $totalTokens = if ($null -ne $metrics) { [int64]$metrics.total_tokens } else { [int64]0 }
        $toolCalls = if ($null -ne $metrics) { [int64]$metrics.tool_calls } else { [int64]0 }
        $completedToolCalls = if ($null -ne $metrics) {
            [int64]$metrics.completed_tool_calls
        }
        else { [int64]0 }
        $lifetime = Get-WorkerProcessLifetime $workerState $live $now
        if ($live -eq 'completed' -and
            [string]::IsNullOrWhiteSpace([string]$workerState.process_exit_utc)) {
            $workerState.process_exit_utc = [string]$lifetime.process_end_utc
        }
        $decision = Get-Wave3BudgetViolation `
            -StartedUtc ([datetimeoffset]::Parse([string]$lifetime.process_start_utc)) `
            -NowUtc ([datetimeoffset]::Parse([string]$lifetime.process_end_utc)) `
            -TotalTokens $totalTokens -ToolCalls $toolCalls -Budget $workerConfig.budget `
            -RunTotalTokens $runTotalTokens -RunTokenCeiling ([int64]$State.actual_token_ceiling)
        if ($null -ne $decision) {
            $violations[[string]$workerConfig.id] = $decision
        }
        else {
            $checkpointDecision = Get-Wave3ArtifactCheckpointDecision `
                -WorkerConfig $workerConfig `
                -WorkspacePath ([string]$workerState.workspace_dir) `
                -DeclaredToolCalls $toolCalls `
                -CompletedToolCalls $completedToolCalls `
                -TelemetryFresh ([bool]$freshMetricsByWorker[[string]$workerConfig.id]) `
                -PreviouslySatisfied ($null -ne $workerState.artifact_checkpoint_satisfied)
            if ($null -ne $checkpointDecision) {
                if ([string]$checkpointDecision.kind -eq 'artifact_checkpoint_satisfied') {
                    $workerState.artifact_checkpoint_satisfied = [ordered]@{
                        kind = [string]$checkpointDecision.kind
                        observed_declared_tool_calls =
                            [int64]$checkpointDecision.observed_declared_tool_calls
                        observed_completed_tool_calls =
                            [int64]$checkpointDecision.observed_completed_tool_calls
                        checkpoint_tool_calls = [int64]$checkpointDecision.limit
                        artifact_path = [string]$checkpointDecision.artifact_path
                        observed_utc = $observedUtc
                    }
                }
                else {
                    $artifactCheckpointFailures[[string]$workerConfig.id] = $checkpointDecision
                }
            }
        }
    }

    foreach ($workerId in @($artifactCheckpointFailures.Keys | Sort-Object)) {
        $decision = $artifactCheckpointFailures[$workerId]
        $workerState = Get-StateWorker $State $workerId
        $checkpointRecord = [ordered]@{
            kind = [string]$decision.kind
            observed_declared_tool_calls = [int64]$decision.observed_declared_tool_calls
            observed_completed_tool_calls = [int64]$decision.observed_completed_tool_calls
            checkpoint_tool_calls = [int64]$decision.limit
            safe_artifact_present_now = [bool]$decision.safe_artifact_present_now
            required_artifact_count = [int]$decision.required_artifact_count
            detected_utc = $observedUtc
        }
        $workerState.artifact_checkpoint_failed = $checkpointRecord
        Stop-WatchdogWorker -WorkerState $workerState `
            -Reason "artifact_checkpoint_not_satisfied_by_deadline:completed_tool_calls=$($decision.observed_completed_tool_calls),checkpoint=$($decision.limit)" `
            -BudgetExceeded $null -TerminalStatus failed
        $liveByWorker[$workerId] = 'failed'
    }

    if ($violations.Count) {
        $violationSummary = @($violations.Keys | Sort-Object | ForEach-Object {
            $decision = $violations[$_]
            "$_/$($decision.kind)=$($decision.observed)>$($decision.limit)"
        }) -join ';'
        $runningWorkerIds = @($workerConfigs | Where-Object {
            [string]$liveByWorker[[string]$_.id] -eq 'running'
        } | ForEach-Object { [string]$_.id })
        $enforcement = Get-Wave3BudgetEnforcementPlan -Violations $violations `
            -RunningWorkerIds $runningWorkerIds
        $runCeilingExceeded = [bool]$enforcement.abort_stage
        foreach ($workerConfig in $workerConfigs) {
            $workerId = [string]$workerConfig.id
            $workerState = Get-StateWorker $State $workerId
            $live = [string]$liveByWorker[$workerId]
            if ($violations.ContainsKey($workerId)) {
                $decision = $violations[$workerId]
                $budgetRecord = [ordered]@{
                    kind = [string]$decision.kind
                    observed = $decision.observed
                    limit = $decision.limit
                    detected_utc = $observedUtc
                    run_total_tokens = $runTotalTokens
                }
                Stop-WatchdogWorker $workerState `
                    "budget_exceeded:$($decision.kind)" $budgetRecord
            }
            elseif ($runCeilingExceeded -and $live -eq 'running') {
                Stop-WatchdogWorker $workerState `
                    "stage_aborted_after_budget_exceeded:$violationSummary" $null
            }
            elseif ($live -eq 'completed') {
                $workerState.status = 'completed'
            }
        }
        if ($runCeilingExceeded) {
            $stageState.status = 'budget_exceeded'
            $stageState.stopped_utc = $observedUtc
            $stageState.stop_reason = "budget_exceeded:$violationSummary"
            $stageState.watchdog_stopped_utc = $observedUtc
            return $false
        }
        # Worker-local caps isolate the offending process. Independent peers may
        # finish depositing artifacts, but the stage remains ineligible to
        # validate and becomes terminal after the remaining workers stop.
        return $true
    }

    $stageWorkerIds = @($workerConfigs | ForEach-Object { [string]$_.id })
    $failurePlan = Get-Wave3FailureEnforcementPlan `
        -LiveStatusByWorker $liveByWorker -StageWorkerIds $stageWorkerIds
    if ($failurePlan.abort_stage) {
        $failedIds = @($failurePlan.identity_mismatch_ids)
        foreach ($workerConfig in $workerConfigs) {
            $workerState = Get-StateWorker $State ([string]$workerConfig.id)
            $live = [string]$liveByWorker[[string]$workerConfig.id]
            if ($live -eq 'running') {
                Stop-WatchdogWorker $workerState `
                    "stage_aborted_after_worker_failure:$($failedIds -join ',')" $null
            }
            elseif ($live -eq 'completed') {
                $workerState.status = 'completed'
            }
            elseif ($live -in @('failed', 'lost', 'launch_failed', 'identity_mismatch')) {
                $workerState.status = 'failed'
                if ([string]::IsNullOrWhiteSpace([string]$workerState.stopped_utc)) {
                    $workerState.stopped_utc = $observedUtc
                }
                if ([string]::IsNullOrWhiteSpace([string]$workerState.stop_reason)) {
                    $workerState.stop_reason = "worker_$live"
                }
            }
        }
        $stageState.status = 'failed'
        $stageState.stopped_utc = $observedUtc
        $stageState.stop_reason = "worker_failure:$($failedIds -join ',')"
        $stageState.watchdog_stopped_utc = $observedUtc
        return $false
    }

    $failedIds = @($failurePlan.ordinary_failure_ids)
    if ($failedIds.Count) {
        foreach ($workerConfig in $workerConfigs) {
            $workerState = Get-StateWorker $State ([string]$workerConfig.id)
            $live = [string]$liveByWorker[[string]$workerConfig.id]
            if ($live -eq 'completed') { $workerState.status = 'completed' }
            elseif ($live -in @('failed', 'lost', 'launch_failed')) {
                $workerState.status = 'failed'
                if ([string]::IsNullOrWhiteSpace([string]$workerState.stopped_utc)) {
                    $workerState.stopped_utc = $observedUtc
                }
                if ([string]::IsNullOrWhiteSpace([string]$workerState.stop_reason)) {
                    $workerState.stop_reason = "worker_$live"
                }
            }
        }
        if (@($failurePlan.peer_ids_to_continue).Count) { return $true }
        $stageState.status = 'failed'
        $stageState.stopped_utc = $observedUtc
        $stageState.stop_reason = "worker_failure:$($failedIds -join ',')"
        $stageState.watchdog_stopped_utc = $observedUtc
        return $false
    }

    $completed = @($workerConfigs | Where-Object {
        [string]$liveByWorker[[string]$_.id] -eq 'completed'
    })
    foreach ($workerConfig in $completed) {
        (Get-StateWorker $State ([string]$workerConfig.id)).status = 'completed'
    }
    $budgetExceeded = @($workerConfigs | Where-Object {
        [string]$liveByWorker[[string]$_.id] -eq 'budget_exceeded'
    })
    $running = @($workerConfigs | Where-Object {
        [string]$liveByWorker[[string]$_.id] -eq 'running'
    })
    if ($budgetExceeded.Count -and -not $running.Count) {
        $ids = @($budgetExceeded | ForEach-Object { [string]$_.id }) -join ','
        $stageState.status = 'budget_exceeded'
        $stageState.stopped_utc = $observedUtc
        $stageState.stop_reason = "worker_budget_exceeded:$ids"
        $stageState.watchdog_stopped_utc = $observedUtc
        return $false
    }
    if ($completed.Count -eq $workerConfigs.Count) {
        $stageState.status = 'completed'
        $stageState.stopped_utc = $observedUtc
        $stageState.stop_reason = 'all_workers_completed'
        $stageState.watchdog_stopped_utc = $observedUtc
        return $false
    }
    return $true
}

function Start-WatchdogProcess($Validation, [string]$StageId) {
    $pwsh = (Get-Command pwsh.exe -ErrorAction Stop).Source
    $arguments = @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $PSCommandPath,
        '-Action', 'Watchdog',
        '-RunId', $RunId,
        '-Stage', $StageId,
        '-ConfigPath', ([string]$Validation.config_path)
    )
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $pwsh
    $startInfo.WorkingDirectory = $repositoryRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    foreach ($argument in $arguments) { $startInfo.ArgumentList.Add([string]$argument) }
    $process = [System.Diagnostics.Process]::Start($startInfo)
    if ($null -eq $process) { throw "Failed to start watchdog for stage $StageId" }
    return $process
}

function Write-WatchdogSidecar([string]$Path, $Value) {
    Write-Wave3AtomicJson -LiteralPath $Path -Value $Value
}

function Invoke-WatchdogFailClosedActions($TrustedState, [string]$StageId, [string]$Reason) {
    $outcomes = @()
    foreach ($workerState in @($TrustedState.workers | Where-Object stage -eq $StageId)) {
        $identity = Get-WorkerProcessIdentity $workerState
        $decision = Get-Wave3FailClosedDecision `
            -WorkerProcessExists ([bool]$identity.exists) -IdentityTrusted ([bool]$identity.trusted)
        $outcome = [ordered]@{
            worker_id = [string]$workerState.id
            action = [string]$decision.action
            identity_reason = [string]$identity.reason
            result = 'not_attempted'
        }
        if ($decision.action -eq 'kill_verified_tree') {
            try {
                Stop-Wave3ProcessTree -ProcessId ([int]$workerState.pid) `
                    -ExpectedStartUtc ([string]$workerState.process_start_utc) `
                    -ExpectedExecutablePath ([string]$workerState.expected_executable_path) `
                    -RequiredCommandLineMarkers @($workerState.command_line_markers) | Out-Null
                $outcome.result = 'killed'
            }
            catch {
                $outcome.result = "kill_failed:$($_.Exception.Message)"
            }
        }
        elseif ($decision.action -eq 'do_not_kill') {
            $outcome.result = 'identity_uncertain_not_killed'
        }
        else {
            $outcome.result = 'not_running'
        }
        $outcomes += [pscustomobject]$outcome
    }
    return @($outcomes)
}

function Set-WatchdogFailureState($State, [string]$StageId, [string]$Reason, $Outcomes) {
    $failedUtc = Get-UtcNowText
    $stageState = Get-StateStage $State $StageId
    $stageState.status = 'watchdog_failed'
    $stageState.stopped_utc = $failedUtc
    $stageState.stop_reason = "watchdog_failed:$Reason"
    $stageState.watchdog_stopped_utc = $failedUtc
    foreach ($outcome in $Outcomes) {
        $workerState = Get-StateWorker $State ([string]$outcome.worker_id)
        if ([string]$outcome.result -eq 'killed') {
            $workerState.status = 'stopped'
            $workerState.stopped_utc = $failedUtc
            $workerState.stop_reason = "watchdog_fail_closed:$Reason"
        }
        elseif ([string]$outcome.result -eq 'identity_uncertain_not_killed') {
            $workerState.status = 'identity_mismatch'
            $workerState.stop_reason = "watchdog_failed_identity_uncertain:$Reason"
        }
    }
}

function Wait-WatchdogStartupReceipt(
    $StageState,
    [System.Diagnostics.Process]$WatchdogProcess,
    [int]$TimeoutSeconds
) {
    $deadline = [datetimeoffset]::UtcNow.AddSeconds($TimeoutSeconds)
    $invalidHeartbeatObserved = $false
    while ([datetimeoffset]::UtcNow -le $deadline) {
        if ($WatchdogProcess.HasExited) {
            return [pscustomobject]@{
                ready = $false
                reason = "watchdog_exited_before_ready:exit_code=$($WatchdogProcess.ExitCode)"
            }
        }
        if (Test-Path -LiteralPath $StageState.watchdog_heartbeat_file -PathType Leaf) {
            try {
                $heartbeat = Get-Content `
                    -LiteralPath $StageState.watchdog_heartbeat_file -Raw |
                    ConvertFrom-Json -Depth 20
                if ([string]$heartbeat.stage -cne [string]$StageState.id -or
                    [int]$heartbeat.pid -ne [int]$StageState.watchdog_pid) {
                    return [pscustomobject]@{
                        ready = $false
                        reason = 'watchdog_startup_heartbeat_identity_mismatch'
                    }
                }
                if ([string]$heartbeat.phase -in @(
                    'waiting_for_lock', 'checking_budgets'
                )) {
                    if ($WatchdogProcess.HasExited) {
                        return [pscustomobject]@{
                            ready = $false
                            reason = "watchdog_exited_before_ready:exit_code=$($WatchdogProcess.ExitCode)"
                        }
                    }
                    return [pscustomobject]@{
                        ready = $true
                        reason = 'authenticated_heartbeat_observed'
                    }
                }
            }
            catch {
                # The watchdog replaces this sidecar atomically on every pass.
                # A reader may transiently collide with replacement or AV/file
                # indexing; retry until the bounded deadline.
                $invalidHeartbeatObserved = $true
            }
        }
        Start-Sleep -Milliseconds 100
    }
    return [pscustomobject]@{
        ready = $false
        reason = if ($invalidHeartbeatObserved) {
            'watchdog_startup_heartbeat_invalid_at_deadline'
        }
        else { "watchdog_startup_handshake_exceeded_${TimeoutSeconds}_seconds" }
    }
}

function Invoke-StartStageWatchdogStartupFailure(
    $Validation,
    $TrustedState,
    $TrustedStageState,
    [System.Diagnostics.Process]$WatchdogProcess,
    [string]$Reason
) {
    if (-not $WatchdogProcess.HasExited) {
        $watchdogIdentity = Get-WatchdogProcessIdentity $TrustedStageState
        if ($watchdogIdentity.trusted) {
            Stop-Wave3ProcessTree -ProcessId ([int]$TrustedStageState.watchdog_pid) `
                -ExpectedStartUtc ([string]$TrustedStageState.watchdog_start_utc) `
                -ExpectedExecutablePath ([string]$TrustedStageState.watchdog_expected_executable_path) `
                -RequiredCommandLineMarkers @($TrustedStageState.watchdog_command_markers) | Out-Null
        }
        else {
            # The exact Process handle came directly from our Start call. It
            # remains safe to terminate even if persisted identity is unusable.
            $WatchdogProcess.Kill($true)
            $WatchdogProcess.WaitForExit()
        }
    }

    $outcomes = Invoke-WatchdogFailClosedActions `
        $TrustedState ([string]$TrustedStageState.id) $Reason
    $failureLock = $null
    $lockWaitStart = [datetimeoffset]::UtcNow
    while ($null -eq $failureLock) {
        try { $failureLock = Open-RunLock }
        catch {
            if (([datetimeoffset]::UtcNow - $lockWaitStart).TotalSeconds -gt
                $watchdogLockStarvationSeconds) {
                throw "watchdog_startup_failure_lock_starvation_exceeded_$($watchdogLockStarvationSeconds)_seconds"
            }
            Start-Sleep -Milliseconds 100
        }
    }
    try {
        $state = Read-State
        Assert-StateMatchesConfig $state $Validation
        $stageState = Get-StateStage $state ([string]$TrustedStageState.id)
        if ([string]$stageState.status -ne 'watchdog_failed') {
            Set-WatchdogFailureState $state ([string]$TrustedStageState.id) `
                $Reason $outcomes
            Write-State $state $Validation
        }
    }
    finally {
        $failureLock.Dispose()
    }
}

function Complete-WatchdogStartupHandshake(
    $Validation,
    $TrustedState,
    $TrustedStageState,
    [System.Diagnostics.Process]$WatchdogProcess,
    [int]$TimeoutSeconds
) {
    try {
        $startupReceipt = Wait-WatchdogStartupReceipt `
            -StageState $TrustedStageState -WatchdogProcess $WatchdogProcess `
            -TimeoutSeconds $TimeoutSeconds
    }
    catch {
        $startupReceipt = [pscustomobject]@{
            ready = $false
            reason = "watchdog_startup_handshake_error:$($_.Exception.Message)"
        }
    }
    if (-not $startupReceipt.ready) {
        Invoke-StartStageWatchdogStartupFailure `
            -Validation $Validation -TrustedState $TrustedState `
            -TrustedStageState $TrustedStageState `
            -WatchdogProcess $WatchdogProcess `
            -Reason ([string]$startupReceipt.reason)
        throw "Watchdog startup failed: $($startupReceipt.reason)"
    }
    return $startupReceipt
}

function Watchdog-Action {
    if ([string]::IsNullOrWhiteSpace($Stage)) { throw 'Watchdog requires -Stage' }
    $validation = Get-ValidatedConfig
    $heartbeatPath = Join-Path $watchdogRoot ($Stage + '.heartbeat.json')
    $errorPath = Join-Path $watchdogRoot ($Stage + '.error.txt')
    $exitPath = Join-Path $watchdogRoot ($Stage + '.exit.json')

    # StartStage records the sole authorized watchdog while it owns the run lock.
    # Authenticate this process before it can touch shared sidecars or worker state.
    $ownerLock = $null
    $ownerLockWaitStart = [datetimeoffset]::UtcNow
    while ($null -eq $ownerLock) {
        try { $ownerLock = Open-RunLock }
        catch {
            if (([datetimeoffset]::UtcNow - $ownerLockWaitStart).TotalSeconds -gt
                $watchdogLockStarvationSeconds) {
                throw "watchdog_owner_lock_starvation_exceeded_$($watchdogLockStarvationSeconds)_seconds"
            }
            Start-Sleep -Milliseconds 200
        }
    }
    try {
        $ownerState = Read-State
        Assert-StateMatchesConfig $ownerState $validation
        $ownerStageState = Get-StateStage $ownerState $Stage
        Assert-WatchdogInvocationOwner $ownerStageState $PID
    }
    finally {
        $ownerLock.Dispose()
    }

    $sequence = 0
    # Owner authentication is itself a trusted state observation. Preserve it
    # so failures while publishing the first heartbeat still fail-close every
    # identity-authenticated worker.
    $lastTrustedState = $ownerState
    $terminalStatus = 'watchdog_failed'
    $terminalReason = 'unhandled_watchdog_error'
    try {
        while ($true) {
            $sequence++
            Write-WatchdogSidecar $heartbeatPath ([ordered]@{
                stage = $Stage
                pid = $PID
                sequence = $sequence
                phase = 'waiting_for_lock'
                updated_utc = Get-UtcNowText
            })
            $lock = $null
            $lockWaitStart = [datetimeoffset]::UtcNow
            while ($null -eq $lock) {
                try { $lock = Open-RunLock }
                catch {
                    if (([datetimeoffset]::UtcNow - $lockWaitStart).TotalSeconds -gt
                        $watchdogLockStarvationSeconds) {
                        throw "watchdog_lock_starvation_exceeded_$($watchdogLockStarvationSeconds)_seconds"
                    }
                    Start-Sleep -Milliseconds 200
                }
            }
            try {
                $state = Read-State
                Assert-StateMatchesConfig $state $validation
                $stageState = Get-StateStage $state $Stage
                $lastTrustedState = $state
                Assert-WatchdogInvocationOwner $stageState $PID
                $watchdogIdentity = Get-WatchdogProcessIdentity $stageState
                if (-not $watchdogIdentity.trusted) {
                    throw "watchdog_identity_mismatch:$($watchdogIdentity.reason)"
                }
                Write-WatchdogSidecar $heartbeatPath ([ordered]@{
                    stage = $Stage
                    pid = $PID
                    sequence = $sequence
                    phase = 'checking_budgets'
                    updated_utc = Get-UtcNowText
                })
                $keepWatching = Invoke-WatchdogPass $state $validation $Stage
                Write-State $state $validation
                $lastTrustedState = $state
            }
            finally {
                $lock.Dispose()
            }
            if (-not $keepWatching) {
                $terminalStatus = 'clean_exit'
                $terminalReason = [string](Get-StateStage $lastTrustedState $Stage).stop_reason
                return
            }
            Start-Sleep -Milliseconds $watchdogPollMilliseconds
        }
    }
    catch {
        $terminalReason = $_.Exception.Message
        Write-Wave3AtomicText -LiteralPath $errorPath -Text (
            ($_ | Out-String) + "`n"
        )
        $outcomes = if ($null -ne $lastTrustedState) {
            Invoke-WatchdogFailClosedActions $lastTrustedState $Stage $terminalReason
        }
        else { @() }
        if ($null -ne $lastTrustedState) {
            Set-WatchdogFailureState $lastTrustedState $Stage $terminalReason $outcomes
            $failureLock = $null
            try {
                $failureLock = Open-RunLock
                Write-State $lastTrustedState $validation
            }
            catch {
                [System.IO.File]::AppendAllText(
                    $errorPath,
                    "State persistence failed: $($_.Exception.Message)`n",
                    [System.Text.UTF8Encoding]::new($false)
                )
            }
            finally {
                if ($null -ne $failureLock) { $failureLock.Dispose() }
            }
        }
    }
    finally {
        Write-WatchdogSidecar $exitPath ([ordered]@{
            stage = $Stage
            pid = $PID
            status = $terminalStatus
            reason = $terminalReason
            exited_utc = Get-UtcNowText
        })
    }
}

function Start-StageAction {
    if ([string]::IsNullOrWhiteSpace($Stage)) { throw 'StartStage requires -Stage' }
    $validation = Get-ValidatedConfig
    if (-not (Test-Path -LiteralPath $workerScript -PathType Leaf)) {
        throw "Worker script is missing: $workerScript"
    }
    $lock = Open-RunLock
    try {
        if (Test-Path -LiteralPath $statePath -PathType Leaf) {
            $state = Read-State
            Assert-StateMatchesConfig $state $validation
        }
        else {
            $unexpected = @(Get-ChildItem -LiteralPath $runRoot -Force | Where-Object Name -ne '.supervisor.lock')
            if ($unexpected.Count) {
                throw "Run root exists without state and is not empty: $runRoot"
            }
            $state = New-InitialState $validation
            Write-State $state $validation
        }

        $config = $validation.config
        $stageConfig = @($config.stages | Where-Object id -eq $Stage)[0]
        $stageState = Get-StateStage $state $Stage
        Assert-Wave3SerialStageStart -Stages @($state.stages) -RequestedStage $Stage | Out-Null
        if ([string]$stageState.status -ne 'pending') {
            throw "Stage $Stage is already $($stageState.status); use a new RunId for fresh sessions"
        }
        Assert-DependencyManifests $state $stageConfig | Out-Null
        $workerConfigs = @($config.workers | Where-Object stage -eq $Stage | Sort-Object id)

        foreach ($directory in @(
            $stageSnapshotRoot, $promptRoot, $reportRoot, $sessionRoot,
            $workspaceRoot, $contextRoot, $manifestRoot, $watchdogRoot
        )) {
            [System.IO.Directory]::CreateDirectory($directory) | Out-Null
        }
        Assert-Wave3SafeDirectoryTree -LiteralPath $workspaceRoot -BoundaryPath $runRoot | Out-Null
        $stageSnapshot = [ordered]@{
            schema_version = 1
            run_id = $RunId
            config_sha256 = [string]$validation.config_sha256
            stage = $stageConfig
            workers = @($workerConfigs)
        }
        $stageSnapshotPath = Join-Path $stageSnapshotRoot ($Stage + '.json')
        Write-Wave3AtomicJson -LiteralPath $stageSnapshotPath -Value $stageSnapshot
        $stageSnapshotHash = Get-Wave3Sha256 -LiteralPath $stageSnapshotPath
        $stageState.status = 'launching'
        $stageState.started_utc = Get-UtcNowText
        $stageState.stage_config_file = $stageSnapshotPath
        $stageState.stage_config_sha256 = $stageSnapshotHash
        Write-State $state $validation

        $startedWorkers = @()
        $watchdogProcess = $null
        $currentLaunchingWorker = $null
        $currentProcess = $null
        try {
            $workerIndex = 0
            $launchStaggerMilliseconds = if (
                $null -ne $config.PSObject.Properties['launch_stagger_milliseconds']
            ) { [int]$config.launch_stagger_milliseconds } else { 0 }
            foreach ($workerConfig in $workerConfigs) {
                $workerState = Get-StateWorker $state ([string]$workerConfig.id)
                $stagePromptRoot = Join-Path $promptRoot $Stage
                $stageReportRoot = Join-Path $reportRoot $Stage
                $stageSessionRoot = Join-Path $sessionRoot $Stage
                foreach ($directory in @($stagePromptRoot, $stageReportRoot, $stageSessionRoot)) {
                    [System.IO.Directory]::CreateDirectory($directory) | Out-Null
                }
                $workerState.workspace_dir = if ([string]::IsNullOrWhiteSpace([string]$workerConfig.writable_dir)) {
                    $null
                }
                else {
                    $path = Resolve-Wave3ContainedPath -Root $workspaceRoot `
                        -RelativePath ([string]$workerConfig.writable_dir)
                    [System.IO.Directory]::CreateDirectory($path) | Out-Null
                    Assert-Wave3SafeDirectoryTree -LiteralPath $path -BoundaryPath $runRoot | Out-Null
                    $path
                }
                $workerState.prompt_file = Join-Path $stagePromptRoot ($workerConfig.id + '.md')
                $workerState.output_file = Join-Path $stageReportRoot ($workerConfig.id + '.json')
                $workerState.error_file = Join-Path $stageReportRoot ($workerConfig.id + '.err.txt')
                $workerState.exit_file = Join-Path $stageReportRoot ($workerConfig.id + '.exit.txt')
                $workerState.launch_receipt_file = Join-Path $stageReportRoot `
                    ($workerConfig.id + '.launch.json')
                $workerState.session_directory = Resolve-WorkerSessionDirectory `
                    -StageSessionRoot $stageSessionRoot `
                    -WorkerId ([string]$workerConfig.id)
                [System.IO.Directory]::CreateDirectory(
                    [string]$workerState.session_directory
                ) | Out-Null
                Assert-Wave3SafeDirectoryTree `
                    -LiteralPath ([string]$workerState.session_directory) `
                    -BoundaryPath $stageSessionRoot | Out-Null
                $workerState.session_id = "$RunId-$Stage-$($workerConfig.id)-a1"
                $workerState.expected_executable_path = (Get-Command pwsh.exe -ErrorAction Stop).Source
                $workerState.command_line_markers = @(
                    $workerScript,
                    [string]$workerState.session_id,
                    [string]$workerState.prompt_file
                )
                $workerState.attempt = 1
                $workerState.status = 'launching'
                $currentLaunchingWorker = $workerState
                foreach ($path in @(
                    $workerState.output_file,
                    $workerState.error_file,
                    $workerState.exit_file,
                    $workerState.launch_receipt_file
                )) {
                    if (Test-Path -LiteralPath $path) {
                        throw "Fresh-session output already exists for $($workerConfig.id): $path"
                    }
                }
                $context = New-ContextManifest $state $validation $workerConfig $stageConfig $stageSnapshotHash
                $workerState.context_manifest = $context.path
                $workerState.context_manifest_sha256 = $context.sha256
                $prompt = Get-WorkerPrompt $config $workerConfig $workerState
                Write-Wave3AtomicText -LiteralPath $workerState.prompt_file -Text ($prompt + "`n")
                Write-State $state $validation

                $process = Start-WorkerProcess $workerConfig $workerState ([string]$config.model)
                $currentProcess = $process
                $workerState.pid = [int]$process.Id
                $workerState.process_start_utc = ([datetimeoffset]$process.StartTime.ToUniversalTime()).ToString('o')
                $workerState.started_utc = Get-UtcNowText
                $workerState.status = 'running'
                $startedWorkers += $workerState
                Write-State $state $validation
                $currentLaunchingWorker = $null
                $currentProcess = $null
                $workerIndex++
                if ($workerIndex -lt $workerConfigs.Count -and
                    $launchStaggerMilliseconds -gt 0) {
                    Start-Sleep -Milliseconds $launchStaggerMilliseconds
                }
            }
            $stageState.status = 'running'
            $stageState.watchdog_expected_executable_path = (Get-Command pwsh.exe -ErrorAction Stop).Source
            $stageState.watchdog_command_markers = @(
                $PSCommandPath,
                'Watchdog',
                $RunId,
                $Stage
            )
            $stageState.watchdog_heartbeat_file = Join-Path $watchdogRoot ($Stage + '.heartbeat.json')
            $stageState.watchdog_error_file = Join-Path $watchdogRoot ($Stage + '.error.txt')
            $stageState.watchdog_exit_file = Join-Path $watchdogRoot ($Stage + '.exit.json')
            foreach ($sidecar in @(
                $stageState.watchdog_heartbeat_file,
                $stageState.watchdog_error_file,
                $stageState.watchdog_exit_file
            )) {
                if (Test-Path -LiteralPath $sidecar) {
                    throw "Fresh watchdog sidecar already exists: $sidecar"
                }
            }
            $watchdogProcess = Start-WatchdogProcess $validation $Stage
            $stageState.watchdog_pid = [int]$watchdogProcess.Id
            $stageState.watchdog_start_utc = (
                [datetimeoffset]$watchdogProcess.StartTime.ToUniversalTime()
            ).ToString('o')
            Write-State $state $validation
        }
        catch {
            $launchFailureReason = $_.Exception.Message
            $failedUtc = Get-UtcNowText
            if ($null -ne $watchdogProcess -and -not $watchdogProcess.HasExited) {
                Stop-Wave3ProcessTree -ProcessId ([int]$watchdogProcess.Id) `
                    -ExpectedStartUtc ([string]$stageState.watchdog_start_utc) `
                    -ExpectedExecutablePath ([string]$stageState.watchdog_expected_executable_path) `
                    -RequiredCommandLineMarkers @($stageState.watchdog_command_markers) | Out-Null
            }
            $affectedWorkers = @($startedWorkers)
            if ($null -ne $currentLaunchingWorker -and
                [string]$currentLaunchingWorker.id -notin @(
                    $affectedWorkers | ForEach-Object { [string]$_.id }
                )) {
                $affectedWorkers += $currentLaunchingWorker
            }
            foreach ($started in $affectedWorkers) {
                if (Test-WorkerProcessIdentity $started) {
                    Stop-Wave3ProcessTree -ProcessId ([int]$started.pid) `
                        -ExpectedStartUtc ([string]$started.process_start_utc) `
                        -ExpectedExecutablePath ([string]$started.expected_executable_path) `
                        -RequiredCommandLineMarkers @($started.command_line_markers) | Out-Null
                }
                elseif ($started -eq $currentLaunchingWorker -and
                    $null -ne $currentProcess -and -not $currentProcess.HasExited) {
                    # This exact Process object was returned by our launch but
                    # state publication failed before identity became usable.
                    $currentProcess.Kill($true)
                    $currentProcess.WaitForExit()
                }
                Set-WorkerLaunchFailure -WorkerState $started `
                    -Reason $launchFailureReason -FailedUtc $failedUtc
            }
            $stageState.status = 'launch_failed'
            $stageState.stopped_utc = $failedUtc
            $stageState.stop_reason = "worker_launch_failed:$launchFailureReason"
            Write-State $state $validation
            throw
        }
        # The watchdog cannot authenticate while StartStage owns the run lock.
        # Release it, then require a PID-bound heartbeat before reporting a
        # successful launch to the caller.
        $lock.Dispose()
        $lock = $null
        Complete-WatchdogStartupHandshake `
            -Validation $validation -TrustedState $state `
            -TrustedStageState $stageState -WatchdogProcess $watchdogProcess `
            -TimeoutSeconds $watchdogStartupHandshakeSeconds | Out-Null
        Write-Output "started_stage=$Stage workers=$($workerConfigs.Count) run=$runRoot"
        $startRows = @($state.workers | Where-Object stage -eq $Stage | ForEach-Object {
            [pscustomobject]@{
                id = $_.id
                role = $_.role
                pid = $_.pid
                status = $_.status
                max_tokens = $_.budget.max_tokens
                timeout_seconds = $_.budget.timeout_seconds
                max_tool_calls = $_.budget.max_tool_calls
                artifact_checkpoint_tool_calls = if (
                    $null -ne $_.budget.PSObject.Properties['artifact_checkpoint_tool_calls']
                ) { $_.budget.artifact_checkpoint_tool_calls } else { $null }
                session_id = $_.session_id
            }
        })
        Write-Output (($startRows | Format-Table -AutoSize | Out-String).TrimEnd())
    }
    finally {
        if ($null -ne $lock) { $lock.Dispose() }
    }
}

function Get-WatchdogHealth($StageState, [datetimeoffset]$NowUtc) {
    if ([string]$StageState.status -notin @('launching', 'running')) {
        return [pscustomobject]@{ healthy = $true; status = 'not_required'; heartbeat_age_seconds = $null }
    }
    $identity = Get-WatchdogProcessIdentity $StageState
    if (-not $identity.trusted) {
        return [pscustomobject]@{
            healthy = $false
            status = "identity_failure:$($identity.reason)"
            heartbeat_age_seconds = $null
        }
    }
    if ([string]::IsNullOrWhiteSpace([string]$StageState.watchdog_heartbeat_file) -or
        -not (Test-Path -LiteralPath $StageState.watchdog_heartbeat_file -PathType Leaf)) {
        return [pscustomobject]@{ healthy = $false; status = 'heartbeat_missing'; heartbeat_age_seconds = $null }
    }
    try {
        $heartbeat = Get-Content -LiteralPath $StageState.watchdog_heartbeat_file -Raw |
            ConvertFrom-Json -Depth 20
        $updated = [datetimeoffset]::Parse([string]$heartbeat.updated_utc).ToUniversalTime()
        $age = [math]::Max(0.0, ($NowUtc.ToUniversalTime() - $updated).TotalSeconds)
        if ([string]$heartbeat.stage -cne [string]$StageState.id -or
            [int]$heartbeat.pid -ne [int]$StageState.watchdog_pid) {
            return [pscustomobject]@{ healthy = $false; status = 'heartbeat_identity_mismatch'; heartbeat_age_seconds = $age }
        }
        if ($age -gt $watchdogHeartbeatMaxAgeSeconds) {
            return [pscustomobject]@{ healthy = $false; status = 'heartbeat_stale'; heartbeat_age_seconds = $age }
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$StageState.watchdog_error_file) -and
            (Test-Path -LiteralPath $StageState.watchdog_error_file -PathType Leaf)) {
            return [pscustomobject]@{ healthy = $false; status = 'watchdog_error_sidecar'; heartbeat_age_seconds = $age }
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$StageState.watchdog_exit_file) -and
            (Test-Path -LiteralPath $StageState.watchdog_exit_file -PathType Leaf)) {
            return [pscustomobject]@{ healthy = $false; status = 'watchdog_exited_while_stage_active'; heartbeat_age_seconds = $age }
        }
        return [pscustomobject]@{
            healthy = $true
            status = [string]$heartbeat.phase
            heartbeat_age_seconds = $age
        }
    }
    catch {
        return [pscustomobject]@{
            healthy = $false
            status = "heartbeat_invalid:$($_.Exception.Message)"
            heartbeat_age_seconds = $null
        }
    }
}

function Status-Action {
    $validation = Get-ValidatedConfig
    $state = Read-State
    Assert-StateMatchesConfig $state $validation
    $rows = foreach ($worker in $state.workers) {
        $status = Get-LiveWorkerStatus $worker
        [pscustomobject]@{
            id = $worker.id
            stage = $worker.stage
            role = $worker.role
            status = $status
            pid = $worker.pid
            attempt = $worker.attempt
            total_tokens = if ($null -ne $worker.last_metrics) { $worker.last_metrics.total_tokens } else { 0 }
            tool_calls = if ($null -ne $worker.last_metrics) { $worker.last_metrics.tool_calls } else { 0 }
            completed_tool_calls = if ($null -ne $worker.last_metrics) {
                $worker.last_metrics.completed_tool_calls
            } else { 0 }
            output_bytes = if (-not [string]::IsNullOrWhiteSpace([string]$worker.output_file) -and
                (Test-Path -LiteralPath $worker.output_file -PathType Leaf)) {
                (Get-Item -LiteralPath $worker.output_file).Length
            } else { 0 }
            max_tokens = $worker.budget.max_tokens
            timeout_seconds = $worker.budget.timeout_seconds
            max_tool_calls = $worker.budget.max_tool_calls
            artifact_checkpoint_tool_calls = if (
                $null -ne $worker.budget.PSObject.Properties['artifact_checkpoint_tool_calls']
            ) { $worker.budget.artifact_checkpoint_tool_calls } else { $null }
            stop_reason = $worker.stop_reason
        }
    }
    $rows | Format-Table -AutoSize
    $rows | Group-Object stage, status | Sort-Object Name |
        Select-Object Name, Count | Format-Table -AutoSize
    $now = [datetimeoffset]::UtcNow
    $watchdogRows = @($state.stages | ForEach-Object {
        $health = Get-WatchdogHealth $_ $now
        [pscustomobject]@{
            stage = $_.id
            stage_status = $_.status
            watchdog_pid = $_.watchdog_pid
            healthy = $health.healthy
            health_status = $health.status
            heartbeat_age_seconds = $health.heartbeat_age_seconds
        }
    })
    $watchdogRows | Format-Table -AutoSize
    $unwatchedLiveWorkers = @($state.stages | Where-Object {
        $stageState = $_
        $health = Get-WatchdogHealth $stageState $now
        -not $health.healthy -and @($rows | Where-Object {
            $_.stage -eq $stageState.id -and $_.status -eq 'running'
        }).Count
    })
    if ($unwatchedLiveWorkers.Count) {
        Write-Error "Live workers have no healthy watchdog: $(@($unwatchedLiveWorkers.id) -join ', ')"
    }
    $failedWatchdogStages = @($state.stages | Where-Object status -eq 'watchdog_failed')
    if ($failedWatchdogStages.Count) {
        Write-Error "Watchdog failure is recorded for stages: $(@($failedWatchdogStages.id) -join ', ')"
    }
    if ($unwatchedLiveWorkers.Count -or $failedWatchdogStages.Count -or
        @($rows | Where-Object status -in @(
        'failed', 'lost', 'launch_failed', 'budget_exceeded', 'identity_mismatch', 'stopped'
    )).Count) { exit 1 }
}

function Validate-Action {
    $validation = Get-ValidatedConfig
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        Write-Output "config_valid=$($validation.config_path) workers=20 token_budget=$($validation.total_token_budget) sha256=$($validation.config_sha256)"
        return
    }
    $lock = Open-RunLock
    try {
        $state = Read-State
        Assert-StateMatchesConfig $state $validation
        $targets = @(if ([string]::IsNullOrWhiteSpace($Stage)) {
            @($state.stages | ForEach-Object {
                $stageRecord = $_
                if ([string]$stageRecord.status -eq 'validated') {
                    [string]$stageRecord.id
                }
                elseif ([string]$stageRecord.status -ne 'pending') {
                    $workerStatuses = @($state.workers | Where-Object stage -eq $stageRecord.id |
                        ForEach-Object { Get-LiveWorkerStatus $_ })
                    if ($workerStatuses.Count -and
                        @($workerStatuses | Where-Object { $_ -ne 'completed' }).Count -eq 0) {
                        [string]$stageRecord.id
                    }
                }
            })
        }
        else { $Stage })
        if (-not $targets.Count) {
            Write-Output "config_valid=$($validation.config_path) no_completed_stage=true"
            return
        }
        foreach ($stageId in $targets) {
            $result = Validate-Stage $state $validation $stageId
            Write-Output "validated_stage=$stageId manifest=$($result.manifest_file) sha256=$($result.manifest_sha256)"
        }
    }
    finally {
        $lock.Dispose()
    }
}

function Stop-Action {
    $validation = Get-ValidatedConfig
    $lock = Open-RunLock
    try {
        $state = Read-State
        Assert-StateMatchesConfig $state $validation
        $targets = if ([string]::IsNullOrWhiteSpace($Stage)) {
            @($state.workers)
        }
        else { @($state.workers | Where-Object stage -eq $Stage) }
        $stopped = 0
        foreach ($worker in $targets) {
            if ((Get-LiveWorkerStatus $worker) -eq 'running') {
                if (Stop-Wave3ProcessTree -ProcessId ([int]$worker.pid) `
                    -ExpectedStartUtc ([string]$worker.process_start_utc) `
                    -ExpectedExecutablePath ([string]$worker.expected_executable_path) `
                    -RequiredCommandLineMarkers @($worker.command_line_markers)) {
                    $stopped++
                }
                $worker.status = 'stopped'
                $worker.stopped_utc = Get-UtcNowText
                $worker.stop_reason = 'manual_stop'
                $worker.budget_exceeded = $null
            }
        }
        foreach ($stageRecord in $state.stages) {
            if (([string]::IsNullOrWhiteSpace($Stage) -or $stageRecord.id -eq $Stage) -and
                @($state.workers | Where-Object { $_.stage -eq $stageRecord.id -and $_.status -eq 'stopped' }).Count) {
                $stageRecord.status = 'stopped'
                $stageRecord.stopped_utc = Get-UtcNowText
                $stageRecord.stop_reason = 'manual_stop'
                $stageRecord.watchdog_stopped_utc = Get-UtcNowText
            }
        }
        Write-State $state $validation
        Write-Output "stopped=$stopped run=$runRoot"
    }
    finally {
        $lock.Dispose()
    }
}

function Collect-Action {
    $lock = Open-RunLock
    try {
        $state = Read-State
        $validation = Get-ValidatedConfig
        Assert-StateMatchesConfig $state $validation
        $notValidated = @($state.stages | Where-Object status -ne 'validated')
        if ($notValidated.Count) {
            throw "Cannot collect until all stages validate: $(@($notValidated.id) -join ', ')"
        }

        $stageEntries = @()
        $reportDocuments = @()
        $totals = [ordered]@{
            total_tokens = [int64]0
            input_tokens = [int64]0
            output_tokens = [int64]0
            cache_read_tokens = [int64]0
            assistant_turns = [int64]0
            tool_calls = [int64]0
            completed_tool_calls = [int64]0
        }
        foreach ($stageRecord in $state.stages | Sort-Object { @('E','O','I','R','G').IndexOf($_.id) }) {
            if (-not (Test-Path -LiteralPath $stageRecord.manifest_file -PathType Leaf)) {
                throw "Stage manifest is missing: $($stageRecord.id)"
            }
            if ((Get-Wave3Sha256 -LiteralPath $stageRecord.manifest_file) -cne
                [string]$stageRecord.manifest_sha256) {
                throw "Stage manifest changed after validation: $($stageRecord.id)"
            }
            $manifest = Get-Content -LiteralPath $stageRecord.manifest_file -Raw | ConvertFrom-Json -Depth 100
            foreach ($workerEntry in $manifest.workers) {
                $workerState = Get-StateWorker $state ([string]$workerEntry.id)
                Assert-ContextManifestCurrent $workerState | Out-Null
                foreach ($artifact in $workerEntry.artifacts) {
                    $absolutePath = Resolve-Wave3ContainedPath -Root $runRoot `
                        -RelativePath ([string]$artifact.path) -MustExist -PathType Leaf
                    if ((Get-Wave3Sha256 -LiteralPath $absolutePath) -cne [string]$artifact.sha256) {
                        throw "Validated artifact changed: $($workerEntry.id)/$($artifact.name)"
                    }
                    if ($workerState.stage -in @('E', 'O', 'R') -and $artifact.format -eq 'json') {
                        $reportDocuments += Get-Content -LiteralPath $absolutePath -Raw | ConvertFrom-Json -Depth 100
                    }
                }
                foreach ($name in @(
                    'total_tokens','input_tokens','output_tokens','cache_read_tokens',
                    'assistant_turns','tool_calls','completed_tool_calls'
                )) {
                    $totals[$name] += [int64]$workerEntry.metrics.$name
                }
            }
            $stageEntries += [ordered]@{
                stage = [string]$stageRecord.id
                path = Get-RunRelativePath ([string]$stageRecord.manifest_file)
                sha256 = [string]$stageRecord.manifest_sha256
            }
        }

        $collection = [ordered]@{
            schema_version = 1
            run_id = $RunId
            model = [string]$state.model
            config_sha256 = [string]$state.config_sha256
            generated_utc = Get-UtcNowText
            stage_manifests = @($stageEntries)
            totals = $totals
        }
        $collectionPath = Join-Path $runRoot 'collection_manifest.json'
        $reportsPath = Join-Path $runRoot 'collected_reports.json'
        Write-Wave3AtomicJson -LiteralPath $reportsPath -Value @($reportDocuments)
        $collection.collected_reports = [ordered]@{
            path = Get-RunRelativePath $reportsPath
            sha256 = Get-Wave3Sha256 -LiteralPath $reportsPath
        }
        Write-Wave3AtomicJson -LiteralPath $collectionPath -Value $collection
        Write-Output "collected=$collectionPath sha256=$(Get-Wave3Sha256 -LiteralPath $collectionPath) workers=20"
    }
    finally {
        $lock.Dispose()
    }
}

if ($MyInvocation.InvocationName -eq '.') {
    return
}

switch ($Action) {
    'StartStage' { Start-StageAction }
    'Status' { Status-Action }
    'Validate' { Validate-Action }
    'Collect' { Collect-Action }
    'Stop' { Stop-Action }
    'Watchdog' { Watchdog-Action }
}
