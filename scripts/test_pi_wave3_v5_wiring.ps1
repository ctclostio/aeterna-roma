#requires -Version 7.4

[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Join-Path $PSScriptRoot '..')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$modulePath = Join-Path $PSScriptRoot 'pi_wave3_common.psm1'
$oldSchemaPath = Join-Path $PSScriptRoot 'pi_wave3_config.schema.json'
$schemaPath = Join-Path $PSScriptRoot 'pi_wave3_config_v2.schema.json'
$oldWorkerPath = Join-Path $PSScriptRoot 'pi_swarm_worker.ps1'
$workerPath = Join-Path $PSScriptRoot 'pi_swarm_worker_v2.ps1'
$oldSupervisorPath = Join-Path $PSScriptRoot 'pi_wave3_supervisor.ps1'
$supervisorPath = Join-Path $PSScriptRoot 'pi_wave3_supervisor_v2.ps1'
$testsPath = Join-Path $PSScriptRoot 'pi_wave3_tests_v2.ps1'
$v4ConfigPath = Join-Path $PSScriptRoot 'pi_wave3_startup_abi_v4.json'
$v5ConfigPath = Join-Path $PSScriptRoot 'pi_wave3_startup_abi_v5.json'
$oldGatePath = Join-Path $PSScriptRoot 'pi_startup_abi_oracle_gate.py'
$v2GatePath = Join-Path $PSScriptRoot 'pi_startup_abi_oracle_gate_v2.py'
$oldGateTestPath = Join-Path $PSScriptRoot 'test_pi_startup_abi_oracle_gate.py'
$successorModel = 'openrouter/z-ai/glm-5.3-flash'
$retiredModel = 'openrouter/stealth/ox-alpha'
$expectedOriginalHashes = [ordered]@{
    'pi_wave3_config.schema.json' = '44a2bb400290047ef1b6d373da37729e9e6f0d893cc1c25740f577996dfc53d0'
    'pi_wave3_startup_abi_v4.json' = '7c8ad99ccc1de8d70399a706dd88700f027de5faf5c78844cbed6f5cc6bdb178'
    'pi_wave3_supervisor.ps1' = 'bfc2c5837ebb5492f5d0a71aaed09050958bc7cac4e617864a06f0e17a280b04'
    'pi_wave3_common.psm1' = '4be923af906ad11573d761e8794598dd118b37c915f5a4958eace8dea1ca7213'
    'pi_swarm_worker.ps1' = '1d8b612ae33c826dbbf211748913f6ea012f28322078abc275185d5c66a8aaec'
    'pi_startup_abi_oracle_gate.py' = '18ad404b4fc54cce5c1130a1296b377a3828be50ee1f56ca28e2bdde32dfaf9d'
    'test_pi_startup_abi_oracle_gate.py' = '69bf1052b6624a027de9c4782e468c34a158d9204ffee8b5a9a144593f22808d'
}
Import-Module -Name $modulePath -Force
$script:Passed = 0
$script:Failed = 0
$script:Skipped = 0

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

function Skip-Test([string]$Name, [string]$Reason) {
    $script:Skipped++
    Write-Output "SKIP $Name`: $Reason"
}

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-Contains([string]$Text, [string]$Needle, [string]$Message) {
    Assert-True $Text.Contains($Needle, [System.StringComparison]::Ordinal) $Message
}

function Assert-Throws([scriptblock]$Body, [string]$Message) {
    $caught = $false
    try { & $Body } catch { $caught = $true }
    Assert-True $caught $Message
}

Invoke-Test 'frozen v4 harness and oracle authorities remain byte-identical' {
    foreach ($entry in $expectedOriginalHashes.GetEnumerator()) {
        $path = Join-Path $PSScriptRoot $entry.Key
        Assert-True (Test-Path -LiteralPath $path -PathType Leaf) "Missing frozen $($entry.Key)"
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
        Assert-True ($actual -eq $entry.Value) "Frozen authority changed: $($entry.Key)"
    }
}

Invoke-Test 'all v2 harness files exist and parse' {
    foreach ($path in @($schemaPath, $workerPath, $supervisorPath, $testsPath)) {
        Assert-True (Test-Path -LiteralPath $path -PathType Leaf) "Missing $path"
    }
    foreach ($path in @($workerPath, $supervisorPath, $testsPath, $PSCommandPath)) {
        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile(
            $path, [ref]$tokens, [ref]$errors
        ) | Out-Null
        Assert-True ($errors.Count -eq 0) "$path has parser errors"
    }
}

Invoke-Test 'v2 schema pins the exact successor model' {
    $schema = Get-Content -LiteralPath $schemaPath -Raw | ConvertFrom-Json -Depth 100
    Assert-True ($schema.'$id' -eq 'https://local.invalid/pi-wave3/config-v2.schema.json') `
        'Unexpected v2 schema ID'
    Assert-True ($schema.title -eq 'Pi wave 3 orchestration configuration v2') `
        'Unexpected v2 schema title'
    Assert-True ($schema.properties.model.const -eq $successorModel) `
        'V2 schema does not pin the exact successor model'
}

Invoke-Test 'old and v2 schemas accept only their matching frozen configs' {
    $v4 = Read-Wave3Config -ConfigPath $v4ConfigPath -SchemaPath $oldSchemaPath `
        -RepositoryRoot $repositoryRoot
    $v5 = Read-Wave3Config -ConfigPath $v5ConfigPath -SchemaPath $schemaPath `
        -RepositoryRoot $repositoryRoot
    Assert-True ($v4.config.model -eq $retiredModel) 'Old schema did not preserve the v4 model'
    Assert-True ($v5.config.model -eq $successorModel) 'V2 schema did not preserve the v5 model'
    Assert-True ($v5.config.workers.Count -eq 20) 'V5 worker count changed'
    Assert-True ($v5.total_token_budget -eq 3480000) 'V5 total token budget changed'
    Assert-Throws {
        Read-Wave3Config -ConfigPath $v5ConfigPath -SchemaPath $oldSchemaPath `
            -RepositoryRoot $repositoryRoot | Out-Null
    } 'Old schema accepted the successor config'
    Assert-Throws {
        Read-Wave3Config -ConfigPath $v4ConfigPath -SchemaPath $schemaPath `
            -RepositoryRoot $repositoryRoot | Out-Null
    } 'V2 schema accepted the retired config'
}

Invoke-Test 'worker requires Model and forwards it without a retired fallback' {
    $command = Get-Command $workerPath
    $parameter = $command.Parameters['Model']
    Assert-True ($null -ne $parameter) 'Worker is missing Model parameter'
    Assert-True (@($parameter.Attributes | Where-Object {
        $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory
    }).Count -gt 0) 'Worker Model parameter is not mandatory'
    $source = Get-Content -LiteralPath $workerPath -Raw
    Assert-Contains $source "'--model', `$Model," 'Worker does not forward Model to Pi'
    Assert-True (-not $source.Contains($retiredModel, [System.StringComparison]::Ordinal)) `
        'Worker retains the retired model alias'
}

Invoke-Test 'supervisor uses only v2 harness paths and passes config.model' {
    $source = Get-Content -LiteralPath $supervisorPath -Raw
    Assert-Contains $source "'pi_wave3_startup_abi_v5.json'" `
        'Supervisor default is not the v5 config'
    Assert-Contains $source "'pi_wave3_config_v2.schema.json'" `
        'Supervisor does not use the v2 config schema'
    Assert-Contains $source "'pi_swarm_worker_v2.ps1'" `
        'Supervisor does not use the v2 worker'
    Assert-Contains $source "'-Model', `$Model," `
        'Supervisor does not pass Model to the worker command'
    Assert-Contains $source `
        'Start-WorkerProcess $workerConfig $workerState ([string]$config.model)' `
        'Supervisor launch does not source Model from the validated config'
    Assert-True (-not $source.Contains($retiredModel, [System.StringComparison]::Ordinal)) `
        'Supervisor retains the retired model alias'
}

Invoke-Test 'versioned regression suite targets only the v2 harness' {
    $source = Get-Content -LiteralPath $testsPath -Raw
    foreach ($name in @(
        'pi_wave3_config_v2.schema.json',
        'pi_wave3_supervisor_v2.ps1',
        'pi_swarm_worker_v2.ps1',
        $successorModel
    )) {
        Assert-Contains $source $name "Versioned regression suite is missing $name"
    }
    $retiredMentions = @([regex]::Matches(
        $source,
        [regex]::Escape($retiredModel),
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    ))
    Assert-True ($retiredMentions.Count -eq 1) `
        'Retired alias must appear exactly once as a rejection fixture'
    Assert-Contains $source "`$retired.model = '$retiredModel'" `
        'Retired alias is not confined to the rejection fixture'
}

if (Test-Path -LiteralPath $v5ConfigPath -PathType Leaf) {
    Invoke-Test 'v5 differs from v4 by exactly four frozen leaf values' {
        $v4 = Get-Content -LiteralPath $v4ConfigPath -Raw | ConvertFrom-Json -Depth 100
        $config = Get-Content -LiteralPath $v5ConfigPath -Raw | ConvertFrom-Json -Depth 100
        Assert-True ($config.'$schema' -eq 'scripts/pi_wave3_config_v2.schema.json') `
            'V5 config does not select the v2 schema'
        Assert-True ($config.model -eq $successorModel) `
            'V5 config does not select the exact successor model'
        $oGate = @($config.semantic_gates | Where-Object stage -eq 'O')
        Assert-True ($oGate.Count -eq 1) 'V5 must contain exactly one O semantic gate'
        Assert-True ($oGate[0].script -eq 'scripts/pi_startup_abi_oracle_gate_v2.py') `
            'V5 does not select the v2 oracle gate'
        $liveGateHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $v2GatePath).Hash.ToLowerInvariant()
        Assert-True ($oGate[0].script_sha256 -eq $liveGateHash) `
            'V5 oracle-gate hash does not match the live v2 gate'
        Assert-True ($config.workers.Count -eq 20) 'V5 must retain exactly twenty configured roles'
        Assert-True (@($config.workers | Where-Object thinking -ne 'high').Count -eq 0) `
            'Every v5 role must explicitly request high thinking'

        $normalized = $config | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100
        $normalized.'$schema' = $v4.'$schema'
        $normalized.model = $v4.model
        $normalizedOGate = @($normalized.semantic_gates | Where-Object stage -eq 'O')
        $v4OGate = @($v4.semantic_gates | Where-Object stage -eq 'O')
        $normalizedOGate[0].script = $v4OGate[0].script
        $normalizedOGate[0].script_sha256 = $v4OGate[0].script_sha256
        $expected = $v4 | ConvertTo-Json -Depth 100 -Compress
        $actual = $normalized | ConvertTo-Json -Depth 100 -Compress
        Assert-True ($actual -ceq $expected) 'V5 contains changes beyond the four admitted leaf values'
    }
}
else {
    Skip-Test 'v5 differs from v4 by exactly four frozen leaf values' `
        'v5 config has not been frozen yet'
}

if (Test-Path -LiteralPath $v2GatePath -PathType Leaf) {
    Invoke-Test 'v2 oracle gate targets the v5 config' {
        $source = Get-Content -LiteralPath $v2GatePath -Raw
        Assert-Contains $source 'scripts/pi_wave3_startup_abi_v5.json' `
            'V2 oracle gate does not target the v5 config'
    }
}
else {
    Skip-Test 'v2 oracle gate targets the v5 config' 'v2 oracle gate has not been frozen yet'
}

Write-Output "passed=$script:Passed failed=$script:Failed skipped=$script:Skipped"
if ($script:Failed -gt 0) { exit 1 }
