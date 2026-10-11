param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$schemaPath = Join-Path $RepositoryRoot 'scripts/pi_wave3_abi_evidence_v2.schema.json'
$configPath = Join-Path $RepositoryRoot 'scripts/pi_wave3_startup_abi_v3.json'

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Test-Document([object]$Document) {
    $json = $Document | ConvertTo-Json -Depth 20
    return Test-Json -Json $json -SchemaFile $schemaPath -ErrorAction SilentlyContinue
}

$baseline = [ordered]@{
    worker_id = 'E01'
    stage = 'E'
    conclusion = 'closed-world fixture'
    claims = @(
        [ordered]@{
            fact_id = 'E01.fixture'
            kind = 'contract'
            value = 'FIXTURE'
            source_path = 'fixture.txt'
            source_sha256 = ('0' * 64)
            locator = 'complete source'
            extractor_command = 'read {"path":"fixture.txt","offset":0,"limit":20000}'
            inference = $false
        }
    )
    blockers = @()
}

Assert-True (Test-Document $baseline) 'baseline evidence document must pass schema v2'

$badLocator = $baseline | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
$badLocator.claims[0].locator = 'complete'
Assert-True (-not (Test-Document $badLocator)) 'locator=complete must fail schema v2'

$badKind = $baseline | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
$badKind.claims[0].kind = 'evidence'
Assert-True (-not (Test-Document $badKind)) 'non-contract kind must fail schema v2'

$badBlockers = $baseline | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
$badBlockers.blockers = @('not admitted')
Assert-True (-not (Test-Document $badBlockers)) 'nonempty blockers must fail schema v2'

$config = Get-Content -Raw -LiteralPath $configPath | ConvertFrom-Json -Depth 100
$eWorkers = @($config.workers | Where-Object { $_.stage -eq 'E' })
Assert-True ($eWorkers.Count -eq 4) 'v3 config must retain exactly four E workers'
foreach ($worker in $eWorkers) {
    $outputs = @($worker.required_outputs)
    Assert-True ($outputs.Count -eq 1) "$($worker.id) must retain one evidence output"
    Assert-True (
        $outputs[0].schema -eq 'scripts/pi_wave3_abi_evidence_v2.schema.json'
    ) "$($worker.id) must use evidence schema v2"
}

Write-Output 'pi wave3 ABI evidence schema v2 tests passed'
