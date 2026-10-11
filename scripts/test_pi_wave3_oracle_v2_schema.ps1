param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$schemaPath = Join-Path $RepositoryRoot 'scripts/pi_wave3_oracle_v2.schema.json'

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Copy-Document([object]$Document) {
    return $Document | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
}

function Test-Document([object]$Document) {
    $json = $Document | ConvertTo-Json -Depth 20
    return Test-Json -Json $json -SchemaFile $schemaPath -ErrorAction SilentlyContinue
}

$tests = @()
$mutants = @()
foreach ($number in 1..8) {
    $tests += [ordered]@{
        test_id = "O01.T$number"
        requirement_ids = @('ABI-ORACLE-001')
        description = "test $number"
        procedure = "procedure $number"
        expected = "expected $number"
        mutant_ids = @("O01.M$number")
    }
    $mutants += [ordered]@{
        mutant_id = "O01.M$number"
        critical = $true
        description = "mutant $number"
        expected_killer_ids = @("O01.T$number")
    }
}

$baseline = [ordered]@{
    worker_id = 'O01'
    stage = 'O'
    tests = $tests
    mutants = $mutants
    blockers = @()
}

# This schema checks transport shape only. Cross-array reciprocity and semantic
# correctness remain the responsibility of downstream validation.
Assert-True (Test-Document $baseline) 'minimal reciprocal 8/8 oracle document must pass schema v2'

$sevenTests = Copy-Document $baseline
$sevenTests.tests = @($sevenTests.tests | Select-Object -First 7)
Assert-True (-not (Test-Document $sevenTests)) 'seven tests must fail schema v2'

$nineTests = Copy-Document $baseline
$extraTest = Copy-Document $nineTests.tests[0]
$extraTest.test_id = 'O01.T9'
$extraTest.mutant_ids = @('O01.M9')
$nineTests.tests = @($nineTests.tests) + @($extraTest)
Assert-True (-not (Test-Document $nineTests)) 'nine tests must fail schema v2'

$sevenMutants = Copy-Document $baseline
$sevenMutants.mutants = @($sevenMutants.mutants | Select-Object -First 7)
Assert-True (-not (Test-Document $sevenMutants)) 'seven mutants must fail schema v2'

$nineMutants = Copy-Document $baseline
$extraMutant = Copy-Document $nineMutants.mutants[0]
$extraMutant.mutant_id = 'O01.M9'
$extraMutant.expected_killer_ids = @('O01.T9')
$nineMutants.mutants = @($nineMutants.mutants) + @($extraMutant)
Assert-True (-not (Test-Document $nineMutants)) 'nine mutants must fail schema v2'

$nonemptyBlockers = Copy-Document $baseline
$nonemptyBlockers.blockers = @('not admitted')
Assert-True (-not (Test-Document $nonemptyBlockers)) 'nonempty blockers must fail schema v2'

$zeroMutantLinks = Copy-Document $baseline
$zeroMutantLinks.tests[0].mutant_ids = @()
Assert-True (-not (Test-Document $zeroMutantLinks)) 'zero mutant links must fail schema v2'

$twoMutantLinks = Copy-Document $baseline
$twoMutantLinks.tests[0].mutant_ids = @('O01.M1', 'O01.M2')
Assert-True (-not (Test-Document $twoMutantLinks)) 'two mutant links must fail schema v2'

$zeroKillerLinks = Copy-Document $baseline
$zeroKillerLinks.mutants[0].expected_killer_ids = @()
Assert-True (-not (Test-Document $zeroKillerLinks)) 'zero expected-killer links must fail schema v2'

$twoKillerLinks = Copy-Document $baseline
$twoKillerLinks.mutants[0].expected_killer_ids = @('O01.T1', 'O01.T2')
Assert-True (-not (Test-Document $twoKillerLinks)) 'two expected-killer links must fail schema v2'

Write-Output 'pi wave3 oracle schema v2 tests passed'
