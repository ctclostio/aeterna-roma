param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$schemaPath = Join-Path $RepositoryRoot 'scripts/pi_wave3_oracle_v3.schema.json'
$mutationFields = @(
    'subject_kind',
    'subject_path',
    'operation',
    'locus',
    'before',
    'after'
)

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Copy-Document([object]$Document) {
    return $Document | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30
}

function Test-Document([object]$Document) {
    $json = $Document | ConvertTo-Json -Depth 30
    return Test-Json -Json $json -SchemaFile $schemaPath -ErrorAction SilentlyContinue
}

function Remove-Property([object]$Object, [string]$Name) {
    $Object.PSObject.Properties.Remove($Name)
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
        description = "EXACT_SINGLE_MUTATION: O01_M${number}_REPLACE_VALUE"
        mutation = [ordered]@{
            subject_kind = 'json_field'
            subject_path = 'scripts/frozen_authority.json'
            operation = 'replace'
            locus = "/facts/$($number - 1)/value"
            before = "pristine-$number"
            after = "mutated-$number"
        }
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

# The schema checks transport shape only. Cross-array reciprocity and semantic
# correctness remain the responsibility of downstream validation.
Assert-True (Test-Document $baseline) 'complete exact 8/8 oracle document must pass schema v3'

foreach ($field in $mutationFields) {
    $missingField = Copy-Document $baseline
    Remove-Property $missingField.mutants[0].mutation $field
    Assert-True (-not (Test-Document $missingField)) `
        "mutation missing $field must fail schema v3"
}

foreach ($field in $mutationFields) {
    $emptyField = Copy-Document $baseline
    $emptyField.mutants[0].mutation.$field = ''
    Assert-True (-not (Test-Document $emptyField)) `
        "empty mutation field $field must fail schema v3"
}

foreach ($field in $mutationFields) {
    $nonStringField = Copy-Document $baseline
    $nonStringField.mutants[0].mutation.$field = 7
    Assert-True (-not (Test-Document $nonStringField)) `
        "non-string mutation field $field must fail schema v3"
}

$extraMutationField = Copy-Document $baseline
$extraMutationField.mutants[0].mutation | Add-Member -NotePropertyName note -NotePropertyValue 'not allowed'
Assert-True (-not (Test-Document $extraMutationField)) `
    'extra nested mutation field must fail schema v3'

$extraMutantKey = Copy-Document $baseline
$extraMutantKey.mutants[0] | Add-Member -NotePropertyName mutation_prose -NotePropertyValue 'not allowed'
Assert-True (-not (Test-Document $extraMutantKey)) `
    'extra mutant key must fail schema v3'

$proseMutation = Copy-Document $baseline
$proseMutation.mutants[0].mutation = 'replace the pristine value with the mutant value'
Assert-True (-not (Test-Document $proseMutation)) `
    'prose in place of the exact nested mutation object must fail schema v3'

$v2ShapedMutant = Copy-Document $baseline
Remove-Property $v2ShapedMutant.mutants[0] 'mutation'
Assert-True (-not (Test-Document $v2ShapedMutant)) `
    'v2-shaped mutant without mutation must fail schema v3'

$sevenTests = Copy-Document $baseline
$sevenTests.tests = @($sevenTests.tests | Select-Object -First 7)
Assert-True (-not (Test-Document $sevenTests)) 'seven tests must fail schema v3'

$nineTests = Copy-Document $baseline
$extraTest = Copy-Document $nineTests.tests[0]
$extraTest.test_id = 'O01.T9'
$extraTest.mutant_ids = @('O01.M9')
$nineTests.tests = @($nineTests.tests) + @($extraTest)
Assert-True (-not (Test-Document $nineTests)) 'nine tests must fail schema v3'

$sevenMutants = Copy-Document $baseline
$sevenMutants.mutants = @($sevenMutants.mutants | Select-Object -First 7)
Assert-True (-not (Test-Document $sevenMutants)) 'seven mutants must fail schema v3'

$nineMutants = Copy-Document $baseline
$extraMutant = Copy-Document $nineMutants.mutants[0]
$extraMutant.mutant_id = 'O01.M9'
$extraMutant.expected_killer_ids = @('O01.T9')
$nineMutants.mutants = @($nineMutants.mutants) + @($extraMutant)
Assert-True (-not (Test-Document $nineMutants)) 'nine mutants must fail schema v3'

$nonemptyBlockers = Copy-Document $baseline
$nonemptyBlockers.blockers = @('not admitted')
Assert-True (-not (Test-Document $nonemptyBlockers)) 'nonempty blockers must fail schema v3'

$zeroMutantLinks = Copy-Document $baseline
$zeroMutantLinks.tests[0].mutant_ids = @()
Assert-True (-not (Test-Document $zeroMutantLinks)) 'zero mutant links must fail schema v3'

$twoMutantLinks = Copy-Document $baseline
$twoMutantLinks.tests[0].mutant_ids = @('O01.M1', 'O01.M2')
Assert-True (-not (Test-Document $twoMutantLinks)) 'two mutant links must fail schema v3'

$zeroKillerLinks = Copy-Document $baseline
$zeroKillerLinks.mutants[0].expected_killer_ids = @()
Assert-True (-not (Test-Document $zeroKillerLinks)) 'zero expected-killer links must fail schema v3'

$twoKillerLinks = Copy-Document $baseline
$twoKillerLinks.mutants[0].expected_killer_ids = @('O01.T1', 'O01.T2')
Assert-True (-not (Test-Document $twoKillerLinks)) 'two expected-killer links must fail schema v3'

Write-Output 'pi wave3 oracle schema v3 tests passed'
