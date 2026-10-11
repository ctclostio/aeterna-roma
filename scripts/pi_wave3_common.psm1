#requires -Version 7.4

Set-StrictMode -Version Latest

$script:Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$script:MaxSessionSnapshotBytes = 32 * 1024 * 1024
$script:StageOrder = @('E', 'O', 'I', 'R', 'G')
$script:ExpectedCounts = @{ E = 4; O = 4; I = 6; R = 4; G = 2 }
$script:ExpectedDependencies = @{
    E = @()
    O = @()
    I = @('E', 'O')
    R = @('I')
    G = @('E', 'O', 'I', 'R')
}
$script:StageBudgetCaps = @{
    E = [pscustomobject]@{ tokens = 250000; seconds = 600; tools = 30 }
    O = [pscustomobject]@{ tokens = 350000; seconds = 900; tools = 40 }
    I = [pscustomobject]@{ tokens = 700000; seconds = 1200; tools = 45 }
    R = [pscustomobject]@{ tokens = 300000; seconds = 720; tools = 35 }
    G = [pscustomobject]@{ tokens = 900000; seconds = 1800; tools = 50 }
}

function Get-Wave3Sha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    return (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Write-Wave3AtomicText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text
    )

    $directory = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($LiteralPath))
    [System.IO.Directory]::CreateDirectory($directory) | Out-Null
    $temporary = Join-Path $directory (
        '.' + [System.IO.Path]::GetFileName($LiteralPath) + '.tmp.' +
        $PID + '.' + [guid]::NewGuid().ToString('N')
    )
    $backup = Join-Path $directory (
        '.' + [System.IO.Path]::GetFileName($LiteralPath) + '.bak.' +
        $PID + '.' + [guid]::NewGuid().ToString('N')
    )
    try {
        $options = [System.IO.FileOptions]::WriteThrough
        $stream = [System.IO.FileStream]::new(
            $temporary,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None,
            4096,
            $options
        )
        try {
            $bytes = $script:Utf8NoBom.GetBytes($Text)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }

        if ([System.IO.File]::Exists($LiteralPath)) {
            [System.IO.File]::Replace($temporary, $LiteralPath, $backup, $true)
            [System.IO.File]::Delete($backup)
        }
        else {
            [System.IO.File]::Move($temporary, $LiteralPath)
        }
    }
    finally {
        if ([System.IO.File]::Exists($temporary)) {
            [System.IO.File]::Delete($temporary)
        }
        if ([System.IO.File]::Exists($backup)) {
            [System.IO.File]::Delete($backup)
        }
    }
}

function Write-Wave3AtomicJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)]$Value
    )

    $json = $Value | ConvertTo-Json -Depth 100
    Write-Wave3AtomicText -LiteralPath $LiteralPath -Text ($json + "`n")
}

function Resolve-Wave3ContainedPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [switch]$MustExist,
        [ValidateSet('Any', 'Leaf', 'Container')][string]$PathType = 'Any'
    )

    if ([string]::IsNullOrWhiteSpace($RelativePath)) {
        throw 'A contained path cannot be blank'
    }
    if ([System.IO.Path]::IsPathRooted($RelativePath)) {
        throw "Contained path must be relative: $RelativePath"
    }
    if ($RelativePath.IndexOfAny(@([char]0, [char]10, [char]13)) -ge 0) {
        throw "Contained path contains a forbidden character: $RelativePath"
    }

    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    $candidate = [System.IO.Path]::GetFullPath((Join-Path $rootFull $RelativePath))
    $prefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
    if (-not $candidate.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escapes its allowed root: $RelativePath"
    }

    if ($MustExist) {
        $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
        $normalizedRelative = [System.IO.Path]::GetRelativePath($rootFull, $candidate)
        $walk = $rootFull
        foreach ($segment in $normalizedRelative.Split(
            @([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar),
            [System.StringSplitOptions]::RemoveEmptyEntries
        )) {
            $walk = Join-Path $walk $segment
            $walkItem = Get-Item -LiteralPath $walk -Force -ErrorAction Stop
            if (($walkItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Reparse-point paths are not accepted: $RelativePath"
            }
        }
        if ($PathType -eq 'Leaf' -and -not ($item -is [System.IO.FileInfo])) {
            throw "Expected a file: $RelativePath"
        }
        if ($PathType -eq 'Container' -and -not ($item -is [System.IO.DirectoryInfo])) {
            throw "Expected a directory: $RelativePath"
        }
    }
    return $candidate
}

function Test-Wave3JsonDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$DocumentPath,
        [Parameter(Mandatory = $true)][string]$SchemaPath
    )

    if (-not (Test-Path -LiteralPath $DocumentPath -PathType Leaf)) {
        throw "JSON document does not exist: $DocumentPath"
    }
    if (-not (Test-Path -LiteralPath $SchemaPath -PathType Leaf)) {
        throw "JSON schema does not exist: $SchemaPath"
    }
    $valid = Test-Json -LiteralPath $DocumentPath -SchemaFile $SchemaPath -ErrorAction Stop
    if (-not $valid) {
        throw "JSON document does not satisfy schema: $DocumentPath"
    }
    return $true
}

function Assert-Wave3EvidenceSources {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Document,
        [Parameter(Mandatory = $true)]$ContextManifest
    )

    $admitted = [System.Collections.Generic.Dictionary[string,string]]::new(
        [System.StringComparer]::Ordinal
    )
    foreach ($entry in @($ContextManifest.declared_inputs)) {
        $path = ([string]$entry.path).Replace('\', '/')
        if (-not $admitted.TryAdd($path, [string]$entry.sha256)) {
            throw "Duplicate declared input in context manifest: $path"
        }
    }

    $factIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )
    $workerId = [string]$Document.worker_id
    if ([string]::IsNullOrWhiteSpace($workerId)) {
        throw 'Evidence document has no worker identity'
    }
    foreach ($claim in @($Document.claims)) {
        $factId = [string]$claim.fact_id
        if (-not $factId.StartsWith(
            $workerId + '.', [System.StringComparison]::Ordinal
        )) {
            throw "Evidence fact_id must begin with $workerId."
        }
        if (-not $factIds.Add($factId)) {
            throw "Duplicate evidence fact_id: $factId"
        }
        $sourcePath = [string]$claim.source_path
        if ($sourcePath.Contains('\')) {
            throw "Evidence source_path must use manifest spelling: $sourcePath"
        }
        $expectedHash = $null
        if (-not $admitted.TryGetValue($sourcePath, [ref]$expectedHash)) {
            throw "Evidence claim cites an undeclared source: $sourcePath"
        }
        if ([string]$claim.source_sha256 -cne $expectedHash) {
            throw "Evidence claim has the wrong frozen hash for $sourcePath"
        }
    }
    return $true
}

function Assert-SameStringSet {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [AllowEmptyCollection()][string[]]$Actual,
        [AllowEmptyCollection()][string[]]$Expected
    )
    $actualSorted = @($Actual | Sort-Object -Unique)
    $expectedSorted = @($Expected | Sort-Object -Unique)
    if (($actualSorted -join "`n") -cne ($expectedSorted -join "`n")) {
        throw "$Label must be [$($expectedSorted -join ', ')]; found [$($actualSorted -join ', ')]"
    }
}

function Read-Wave3Config {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][string]$SchemaPath,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot
    )

    $resolvedConfig = (Resolve-Path -LiteralPath $ConfigPath -ErrorAction Stop).Path
    $resolvedSchema = (Resolve-Path -LiteralPath $SchemaPath -ErrorAction Stop).Path
    if (-not (Test-Json -LiteralPath $resolvedConfig -SchemaFile $resolvedSchema -ErrorAction Stop)) {
        throw "Wave-3 configuration does not satisfy schema: $resolvedConfig"
    }
    $config = Get-Content -LiteralPath $resolvedConfig -Raw | ConvertFrom-Json -Depth 100

    Assert-SameStringSet -Label 'stage_order' -Actual @($config.stage_order) -Expected $script:StageOrder
    if ((@($config.stage_order) -join ',') -cne ($script:StageOrder -join ',')) {
        throw "stage_order must be exactly: $($script:StageOrder -join ',')"
    }

    $stageIds = @($config.stages | ForEach-Object { [string]$_.id })
    if (@($stageIds | Sort-Object -Unique).Count -ne 5) {
        throw 'Stage IDs must be unique'
    }
    Assert-SameStringSet -Label 'stage IDs' -Actual $stageIds -Expected $script:StageOrder

    foreach ($stage in $config.stages) {
        $stageId = [string]$stage.id
        if ([int]$stage.worker_count -ne $script:ExpectedCounts[$stageId]) {
            throw "Stage $stageId must declare $($script:ExpectedCounts[$stageId]) workers"
        }
        Assert-SameStringSet -Label "dependencies for stage $stageId" `
            -Actual @($stage.depends_on | ForEach-Object { [string]$_ }) `
            -Expected $script:ExpectedDependencies[$stageId]
    }

    $workerIds = @($config.workers | ForEach-Object { [string]$_.id })
    if (@($workerIds | Sort-Object -Unique).Count -ne 20) {
        throw 'Worker IDs must be unique'
    }
    $roles = @($config.workers | ForEach-Object { [string]$_.role })
    if (@($roles | Sort-Object -Unique).Count -ne 20) {
        throw 'Worker roles must be unique to preserve independent charters'
    }

    $totalTokenBudget = [int64]0
    $writablePaths = @{}
    $implementationIds = @($config.workers | Where-Object stage -eq 'I' | ForEach-Object { [string]$_.id })
    $reviewCoverage = @{}
    foreach ($implementationId in $implementationIds) { $reviewCoverage[$implementationId] = 0 }

    foreach ($stageId in $script:StageOrder) {
        $stageWorkers = @($config.workers | Where-Object stage -eq $stageId)
        if ($stageWorkers.Count -ne $script:ExpectedCounts[$stageId]) {
            throw "Stage $stageId must contain $($script:ExpectedCounts[$stageId]) workers; found $($stageWorkers.Count)"
        }
        $expectedIds = @(1..$script:ExpectedCounts[$stageId] | ForEach-Object { '{0}{1:d2}' -f $stageId, $_ })
        Assert-SameStringSet -Label "worker IDs for stage $stageId" `
            -Actual @($stageWorkers | ForEach-Object { [string]$_.id }) -Expected $expectedIds
    }

    foreach ($worker in $config.workers) {
        $workerId = [string]$worker.id
        $stageId = [string]$worker.stage
        if (-not $workerId.StartsWith($stageId, [System.StringComparison]::Ordinal)) {
            throw "Worker $workerId does not match its stage $stageId"
        }

        $caps = $script:StageBudgetCaps[$stageId]
        if ([int64]$worker.budget.max_tokens -gt $caps.tokens) {
            throw "Worker $workerId exceeds the $stageId token cap of $($caps.tokens)"
        }
        if ([int]$worker.budget.timeout_seconds -gt $caps.seconds) {
            throw "Worker $workerId exceeds the $stageId timeout cap of $($caps.seconds) seconds"
        }
        if ([int]$worker.budget.max_tool_calls -gt $caps.tools) {
            throw "Worker $workerId exceeds the $stageId tool-call cap of $($caps.tools)"
        }
        $artifactCheckpointProperty =
            $worker.budget.PSObject.Properties['artifact_checkpoint_tool_calls']
        if ($null -ne $artifactCheckpointProperty -and
            [int]$artifactCheckpointProperty.Value -gt [int]$worker.budget.max_tool_calls) {
            throw "Worker $workerId artifact_checkpoint_tool_calls cannot exceed max_tool_calls"
        }
        $totalTokenBudget += [int64]$worker.budget.max_tokens

        $outputNames = @($worker.required_outputs | ForEach-Object { [string]$_.name })
        if (@($outputNames | Sort-Object -Unique).Count -ne $outputNames.Count) {
            throw "Worker $workerId has duplicate required-output names"
        }
        foreach ($contextFile in @($worker.context_files)) {
            Resolve-Wave3ContainedPath -Root $RepositoryRoot -RelativePath ([string]$contextFile) | Out-Null
        }
        foreach ($output in $worker.required_outputs) {
            if ($output.source -eq 'workspace') {
                Resolve-Wave3ContainedPath -Root $RepositoryRoot -RelativePath ([string]$output.path) | Out-Null
            }
            elseif ($null -ne $output.PSObject.Properties['path']) {
                throw "Report output $($output.name) for $workerId cannot declare path"
            }
            if ($output.format -eq 'json' -and $null -eq $output.schema) {
                throw "JSON output $($output.name) for $workerId requires a schema"
            }
            if ($output.format -ne 'json' -and $null -ne $output.schema) {
                throw "Only JSON output $($output.name) for $workerId may declare a schema"
            }
            if ($null -ne $output.schema) {
                Resolve-Wave3ContainedPath -Root $RepositoryRoot -RelativePath ([string]$output.schema) | Out-Null
            }
        }
        if ($null -ne $worker.PSObject.Properties['expected_workspace_files']) {
            if ($stageId -notin @('I', 'G')) {
                throw "Only writable I/G worker $workerId may declare expected_workspace_files"
            }
            $expectedWorkspaceFiles = @($worker.expected_workspace_files | ForEach-Object {
                ([string]$_).Replace('\', '/')
            })
            foreach ($expectedFile in $expectedWorkspaceFiles) {
                Resolve-Wave3ContainedPath -Root $RepositoryRoot `
                    -RelativePath $expectedFile | Out-Null
            }
            $requiredWorkspaceOutputs = @($worker.required_outputs | ForEach-Object {
                ([string]$_.path).Replace('\', '/')
            })
            foreach ($requiredWorkspaceOutput in $requiredWorkspaceOutputs) {
                if ($requiredWorkspaceOutput -cnotin $expectedWorkspaceFiles) {
                    throw "Worker $workerId expected_workspace_files omits required output $requiredWorkspaceOutput"
                }
            }
        }

        if ([string]::IsNullOrWhiteSpace([string]$worker.writable_dir)) {
            throw "Worker $workerId must declare writable_dir"
        }
        Resolve-Wave3ContainedPath -Root $RepositoryRoot `
            -RelativePath ([string]$worker.writable_dir) | Out-Null
        $normalizedWritable = [System.IO.Path]::GetFullPath(
            (Join-Path $RepositoryRoot ([string]$worker.writable_dir))
        ).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
        foreach ($priorWorkerId in @($writablePaths.Keys)) {
            $priorPath = [string]$writablePaths[$priorWorkerId]
            if ($normalizedWritable.Equals($priorPath, [System.StringComparison]::OrdinalIgnoreCase) -or
                $normalizedWritable.StartsWith(
                    $priorPath + [System.IO.Path]::DirectorySeparatorChar,
                    [System.StringComparison]::OrdinalIgnoreCase
                ) -or
                $priorPath.StartsWith(
                    $normalizedWritable + [System.IO.Path]::DirectorySeparatorChar,
                    [System.StringComparison]::OrdinalIgnoreCase
                )) {
                throw "Writable directories overlap for $priorWorkerId and $workerId"
            }
        }
        $writablePaths[$workerId] = $normalizedWritable

        if ($stageId -in @('E', 'O', 'R')) {
            $allowedArtifactTools = if ($stageId -in @('E', 'O')) {
                @('read', 'grep', 'find', 'ls', 'write')
            }
            else {
                @('read', 'grep', 'find', 'ls', 'write', 'powershell')
            }
            $forbiddenTools = @($worker.tools | Where-Object { $_ -notin $allowedArtifactTools })
            if ($forbiddenTools.Count) {
                throw "Source-read-only worker $workerId has forbidden tools: $($forbiddenTools -join ', ')"
            }
            if ('write' -notin @($worker.tools)) {
                throw "Source-read-only worker $workerId must have the write tool for its isolated artifact"
            }
            if ($worker.required_outputs.Count -ne 1 -or
                $worker.required_outputs[0].source -ne 'workspace' -or
                $worker.required_outputs[0].format -ne 'json' -or
                $null -eq $worker.required_outputs[0].schema -or
                [string]::IsNullOrWhiteSpace([string]$worker.required_outputs[0].path)) {
                throw "Source-read-only worker $workerId must declare exactly one schema-validated workspace JSON output"
            }
        }
        else {
            foreach ($neededTool in @('write', 'edit')) {
                if ($neededTool -notin @($worker.tools)) {
                    throw "Writable worker $workerId must have the $neededTool tool"
                }
            }
            if (@($worker.required_outputs | Where-Object source -ne 'workspace').Count) {
                throw "Writable worker $workerId must place every required output in its workspace"
            }
            $structuredOutputs = @($worker.required_outputs | Where-Object {
                $_.format -eq 'json' -and $null -ne $_.schema
            })
            if ($structuredOutputs.Count -ne 1) {
                throw "Writable worker $workerId must declare exactly one schema-validated JSON manifest"
            }
            $workspaceOutputPaths = @($worker.required_outputs | ForEach-Object { [string]$_.path })
            if (@($workspaceOutputPaths | Sort-Object -Unique).Count -ne $workspaceOutputPaths.Count) {
                throw "Writable worker $workerId has duplicate output paths"
            }
        }

        if ($stageId -eq 'R') {
            $targets = @($worker.review_targets | ForEach-Object { [string]$_ })
            if ($targets.Count -ne 3) {
                throw "Reviewer $workerId must review exactly three implementations"
            }
            foreach ($target in $targets) {
                if ($target -notin $implementationIds) {
                    throw "Reviewer $workerId names unknown implementation $target"
                }
                $reviewCoverage[$target]++
            }
        }
        elseif (@($worker.review_targets).Count) {
            throw "Only R-stage workers may declare review_targets ($workerId)"
        }
    }

    if ($totalTokenBudget -gt 7500000) {
        throw "Total token budget exceeds 7,500,000: $totalTokenBudget"
    }
    foreach ($implementationId in $implementationIds) {
        if ($reviewCoverage[$implementationId] -ne 2) {
            throw "Implementation $implementationId must have exactly two reviewers; found $($reviewCoverage[$implementationId])"
        }
    }

    $semanticGatesProperty = $config.PSObject.Properties['semantic_gates']
    if ($null -ne $semanticGatesProperty) {
        $gatedStages = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::Ordinal
        )
        foreach ($gate in @($semanticGatesProperty.Value)) {
            $gateStage = [string]$gate.stage
            if (-not $gatedStages.Add($gateStage)) {
                throw "Stage $gateStage declares more than one semantic gate"
            }

            $scriptRelative = [string]$gate.script
            if ($scriptRelative.Contains('\') -or
                -not $scriptRelative.EndsWith('.py', [System.StringComparison]::Ordinal)) {
                throw "Semantic gate $gateStage script must be a forward-slash repo-relative .py path"
            }
            $scriptPath = Resolve-Wave3ContainedPath -Root $RepositoryRoot `
                -RelativePath $scriptRelative -MustExist -PathType Leaf
            Assert-Wave3SafeDirectoryTree `
                -LiteralPath ([System.IO.Path]::GetDirectoryName($scriptPath)) `
                -BoundaryPath $RepositoryRoot | Out-Null
            Assert-Wave3ArtifactFile -LiteralPath $scriptPath | Out-Null
            $scriptHash = Get-Wave3Sha256 -LiteralPath $scriptPath
            if ($scriptHash -cne [string]$gate.script_sha256) {
                throw "Semantic gate $gateStage script SHA-256 does not match the frozen configuration"
            }

            $workspaceRelative = ([string]$gate.workspace_root).Replace('\', '/')
            Resolve-Wave3ContainedPath -Root $RepositoryRoot `
                -RelativePath $workspaceRelative | Out-Null
            $workspacePrefix = $workspaceRelative.TrimEnd('/') + '/'
            $stageWorkers = @($config.workers | Where-Object stage -ceq $gateStage)
            foreach ($stageWorker in $stageWorkers) {
                $workerWorkspace = ([string]$stageWorker.writable_dir).Replace('\', '/')
                if (-not $workerWorkspace.StartsWith(
                    $workspacePrefix, [System.StringComparison]::OrdinalIgnoreCase
                )) {
                    throw "Semantic gate $gateStage workspace_root must contain every $gateStage worker workspace"
                }
            }
            $foreignWorkers = @($config.workers | Where-Object {
                [string]$_.stage -cne $gateStage -and
                ([string]$_.writable_dir).Replace('\', '/').StartsWith(
                    $workspacePrefix, [System.StringComparison]::OrdinalIgnoreCase
                )
            })
            if ($foreignWorkers.Count) {
                throw "Semantic gate $gateStage workspace_root contains another stage's worker workspace"
            }
        }
    }

    return [pscustomobject]@{
        config = $config
        config_path = $resolvedConfig
        schema_path = $resolvedSchema
        config_sha256 = Get-Wave3Sha256 -LiteralPath $resolvedConfig
        total_token_budget = $totalTokenBudget
    }
}

function Assert-Wave3FrozenState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)]$Validation,
        [Parameter(Mandatory = $true)][string]$ExpectedRunId,
        [Parameter(Mandatory = $true)][string]$ExpectedRunRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedRepositoryRoot,
        [Parameter(Mandatory = $true)][string]$ConfigSchemaPath
    )

    if ([int]$State.state_version -ne 3) {
        throw "State version must be 3; found $($State.state_version)"
    }
    if ([string]$State.run_id -cne $ExpectedRunId) {
        throw "State run_id mismatch. Expected $ExpectedRunId, found $($State.run_id)"
    }
    $pathChecks = @(
        [pscustomobject]@{
            label = 'run_root'
            actual = [string]$State.run_root
            expected = $ExpectedRunRoot
        },
        [pscustomobject]@{
            label = 'repository_root'
            actual = [string]$State.repository_root
            expected = $ExpectedRepositoryRoot
        },
        [pscustomobject]@{
            label = 'config_path'
            actual = [string]$State.config_path
            expected = [string]$Validation.config_path
        }
    )
    foreach ($check in $pathChecks) {
        if ([string]::IsNullOrWhiteSpace($check.actual)) {
            throw "State $($check.label) is blank"
        }
        $actualPath = [System.IO.Path]::GetFullPath($check.actual).TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar
        )
        $expectedPath = [System.IO.Path]::GetFullPath($check.expected).TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar
        )
        if (-not $actualPath.Equals($expectedPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "State $($check.label) mismatch. Expected $expectedPath, found $actualPath"
        }
    }
    if ([string]$State.config_sha256 -cne [string]$Validation.config_sha256) {
        throw "State configuration hash mismatch"
    }
    if ([string]$State.model -cne [string]$Validation.config.model) {
        throw "State model mismatch"
    }
    $resolvedSchema = (Resolve-Path -LiteralPath $ConfigSchemaPath -ErrorAction Stop).Path
    if (-not $resolvedSchema.Equals(
        [string]$Validation.schema_path,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Validated configuration schema path mismatch"
    }
    $schemaHash = Get-Wave3Sha256 -LiteralPath $resolvedSchema
    if ([string]$State.config_schema_sha256 -cne $schemaHash) {
        throw "State configuration schema hash mismatch"
    }
    if ([int64]$State.total_token_budget -ne [int64]$Validation.total_token_budget) {
        throw "State total_token_budget mismatch"
    }
    if ([int64]$State.actual_token_ceiling -ne [int64]$Validation.total_token_budget) {
        throw "State actual_token_ceiling must equal the frozen total token budget of $($Validation.total_token_budget)"
    }

    $configStages = @($Validation.config.stages)
    $stateStages = @($State.stages)
    if ($stateStages.Count -ne $configStages.Count) {
        throw "State stage count mismatch"
    }
    if (@($stateStages.id | Sort-Object -Unique).Count -ne $stateStages.Count) {
        throw "State stage identities are not unique"
    }
    foreach ($configStage in $configStages) {
        $matches = @($stateStages | Where-Object id -ceq ([string]$configStage.id))
        if ($matches.Count -ne 1) {
            throw "State does not contain exactly one stage $($configStage.id)"
        }
        $actualDependencies = @($matches[0].depends_on | ForEach-Object { [string]$_ })
        $expectedDependencies = @($configStage.depends_on | ForEach-Object { [string]$_ })
        if (($actualDependencies -join "`n") -cne ($expectedDependencies -join "`n")) {
            throw "State dependencies changed for stage $($configStage.id)"
        }
    }

    $configWorkers = @($Validation.config.workers)
    $stateWorkers = @($State.workers)
    if ($stateWorkers.Count -ne $configWorkers.Count) {
        throw "State worker count mismatch"
    }
    if (@($stateWorkers.id | Sort-Object -Unique).Count -ne $stateWorkers.Count) {
        throw "State worker identities are not unique"
    }
    $budgetFields = @('max_tokens', 'timeout_seconds', 'max_tool_calls', 'max_output_bytes')
    $optionalBudgetFields = @('artifact_checkpoint_tool_calls')
    foreach ($configWorker in $configWorkers) {
        $matches = @($stateWorkers | Where-Object id -ceq ([string]$configWorker.id))
        if ($matches.Count -ne 1) {
            throw "State does not contain exactly one worker $($configWorker.id)"
        }
        $stateWorker = $matches[0]
        if ([string]$stateWorker.stage -cne [string]$configWorker.stage) {
            throw "State stage identity changed for worker $($configWorker.id)"
        }
        if ([string]$stateWorker.role -cne [string]$configWorker.role) {
            throw "State role changed for worker $($configWorker.id)"
        }
        foreach ($field in $budgetFields) {
            if ([int64]$stateWorker.budget.$field -ne [int64]$configWorker.budget.$field) {
                throw "State budget $field changed for worker $($configWorker.id)"
            }
        }
        foreach ($field in $optionalBudgetFields) {
            $stateProperty = $stateWorker.budget.PSObject.Properties[$field]
            $configProperty = $configWorker.budget.PSObject.Properties[$field]
            if (($null -eq $stateProperty) -ne ($null -eq $configProperty)) {
                throw "State budget $field presence changed for worker $($configWorker.id)"
            }
            if ($null -ne $configProperty -and
                [int64]$stateProperty.Value -ne [int64]$configProperty.Value) {
                throw "State budget $field changed for worker $($configWorker.id)"
            }
        }
    }
    return $true
}

function Get-Wave3ArtifactCheckpointDecision {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$WorkerConfig,
        [Parameter(Mandatory = $true)][string]$WorkspacePath,
        [Parameter(Mandatory = $true)][int64]$DeclaredToolCalls,
        [Parameter(Mandatory = $true)][int64]$CompletedToolCalls,
        [Parameter(Mandatory = $true)][bool]$TelemetryFresh,
        [Parameter(Mandatory = $true)][bool]$PreviouslySatisfied
    )

    if ($DeclaredToolCalls -lt 0 -or $CompletedToolCalls -lt 0) {
        throw 'Artifact checkpoint tool-call telemetry cannot be negative'
    }
    if ($CompletedToolCalls -gt $DeclaredToolCalls) {
        throw 'Completed tool-call telemetry cannot exceed declared tool calls'
    }
    $checkpointProperty =
        $WorkerConfig.budget.PSObject.Properties['artifact_checkpoint_tool_calls']
    if ($null -eq $checkpointProperty -or -not $TelemetryFresh -or $PreviouslySatisfied) {
        return $null
    }
    $checkpointToolCalls = [int64]$checkpointProperty.Value

    $requiredWorkspaceOutputs = @($WorkerConfig.required_outputs | Where-Object {
        [string]$_.source -eq 'workspace'
    })
    if (-not $requiredWorkspaceOutputs.Count) {
        throw "Worker $($WorkerConfig.id) has an artifact checkpoint but no required workspace artifacts"
    }
    $safeArtifactPath = $null
    foreach ($requiredOutput in $requiredWorkspaceOutputs) {
        try {
            Assert-Wave3SafeDirectoryTree -LiteralPath $WorkspacePath `
                -BoundaryPath $WorkspacePath | Out-Null
            $artifactPath = Resolve-Wave3ContainedPath -Root $WorkspacePath `
                -RelativePath ([string]$requiredOutput.path) -MustExist -PathType Leaf
            Assert-Wave3SafeDirectoryTree `
                -LiteralPath ([System.IO.Path]::GetDirectoryName($artifactPath)) `
                -BoundaryPath $WorkspacePath | Out-Null
            Assert-Wave3ArtifactFile -LiteralPath $artifactPath | Out-Null
            $item = Get-Item -LiteralPath $artifactPath -Force -ErrorAction Stop
            if ([int64]$item.Length -gt 0) {
                $safeArtifactPath = ([string]$requiredOutput.path).Replace('\', '/')
                break
            }
        }
        catch { continue }
    }

    $beforeDeadline = $CompletedToolCalls -lt $checkpointToolCalls
    $atQuiescentDeadline = $CompletedToolCalls -eq $checkpointToolCalls -and
        $DeclaredToolCalls -eq $CompletedToolCalls
    if ($null -ne $safeArtifactPath -and ($beforeDeadline -or $atQuiescentDeadline)) {
        # This external observation is the durable receipt. Once persisted by
        # the supervisor, later edits do not erase a checkpoint that was met;
        # final validation still authenticates the finished artifact.
        return [pscustomobject]@{
            kind = 'artifact_checkpoint_satisfied'
            observed_declared_tool_calls = $DeclaredToolCalls
            observed_completed_tool_calls = $CompletedToolCalls
            limit = $checkpointToolCalls
            artifact_path = $safeArtifactPath
            required_artifact_count = $requiredWorkspaceOutputs.Count
        }
    }
    if ($beforeDeadline) { return $null }

    return [pscustomobject]@{
        kind = 'artifact_checkpoint_not_satisfied_by_deadline'
        observed_declared_tool_calls = $DeclaredToolCalls
        observed_completed_tool_calls = $CompletedToolCalls
        limit = $checkpointToolCalls
        safe_artifact_present_now = $null -ne $safeArtifactPath
        required_artifact_count = $requiredWorkspaceOutputs.Count
    }
}

function Get-Wave3SessionMetrics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$SessionDirectory,
        [Parameter(Mandatory = $true)][string]$SessionId,
        [switch]$AllowIncompleteTail
    )

    $files = @(Get-ChildItem -LiteralPath $SessionDirectory -Filter ('*_' + $SessionId + '.jsonl') `
        -File -ErrorAction SilentlyContinue)
    if ($files.Count -ne 1) {
        throw "Expected one session JSONL for $SessionId; found $($files.Count)"
    }

    # Pi appends to the JSONL while the watchdog is active.  Read one bounded
    # snapshot with permissive sharing, then derive both metrics and the hash
    # from those exact bytes.  Opening the live file again with Get-FileHash
    # created a Windows sharing race with Pi's writer in earlier runs.
    $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
    $stream = [System.IO.FileStream]::new(
        $files[0].FullName,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        $share
    )
    try {
        $snapshotLength = $stream.Length
        if ($snapshotLength -gt $script:MaxSessionSnapshotBytes) {
            throw "Session JSONL exceeds the $($script:MaxSessionSnapshotBytes)-byte snapshot cap: $snapshotLength bytes"
        }
        $snapshot = [byte[]]::new([int]$snapshotLength)
        $read = 0
        while ($read -lt $snapshot.Length) {
            $count = $stream.Read($snapshot, $read, $snapshot.Length - $read)
            if ($count -eq 0) { break }
            $read += $count
        }
        if ($read -ne $snapshot.Length) {
            [array]::Resize([ref]$snapshot, $read)
        }
    }
    finally {
        $stream.Dispose()
    }

    $parsedLength = $snapshot.Length
    if ($AllowIncompleteTail -and $parsedLength -gt 0 -and
        $snapshot[$parsedLength - 1] -ne [byte]10) {
        while ($parsedLength -gt 0 -and $snapshot[$parsedLength - 1] -ne [byte]10) {
            $parsedLength--
        }
    }
    $strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $text = $strictUtf8.GetString($snapshot, 0, $parsedLength)

    $totalTokens = [int64]0
    $inputTokens = [int64]0
    $outputTokens = [int64]0
    $cacheReadTokens = [int64]0
    $toolCalls = [int64]0
    $completedToolCalls = [int64]0
    $assistantTurns = [int64]0
    $declaredToolCallIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )
    $completedToolCallIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )
    $firstTimestamp = $null
    $lastTimestamp = $null
    $reader = [System.IO.StringReader]::new($text)
    try {
        while (($line = $reader.ReadLine()) -ne $null) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            # Keep ISO-8601 timestamps as text. PowerShell's default JSON date
            # conversion creates a DateTime in local time; string-casting that
            # value and parsing it again as DateTimeOffset applies the local
            # offset a second time and corrupts persisted UTC provenance.
            $entry = $line | ConvertFrom-Json -Depth 100 -DateKind String
            $entryTimestamp = $null
            if ($null -ne $entry.timestamp) {
                $entryTimestamp = [datetimeoffset]::Parse([string]$entry.timestamp).ToUniversalTime()
                if ($null -eq $firstTimestamp -or $entryTimestamp -lt $firstTimestamp) { $firstTimestamp = $entryTimestamp }
                if ($null -eq $lastTimestamp -or $entryTimestamp -gt $lastTimestamp) { $lastTimestamp = $entryTimestamp }
            }
            if ($entry.type -eq 'message' -and $entry.message.role -eq 'assistant') {
                $assistantTurns++
                if ($null -ne $entry.message.usage) {
                    $totalTokens += [int64]$entry.message.usage.totalTokens
                    $inputTokens += [int64]$entry.message.usage.input
                    $outputTokens += [int64]$entry.message.usage.output
                    $cacheReadTokens += [int64]$entry.message.usage.cacheRead
                }
                $declaredCalls = @($entry.message.content | Where-Object type -eq 'toolCall')
                $toolCalls += $declaredCalls.Count
                foreach ($declaredCall in $declaredCalls) {
                    $toolCallId = if ($null -ne $declaredCall.PSObject.Properties['id']) {
                        [string]$declaredCall.id
                    }
                    else { $null }
                    if ([string]::IsNullOrWhiteSpace($toolCallId)) {
                        throw 'Session contains a toolCall declaration without an ID'
                    }
                    if (-not $declaredToolCallIds.Add($toolCallId)) {
                        throw "Session contains duplicate toolCall ID $toolCallId"
                    }
                }
            }
            elseif ($entry.type -eq 'message' -and $entry.message.role -eq 'toolResult') {
                $toolCallId = if ($null -ne $entry.message.PSObject.Properties['toolCallId']) {
                    [string]$entry.message.toolCallId
                }
                else { $null }
                if ([string]::IsNullOrWhiteSpace($toolCallId)) {
                    throw 'Session contains a toolResult without a toolCallId'
                }
                if (-not $declaredToolCallIds.Contains($toolCallId)) {
                    throw "Session contains a toolResult for undeclared toolCall ID $toolCallId"
                }
                if (-not $completedToolCallIds.Add($toolCallId)) {
                    throw "Session contains duplicate toolResult for toolCall ID $toolCallId"
                }
                if ($null -eq $entryTimestamp) {
                    throw "Session toolResult $toolCallId has no timestamp"
                }
                $completedToolCalls++
            }
        }
    }
    finally {
        $reader.Dispose()
    }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $sessionSha256 = [System.Convert]::ToHexString(
            $sha.ComputeHash($snapshot)
        ).ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }

    return [pscustomobject]@{
        session_file = $files[0].FullName
        session_sha256 = $sessionSha256
        byte_count = $snapshot.Length
        parsed_byte_count = $parsedLength
        total_tokens = $totalTokens
        input_tokens = $inputTokens
        output_tokens = $outputTokens
        cache_read_tokens = $cacheReadTokens
        assistant_turns = $assistantTurns
        tool_calls = $toolCalls
        completed_tool_calls = $completedToolCalls
        first_timestamp_utc = if ($null -ne $firstTimestamp) { $firstTimestamp.ToString('o') } else { $null }
        last_timestamp_utc = if ($null -ne $lastTimestamp) { $lastTimestamp.ToString('o') } else { $null }
    }
}

function Assert-Wave3MonotonicSessionMetrics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Previous,
        [Parameter(Mandatory = $true)]$Current
    )

    foreach ($field in @(
        'byte_count', 'parsed_byte_count', 'total_tokens', 'input_tokens',
        'output_tokens', 'cache_read_tokens', 'assistant_turns', 'tool_calls',
        'completed_tool_calls'
    )) {
        $previousProperty = $Previous.PSObject.Properties[$field]
        $currentProperty = $Current.PSObject.Properties[$field]
        if ($null -eq $previousProperty -or $null -eq $currentProperty) {
            throw "Session metrics are missing monotonic field $field"
        }
        if ([int64]$currentProperty.Value -lt [int64]$previousProperty.Value) {
            throw "Session metric $field regressed from $($previousProperty.Value) to $($currentProperty.Value)"
        }
    }
    if ([int64]$Current.byte_count -eq [int64]$Previous.byte_count -and
        [string]$Current.session_sha256 -cne [string]$Previous.session_sha256) {
        throw 'Session hash changed without an increase in byte_count'
    }
    return $true
}

function Get-Wave3ProcessLifetime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][datetimeoffset]$ProcessStartUtc,
        [Parameter(Mandatory = $true)][datetimeoffset]$NowUtc,
        [switch]$Completed,
        [Nullable[datetimeoffset]]$ExitFileLastWriteUtc,
        [Nullable[datetimeoffset]]$PersistedExitUtc
    )

    $start = $ProcessStartUtc.ToUniversalTime()
    $end = $NowUtc.ToUniversalTime()
    if ($Completed) {
        if ($null -ne $PersistedExitUtc) {
            $end = ([datetimeoffset]$PersistedExitUtc).ToUniversalTime()
            if ($null -ne $ExitFileLastWriteUtc -and
                [math]::Abs(($end - ([datetimeoffset]$ExitFileLastWriteUtc).ToUniversalTime()).TotalSeconds) -gt 2.0) {
                throw 'Persisted process exit time does not match the exit-file timestamp'
            }
        }
        elseif ($null -ne $ExitFileLastWriteUtc) {
            $end = ([datetimeoffset]$ExitFileLastWriteUtc).ToUniversalTime()
        }
        else {
            throw 'Completed worker has neither a persisted exit time nor an exit-file timestamp'
        }
    }
    if ($end -lt $start) {
        throw 'Worker process lifetime ends before process_start_utc'
    }
    return [pscustomobject]@{
        process_start_utc = $start.ToString('o')
        process_end_utc = $end.ToString('o')
        elapsed_seconds = ($end - $start).TotalSeconds
    }
}

function Test-Wave3ProcessIdentityRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][datetimeoffset]$ExpectedStartUtc,
        [Parameter(Mandatory = $true)][datetimeoffset]$ActualStartUtc,
        [Parameter(Mandatory = $true)][string]$ExpectedExecutablePath,
        [Parameter(Mandatory = $true)][string]$ActualExecutablePath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$RequiredCommandLineMarkers,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ActualCommandLine,
        [int]$StartToleranceMilliseconds = 1000
    )

    $startDelta = [math]::Abs((
        $ActualStartUtc.ToUniversalTime() - $ExpectedStartUtc.ToUniversalTime()
    ).TotalMilliseconds)
    if ($startDelta -gt $StartToleranceMilliseconds) {
        return [pscustomobject]@{ trusted = $false; reason = 'process_start_mismatch' }
    }
    $expectedExecutable = [System.IO.Path]::GetFullPath($ExpectedExecutablePath)
    $actualExecutable = [System.IO.Path]::GetFullPath($ActualExecutablePath)
    if (-not $actualExecutable.Equals(
        $expectedExecutable,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        return [pscustomobject]@{ trusted = $false; reason = 'executable_mismatch' }
    }
    if ([string]::IsNullOrWhiteSpace($ActualCommandLine)) {
        return [pscustomobject]@{ trusted = $false; reason = 'command_line_unavailable' }
    }
    foreach ($marker in $RequiredCommandLineMarkers) {
        if ([string]::IsNullOrWhiteSpace($marker) -or
            $ActualCommandLine.IndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
            return [pscustomobject]@{
                trusted = $false
                reason = "command_line_marker_missing:$marker"
            }
        }
    }
    return [pscustomobject]@{ trusted = $true; reason = 'exact_identity_match' }
}

function Get-Wave3LiveProcessIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][string]$ExpectedStartUtc,
        [Parameter(Mandatory = $true)][string]$ExpectedExecutablePath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$RequiredCommandLineMarkers
    )

    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        return [pscustomobject]@{ exists = $false; trusted = $false; reason = 'process_not_found' }
    }
    try {
        $cim = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ProcessId" `
            -ErrorAction Stop
        if ($null -eq $cim) {
            return [pscustomobject]@{ exists = $true; trusted = $false; reason = 'process_metadata_missing' }
        }
        $actualExecutable = if (-not [string]::IsNullOrWhiteSpace([string]$cim.ExecutablePath)) {
            [string]$cim.ExecutablePath
        }
        else { [string]$process.Path }
        $result = Test-Wave3ProcessIdentityRecord `
            -ExpectedStartUtc ([datetimeoffset]::Parse($ExpectedStartUtc)) `
            -ActualStartUtc ([datetimeoffset]$process.StartTime.ToUniversalTime()) `
            -ExpectedExecutablePath $ExpectedExecutablePath `
            -ActualExecutablePath $actualExecutable `
            -RequiredCommandLineMarkers $RequiredCommandLineMarkers `
            -ActualCommandLine ([string]$cim.CommandLine)
        return [pscustomobject]@{
            exists = $true
            trusted = [bool]$result.trusted
            reason = [string]$result.reason
            executable_path = $actualExecutable
            command_line = [string]$cim.CommandLine
        }
    }
    catch {
        return [pscustomobject]@{
            exists = $true
            trusted = $false
            reason = "process_metadata_error:$($_.Exception.Message)"
        }
    }
    finally {
        $process.Dispose()
    }
}

function Get-Wave3FailClosedDecision {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][bool]$WorkerProcessExists,
        [Parameter(Mandatory = $true)][bool]$IdentityTrusted
    )

    if (-not $WorkerProcessExists) {
        return [pscustomobject]@{ action = 'none'; reason = 'process_not_found' }
    }
    if (-not $IdentityTrusted) {
        return [pscustomobject]@{ action = 'do_not_kill'; reason = 'identity_mismatch' }
    }
    return [pscustomobject]@{ action = 'kill_verified_tree'; reason = 'watchdog_fail_closed' }
}

function Assert-Wave3SafeDirectoryTree {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$BoundaryPath
    )

    $boundary = [System.IO.Path]::GetFullPath($BoundaryPath).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    $current = [System.IO.Path]::GetFullPath($LiteralPath).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    if (-not ($current.Equals($boundary, [System.StringComparison]::OrdinalIgnoreCase) -or
        $current.StartsWith(
            $boundary + [System.IO.Path]::DirectorySeparatorChar,
            [System.StringComparison]::OrdinalIgnoreCase
        ))) {
        throw "Directory is outside its safety boundary: $current"
    }
    while ($true) {
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (-not ($item -is [System.IO.DirectoryInfo])) {
            throw "Expected a directory in workspace ancestry: $current"
        }
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Workspace root or ancestor is a reparse point: $current"
        }
        if ($current.Equals($boundary, [System.StringComparison]::OrdinalIgnoreCase)) { break }
        $parent = [System.IO.Directory]::GetParent($current)
        if ($null -eq $parent) { throw "Workspace ancestry escaped its boundary: $current" }
        $current = $parent.FullName.TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar
        )
    }
    return $true
}

function Assert-Wave3ArtifactFile {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $item = Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
    if (-not ($item -is [System.IO.FileInfo])) {
        throw "Expected a regular artifact file: $LiteralPath"
    }
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not [string]::IsNullOrWhiteSpace([string]$item.LinkType)) {
        throw "Artifact cannot be a symbolic, junction, or hard link: $LiteralPath"
    }
    if ($IsWindows) {
        $fsutil = Join-Path $env:SystemRoot 'System32\fsutil.exe'
        $linkOutput = @(& $fsutil hardlink list $item.FullName 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "Could not establish hard-link count for artifact: $LiteralPath"
        }
        $links = @($linkOutput | ForEach-Object { [string]$_ } | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_)
        })
        if ($links.Count -ne 1) {
            throw "Artifact has $($links.Count) hard links: $LiteralPath"
        }
    }
    return $true
}

function Get-Wave3SemanticGateTreeFingerprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$BoundaryPath
    )

    Assert-Wave3SafeDirectoryTree -LiteralPath $LiteralPath `
        -BoundaryPath $BoundaryPath | Out-Null
    $items = @(Get-ChildItem -LiteralPath $LiteralPath -Recurse -Force -ErrorAction Stop)
    $reparse = @($items | Where-Object {
        ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    } | Select-Object -First 1)
    if ($reparse.Count) {
        throw "Semantic gate workspace contains a reparse point: $($reparse[0].FullName)"
    }

    $records = @($items | Sort-Object FullName -CaseSensitive | ForEach-Object {
        $relativePath = [System.IO.Path]::GetRelativePath(
            $LiteralPath, $_.FullName
        ).Replace('\', '/')
        if ($_ -is [System.IO.DirectoryInfo]) {
            [ordered]@{ kind = 'directory'; path = $relativePath }
        }
        elseif ($_ -is [System.IO.FileInfo]) {
            Assert-Wave3ArtifactFile -LiteralPath $_.FullName | Out-Null
            [ordered]@{
                kind = 'file'
                path = $relativePath
                sha256 = Get-Wave3Sha256 -LiteralPath $_.FullName
                byte_count = [int64]$_.Length
            }
        }
        else {
            throw "Semantic gate workspace contains an unsupported item: $($_.FullName)"
        }
    })
    return ($records | ConvertTo-Json -Depth 5 -Compress)
}

function ConvertTo-Wave3DeterministicProcessText {
    param([AllowNull()][string]$Text)

    if ($null -eq $Text) { return '' }
    $normalized = $Text.Replace("`r`n", "`n").Replace("`r", "`n")
    return $normalized.TrimEnd([char[]]@([char]10))
}

function Invoke-Wave3SemanticGate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$GateConfig,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$WorkspaceRoot
    )

    $stageId = [string]$GateConfig.stage
    $scriptRelative = [string]$GateConfig.script
    $workspaceRelative = [string]$GateConfig.workspace_root
    $expectedScriptHash = [string]$GateConfig.script_sha256
    if ($stageId -cnotmatch '^[EOIRG]$' -or
        $scriptRelative.Contains('\') -or
        -not $scriptRelative.EndsWith('.py', [System.StringComparison]::Ordinal) -or
        $expectedScriptHash -cnotmatch '^[0-9a-f]{64}$' -or
        $workspaceRelative.Contains('\')) {
        throw "Semantic gate $stageId has an invalid frozen configuration"
    }

    $scriptPath = Resolve-Wave3ContainedPath -Root $RepositoryRoot `
        -RelativePath $scriptRelative -MustExist -PathType Leaf
    Assert-Wave3SafeDirectoryTree `
        -LiteralPath ([System.IO.Path]::GetDirectoryName($scriptPath)) `
        -BoundaryPath $RepositoryRoot | Out-Null
    Assert-Wave3ArtifactFile -LiteralPath $scriptPath | Out-Null
    $scriptHashBefore = Get-Wave3Sha256 -LiteralPath $scriptPath
    if ($scriptHashBefore -cne $expectedScriptHash) {
        throw "Semantic gate $stageId script changed after configuration freeze"
    }

    $argumentRoot = Resolve-Wave3ContainedPath -Root $WorkspaceRoot `
        -RelativePath $workspaceRelative -MustExist -PathType Container
    Assert-Wave3SafeDirectoryTree -LiteralPath $argumentRoot `
        -BoundaryPath $WorkspaceRoot | Out-Null
    $treeBefore = Get-Wave3SemanticGateTreeFingerprint `
        -LiteralPath $argumentRoot -BoundaryPath $WorkspaceRoot

    $pythonCommand = $null
    foreach ($commandName in @('python', 'python3')) {
        $candidate = @(Get-Command -Name $commandName -CommandType Application `
            -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($candidate.Count) {
            $pythonCommand = [string]$candidate[0].Source
            break
        }
    }
    if ([string]::IsNullOrWhiteSpace($pythonCommand)) {
        throw "Semantic gate $stageId cannot resolve the current Python interpreter"
    }

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $pythonCommand
    $startInfo.WorkingDirectory = $RepositoryRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $startInfo.StandardErrorEncoding = [System.Text.UTF8Encoding]::new($false)
    $startInfo.Environment['PYTHONDONTWRITEBYTECODE'] = '1'
    $startInfo.Environment['PYTHONUTF8'] = '1'
    foreach ($argument in @('-B', $scriptPath, $argumentRoot)) {
        $startInfo.ArgumentList.Add([string]$argument)
    }

    $process = [System.Diagnostics.Process]::Start($startInfo)
    if ($null -eq $process) {
        throw "Semantic gate $stageId failed to start the current Python interpreter"
    }
    $timedOut = $false
    $stdout = ''
    $stderr = ''
    $exitCode = $null
    try {
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(120000)) {
            $timedOut = $true
            $process.Kill($true)
            $process.WaitForExit()
        }
        $stdout = ConvertTo-Wave3DeterministicProcessText `
            $stdoutTask.GetAwaiter().GetResult()
        $stderr = ConvertTo-Wave3DeterministicProcessText `
            $stderrTask.GetAwaiter().GetResult()
        $exitCode = [int]$process.ExitCode
    }
    finally {
        $process.Dispose()
    }

    $scriptHashAfter = Get-Wave3Sha256 -LiteralPath $scriptPath
    if ($scriptHashAfter -cne $expectedScriptHash) {
        throw "Semantic gate $stageId script changed while it was running"
    }
    $treeAfter = Get-Wave3SemanticGateTreeFingerprint `
        -LiteralPath $argumentRoot -BoundaryPath $WorkspaceRoot
    if ($treeAfter -cne $treeBefore) {
        throw "Semantic gate $stageId mutated its read-only workspace argument"
    }
    if ($timedOut) {
        throw "Semantic gate $stageId exceeded the fixed 120-second timeout"
    }
    $capturedBytes = [System.Text.Encoding]::UTF8.GetByteCount($stdout) +
        [System.Text.Encoding]::UTF8.GetByteCount($stderr)
    if ($capturedBytes -gt 1048576) {
        throw "Semantic gate $stageId exceeded the fixed 1048576-byte output limit"
    }
    if ($exitCode -ne 0) {
        throw "Semantic gate $stageId failed with exit code $exitCode; stdout=[$stdout]; stderr=[$stderr]"
    }

    return [pscustomobject][ordered]@{
        stage = $stageId
        script = $scriptRelative
        script_sha256 = $expectedScriptHash
        workspace_root = $workspaceRelative
        exit_code = $exitCode
        stdout = $stdout
        stderr = $stderr
    }
}

function Assert-Wave3ExactWorkspaceInventory {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Inventory,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][string]$WorkerId
    )

    # PowerShell unwraps a one-item pipeline result at a function boundary. In
    # particular, a single [ordered] inventory record otherwise exposes the
    # record's three fields through .Count instead of representing one file.
    $entries = @($Inventory)
    if ($entries.Count -ne 1 -or [string]$entries[0].path -cne $ExpectedPath) {
        throw "Source-read-only worker $WorkerId workspace must contain only $ExpectedPath"
    }
    return $true
}

function Assert-Wave3ExactWorkspacePathSet {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Inventory,
        [Parameter(Mandatory = $true)][string[]]$ExpectedPaths,
        [Parameter(Mandatory = $true)][string]$WorkerId
    )

    $actual = @(@($Inventory) | ForEach-Object { [string]$_.path } | Sort-Object)
    $expected = @($ExpectedPaths | ForEach-Object { $_.Replace('\', '/') } | Sort-Object)
    if (@($expected | Sort-Object -Unique).Count -ne $expected.Count) {
        throw "Worker $WorkerId declares duplicate workspace paths"
    }
    if (($actual -join "`n") -cne ($expected -join "`n")) {
        throw "Worker $WorkerId workspace inventory does not exactly match declared files"
    }
    return $true
}

function Get-Wave3DependencyArtifactIndex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$StageManifests,
        [Parameter(Mandatory = $true)][string]$RunRoot
    )

    $index = [hashtable]::new([System.StringComparer]::Ordinal)
    foreach ($stageManifest in @($StageManifests)) {
        $stageId = [string]$stageManifest.stage
        if ([string]::IsNullOrWhiteSpace($stageId)) {
            throw 'Dependency stage manifest has no stage identity'
        }
        foreach ($worker in @($stageManifest.workers)) {
            $workerId = [string]$worker.id
            if ([string]::IsNullOrWhiteSpace($workerId)) {
                throw "Dependency stage $stageId contains a worker without an identity"
            }
            if ($index.ContainsKey($workerId)) {
                throw "Dependency manifests contain duplicate worker identity $workerId"
            }
            $artifacts = @($worker.artifacts)
            if (-not $artifacts.Count) {
                throw "Dependency worker $workerId has no admitted artifacts"
            }

            $workspaceRelative = ([string]$worker.workspace_path).Replace('\', '/')
            if ([string]::IsNullOrWhiteSpace($workspaceRelative)) {
                throw "Dependency worker $workerId has no frozen workspace path"
            }
            $workspaceAbsolute = Resolve-Wave3ContainedPath -Root $RunRoot `
                -RelativePath $workspaceRelative -MustExist -PathType Container
            Assert-Wave3SafeDirectoryTree -LiteralPath $workspaceAbsolute `
                -BoundaryPath $RunRoot | Out-Null
            $treeItems = @(Get-ChildItem -LiteralPath $workspaceAbsolute -Recurse -Force -ErrorAction Stop)
            $reparseItem = @($treeItems | Where-Object {
                ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
            } | Select-Object -First 1)
            if ($reparseItem.Count) {
                throw "Dependency workspace for $workerId contains a reparse point: $($reparseItem[0].FullName)"
            }
            $currentInventory = @($treeItems | Where-Object {
                $_ -is [System.IO.FileInfo]
            } | Sort-Object FullName | ForEach-Object {
                Assert-Wave3ArtifactFile -LiteralPath $_.FullName | Out-Null
                [pscustomobject]@{
                    path = [System.IO.Path]::GetRelativePath(
                        $workspaceAbsolute, $_.FullName
                    ).Replace('\', '/')
                    sha256 = Get-Wave3Sha256 -LiteralPath $_.FullName
                    byte_count = [int64]$_.Length
                }
            })
            $expectedInventory = @($worker.workspace_inventory)
            $expectedByPath = [hashtable]::new([System.StringComparer]::Ordinal)
            foreach ($expectedFile in $expectedInventory) {
                $expectedPath = ([string]$expectedFile.path).Replace('\', '/')
                $expectedHash = [string]$expectedFile.sha256
                $expectedBytes = [int64]$expectedFile.byte_count
                if ([string]::IsNullOrWhiteSpace($expectedPath) -or
                    $expectedHash -cnotmatch '^[0-9a-f]{64}$' -or $expectedBytes -lt 0) {
                    throw "Dependency worker $workerId has an invalid workspace inventory record"
                }
                if ($expectedByPath.ContainsKey($expectedPath)) {
                    throw "Dependency worker $workerId has duplicate workspace path $expectedPath"
                }
                $expectedByPath[$expectedPath] = [pscustomobject]@{
                    sha256 = $expectedHash
                    byte_count = $expectedBytes
                }
            }
            $actualPaths = @($currentInventory | ForEach-Object { [string]$_.path } | Sort-Object)
            $expectedPaths = @($expectedByPath.Keys | ForEach-Object { [string]$_ } | Sort-Object)
            if (($actualPaths -join "`n") -cne ($expectedPaths -join "`n")) {
                throw "Dependency workspace inventory changed for worker $workerId"
            }
            foreach ($currentFile in $currentInventory) {
                $expectedFile = $expectedByPath[[string]$currentFile.path]
                if ([string]$currentFile.sha256 -cne [string]$expectedFile.sha256 -or
                    [int64]$currentFile.byte_count -ne [int64]$expectedFile.byte_count) {
                    throw "Dependency workspace file changed for worker ${workerId}: $($currentFile.path)"
                }
            }

            $artifactNames = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::Ordinal
            )
            $validatedArtifacts = foreach ($artifact in $artifacts) {
                $name = [string]$artifact.name
                $relativePath = ([string]$artifact.path).Replace('\', '/')
                $sha256 = [string]$artifact.sha256
                $byteCount = [int64]$artifact.byte_count
                if ([string]::IsNullOrWhiteSpace($name) -or
                    [string]::IsNullOrWhiteSpace($relativePath) -or
                    $sha256 -cnotmatch '^[0-9a-f]{64}$' -or $byteCount -lt 0) {
                    throw "Dependency worker $workerId has an invalid artifact record"
                }
                if (-not $artifactNames.Add($name)) {
                    throw "Dependency worker $workerId has duplicate artifact name $name"
                }
                $absolutePath = Resolve-Wave3ContainedPath -Root $RunRoot `
                    -RelativePath $relativePath -MustExist -PathType Leaf
                $workspacePrefix = $workspaceAbsolute.TrimEnd(
                    [System.IO.Path]::DirectorySeparatorChar,
                    [System.IO.Path]::AltDirectorySeparatorChar
                ) + [System.IO.Path]::DirectorySeparatorChar
                if (-not $absolutePath.StartsWith(
                    $workspacePrefix, [System.StringComparison]::OrdinalIgnoreCase
                )) {
                    throw "Dependency artifact for worker $workerId is outside its frozen workspace"
                }
                Assert-Wave3ArtifactFile -LiteralPath $absolutePath | Out-Null
                $actualHash = Get-Wave3Sha256 -LiteralPath $absolutePath
                $actualBytes = [int64](Get-Item -LiteralPath $absolutePath -Force).Length
                if ($actualHash -cne $sha256 -or $actualBytes -ne $byteCount) {
                    throw "Dependency artifact changed for worker ${workerId}: $relativePath"
                }
                [pscustomobject]@{
                    name = $name
                    path = $relativePath
                    sha256 = $sha256
                    byte_count = $byteCount
                    absolute_path = $absolutePath
                }
            }
            $index[$workerId] = [pscustomobject]@{
                stage = $stageId
                worker_id = $workerId
                artifacts = @($validatedArtifacts)
            }
        }
    }
    return $index
}

function Assert-Wave3DependencyArtifactReference {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$ArtifactIndex,
        [Parameter(Mandatory = $true)][string]$WorkerId,
        [Parameter(Mandatory = $true)][string]$ArtifactSha256,
        [string]$ExpectedStage,
        [string]$ExpectedArtifactName
    )

    if (-not $ArtifactIndex.ContainsKey($WorkerId)) {
        throw "Artifact reference names worker $WorkerId outside the admitted dependencies"
    }
    $entry = $ArtifactIndex[$WorkerId]
    if (-not [string]::IsNullOrWhiteSpace($ExpectedStage) -and
        [string]$entry.stage -cne $ExpectedStage) {
        throw "Artifact reference for worker $WorkerId expected stage $ExpectedStage, found $($entry.stage)"
    }
    $eligible = if ([string]::IsNullOrWhiteSpace($ExpectedArtifactName)) {
        @($entry.artifacts)
    }
    else {
        @($entry.artifacts | Where-Object { [string]$_.name -ceq $ExpectedArtifactName })
    }
    if ($eligible.Count -ne 1) {
        $description = if ([string]::IsNullOrWhiteSpace($ExpectedArtifactName)) {
            'a unique admitted artifact'
        }
        else { "exactly one '$ExpectedArtifactName' artifact" }
        throw "Dependency worker $WorkerId does not expose $description"
    }
    if ([string]$eligible[0].sha256 -cne $ArtifactSha256) {
        throw "Artifact reference hash mismatch for worker $WorkerId"
    }
    return $true
}

function Assert-Wave3DependencyArtifactReferences {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('R', 'G')][string]$StageId,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Documents,
        [Parameter(Mandatory = $true)][hashtable]$ArtifactIndex
    )

    foreach ($document in @($Documents)) {
        $seenWorkers = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::Ordinal
        )
        $references = if ($StageId -eq 'R') { @($document.reviews) }
        else { @($document.selected_components) }
        foreach ($reference in $references) {
            $workerId = if ($StageId -eq 'R') {
                [string]$reference.candidate_id
            }
            else { [string]$reference.worker_id }
            $sha256 = if ($StageId -eq 'R') {
                [string]$reference.candidate_sha256
            }
            else { [string]$reference.artifact_sha256 }
            if (-not $seenWorkers.Add($workerId)) {
                throw "Worker $($document.worker_id) references dependency $workerId more than once"
            }
            if ($StageId -eq 'R') {
                Assert-Wave3DependencyArtifactReference -ArtifactIndex $ArtifactIndex `
                    -WorkerId $workerId -ArtifactSha256 $sha256 `
                    -ExpectedStage I -ExpectedArtifactName submission | Out-Null
            }
            else {
                Assert-Wave3DependencyArtifactReference -ArtifactIndex $ArtifactIndex `
                    -WorkerId $workerId -ArtifactSha256 $sha256 | Out-Null
            }
        }
        if ($StageId -eq 'G') {
            $selectedStages = @($seenWorkers | ForEach-Object {
                [string]$ArtifactIndex[[string]$_].stage
            } | Sort-Object -Unique)
            foreach ($requiredStage in @('E', 'O', 'I', 'R')) {
                if ($requiredStage -cnotin $selectedStages) {
                    throw "Integration worker $($document.worker_id) must select at least one $requiredStage-stage artifact"
                }
            }
        }
    }
    return $true
}

function Assert-Wave3SelectedCandidateReviewConsensus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Documents,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$ReviewerConfigs,
        [Parameter(Mandatory = $true)][hashtable]$ArtifactIndex
    )

    if (-not @($Documents).Count) {
        throw 'G-stage reviewer consensus requires at least one integration document'
    }

    $reviewerById = [hashtable]::new([System.StringComparer]::Ordinal)
    $reviewersByCandidate = [hashtable]::new([System.StringComparer]::Ordinal)
    foreach ($reviewer in @($ReviewerConfigs)) {
        $reviewerId = [string]$reviewer.id
        if ($reviewerId -cnotmatch '^R[0-9]{2}$' -or [string]$reviewer.stage -cne 'R') {
            throw "Reviewer consensus received invalid reviewer configuration $reviewerId"
        }
        if ($reviewerById.ContainsKey($reviewerId)) {
            throw "Reviewer consensus received duplicate reviewer configuration $reviewerId"
        }
        $reviewerById[$reviewerId] = $reviewer

        $seenTargets = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::Ordinal
        )
        foreach ($targetValue in @($reviewer.review_targets)) {
            $target = [string]$targetValue
            if ($target -cnotmatch '^I[0-9]{2}$') {
                throw "Reviewer $reviewerId has invalid configured target $target"
            }
            if (-not $seenTargets.Add($target)) {
                throw "Reviewer $reviewerId has duplicate configured target $target"
            }
            if (-not $reviewersByCandidate.ContainsKey($target)) {
                $reviewersByCandidate[$target] = [System.Collections.Generic.List[string]]::new()
            }
            $reviewersByCandidate[$target].Add($reviewerId)
        }
    }

    $integrationIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )
    $selectedCandidates = [hashtable]::new([System.StringComparer]::Ordinal)
    foreach ($document in @($Documents)) {
        $integrationId = [string]$document.worker_id
        if ($integrationId -cnotmatch '^G[0-9]{2}$' -or
            -not $integrationIds.Add($integrationId)) {
            throw "Reviewer consensus received duplicate or invalid integration identity $integrationId"
        }
        $seenSelections = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::Ordinal
        )
        foreach ($reference in @($document.selected_components)) {
            $workerId = [string]$reference.worker_id
            if (-not $ArtifactIndex.ContainsKey($workerId)) {
                throw "Integration worker $integrationId selects unknown dependency $workerId"
            }
            if ([string]$ArtifactIndex[$workerId].stage -cne 'I') { continue }
            if (-not $seenSelections.Add($workerId)) {
                throw "Integration worker $integrationId selects implementation $workerId more than once"
            }

            $candidateHash = [string]$reference.artifact_sha256
            Assert-Wave3DependencyArtifactReference -ArtifactIndex $ArtifactIndex `
                -WorkerId $workerId -ArtifactSha256 $candidateHash `
                -ExpectedStage I -ExpectedArtifactName submission | Out-Null
            if ($selectedCandidates.ContainsKey($workerId)) {
                if ([string]$selectedCandidates[$workerId].candidate_sha256 -cne $candidateHash) {
                    throw "Integration workers selected conflicting hashes for implementation $workerId"
                }
                $selectedCandidates[$workerId].selected_by.Add($integrationId)
            }
            else {
                $selectedCandidates[$workerId] = [pscustomobject]@{
                    candidate_sha256 = $candidateHash
                    selected_by = [System.Collections.Generic.List[string]]::new()
                }
                $selectedCandidates[$workerId].selected_by.Add($integrationId)
            }
        }
    }
    if (-not $selectedCandidates.Count) {
        throw 'G-stage reviewer consensus requires at least one selected I-stage candidate'
    }

    $neededReviewerIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )
    foreach ($candidateId in @($selectedCandidates.Keys)) {
        $assigned = if ($reviewersByCandidate.ContainsKey([string]$candidateId)) {
            @($reviewersByCandidate[[string]$candidateId])
        }
        else { @() }
        if ($assigned.Count -ne 2 -or @($assigned | Sort-Object -Unique).Count -ne 2) {
            throw "Selected implementation $candidateId must have exactly two distinct configured reviewers; found $($assigned.Count)"
        }
        foreach ($reviewerId in $assigned) { $neededReviewerIds.Add($reviewerId) | Out-Null }
    }

    $reviewDocumentById = [hashtable]::new([System.StringComparer]::Ordinal)
    $reviewArtifactHashById = [hashtable]::new([System.StringComparer]::Ordinal)
    foreach ($reviewerId in @($neededReviewerIds | Sort-Object)) {
        if (-not $reviewerById.ContainsKey($reviewerId)) {
            throw "Selected implementation names missing configured reviewer $reviewerId"
        }
        if (-not $ArtifactIndex.ContainsKey($reviewerId)) {
            throw "Configured reviewer $reviewerId has no authenticated R-stage artifact"
        }
        $reviewerEntry = $ArtifactIndex[$reviewerId]
        if ([string]$reviewerEntry.stage -cne 'R') {
            throw "Configured reviewer $reviewerId resolves to stage $($reviewerEntry.stage), not R"
        }
        $allReviewerArtifacts = @($reviewerEntry.artifacts)
        $findingsArtifacts = @($allReviewerArtifacts | Where-Object {
            [string]$_.name -ceq 'findings'
        })
        if ($allReviewerArtifacts.Count -ne 1 -or $findingsArtifacts.Count -ne 1) {
            throw "Configured reviewer $reviewerId must expose exactly one authenticated findings artifact"
        }
        $findingsArtifact = $findingsArtifacts[0]
        $findingsPath = [string]$findingsArtifact.absolute_path
        Assert-Wave3ArtifactFile -LiteralPath $findingsPath | Out-Null
        $findingsItem = Get-Item -LiteralPath $findingsPath -Force -ErrorAction Stop
        $findingsHash = Get-Wave3Sha256 -LiteralPath $findingsPath
        if ($findingsHash -cne [string]$findingsArtifact.sha256 -or
            [int64]$findingsItem.Length -ne [int64]$findingsArtifact.byte_count) {
            throw "Authenticated findings artifact changed for reviewer $reviewerId"
        }
        try {
            $reviewDocument = Get-Content -LiteralPath $findingsPath -Raw -ErrorAction Stop |
                ConvertFrom-Json -Depth 100 -ErrorAction Stop
        }
        catch {
            throw "Authenticated findings artifact is not valid JSON for reviewer ${reviewerId}: $($_.Exception.Message)"
        }
        if ([string]$reviewDocument.worker_id -cne $reviewerId -or
            [string]$reviewDocument.stage -cne 'R') {
            throw "Authenticated findings identity mismatch for reviewer $reviewerId"
        }

        $seenReviews = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::Ordinal
        )
        foreach ($review in @($reviewDocument.reviews)) {
            $candidateId = [string]$review.candidate_id
            if (-not $seenReviews.Add($candidateId)) {
                throw "Reviewer $reviewerId reports duplicate review for $candidateId"
            }
            Assert-Wave3DependencyArtifactReference -ArtifactIndex $ArtifactIndex `
                -WorkerId $candidateId -ArtifactSha256 ([string]$review.candidate_sha256) `
                -ExpectedStage I -ExpectedArtifactName submission | Out-Null
        }
        $actualTargets = @($seenReviews | Sort-Object)
        $configuredTargets = @($reviewerById[$reviewerId].review_targets |
            ForEach-Object { [string]$_ } | Sort-Object)
        if (($actualTargets -join "`n") -cne ($configuredTargets -join "`n")) {
            throw "Reviewer $reviewerId findings do not exactly match its configured targets"
        }
        $reviewDocumentById[$reviewerId] = $reviewDocument
        $reviewArtifactHashById[$reviewerId] = $findingsHash
    }

    $candidateReceipts = @()
    foreach ($candidateId in @($selectedCandidates.Keys | Sort-Object)) {
        $candidate = $selectedCandidates[$candidateId]
        $assignedReviewerIds = @($reviewersByCandidate[$candidateId] | Sort-Object)
        $reviewReceipts = @()
        foreach ($reviewerId in $assignedReviewerIds) {
            $matchingReviews = @($reviewDocumentById[$reviewerId].reviews | Where-Object {
                [string]$_.candidate_id -ceq $candidateId
            })
            if ($matchingReviews.Count -ne 1) {
                throw "Reviewer $reviewerId must report exactly one review for selected implementation $candidateId"
            }
            $review = $matchingReviews[0]
            if ([string]$review.candidate_sha256 -cne [string]$candidate.candidate_sha256) {
                throw "Reviewer $reviewerId reviewed a mismatched hash for selected implementation $candidateId"
            }
            if ([string]$review.verdict -cne 'pass') {
                throw "Reviewer $reviewerId verdict for selected implementation $candidateId is $($review.verdict), not pass"
            }
            $reviewReceipts += [ordered]@{
                reviewer_id = $reviewerId
                findings_sha256 = [string]$reviewArtifactHashById[$reviewerId]
                candidate_sha256 = [string]$review.candidate_sha256
                verdict = 'pass'
            }
        }
        $candidateReceipts += [ordered]@{
            candidate_id = [string]$candidateId
            candidate_sha256 = [string]$candidate.candidate_sha256
            selected_by = @($candidate.selected_by | Sort-Object)
            reviews = @($reviewReceipts)
        }
    }

    return [pscustomobject][ordered]@{
        policy = 'two_configured_reviewers_must_pass'
        candidate_count = $candidateReceipts.Count
        candidates = @($candidateReceipts)
    }
}

function Assert-Wave3Milestone {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Documents,
        [Parameter(Mandatory = $true)][string]$ExpectedMilestone
    )

    foreach ($document in @($Documents)) {
        if ([string]$document.milestone -cne $ExpectedMilestone) {
            throw "Worker $($document.worker_id) must use milestone $ExpectedMilestone"
        }
    }
    return $true
}

function Assert-Wave3RequirementIds {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('O', 'I', 'R', 'G')][string]$StageId,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Documents,
        [Parameter(Mandatory = $true)][string[]]$AllowedRequirementIds
    )

    $allowed = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )
    foreach ($requirementId in $AllowedRequirementIds) {
        if (-not $allowed.Add([string]$requirementId)) {
            throw "Allowed requirement IDs contain duplicate $requirementId"
        }
    }
    if (-not $allowed.Count) { throw 'Allowed requirement IDs cannot be empty' }

    foreach ($document in @($Documents)) {
        $values = switch ($StageId) {
            'O' {
                @($document.tests | ForEach-Object {
                    $_.requirement_ids | ForEach-Object { [string]$_ }
                })
            }
            'I' { @($document.requirement_ids | ForEach-Object { [string]$_ }) }
            'R' {
                @($document.reviews | ForEach-Object {
                    $_.findings | ForEach-Object { [string]$_.requirement_id }
                })
            }
            'G' {
                if ($null -eq $document.PSObject.Properties['requirement_ids'] -or
                    -not @($document.requirement_ids).Count) {
                    throw "Integration worker $($document.worker_id) must declare requirement_ids"
                }
                @($document.requirement_ids | ForEach-Object { [string]$_ })
            }
        }
        foreach ($requirementId in @($values)) {
            if (-not $allowed.Contains($requirementId)) {
                throw "Worker $($document.worker_id) cites non-canonical requirement ID $requirementId"
            }
        }
        if ($StageId -in @('I', 'G')) {
            $actual = @($values | Sort-Object -Unique)
            $expected = @($AllowedRequirementIds | Sort-Object -Unique)
            if (($actual -join "`n") -cne ($expected -join "`n")) {
                throw "Worker $($document.worker_id) must claim the complete configured requirement set"
            }
        }
    }
    if ($StageId -eq 'O') {
        $covered = @($Documents | ForEach-Object {
            $_.tests | ForEach-Object { $_.requirement_ids | ForEach-Object { [string]$_ } }
        } | Sort-Object -Unique)
        $expected = @($AllowedRequirementIds | Sort-Object -Unique)
        if (($covered -join "`n") -cne ($expected -join "`n")) {
            throw 'O-stage oracle documents must collectively cover the complete configured requirement set'
        }
    }
    return $true
}

function Assert-Wave3SerialStageStart {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object[]]$Stages,
        [Parameter(Mandatory = $true)][string]$RequestedStage
    )

    $active = @($Stages | Where-Object { [string]$_.status -in @('launching', 'running') })
    if ($active.Count) {
        throw "Cannot start stage $RequestedStage while stage(s) $(@($active.id) -join ',') are active; wave stages run serially"
    }
    $requestedIndex = [array]::IndexOf($script:StageOrder, $RequestedStage)
    if ($requestedIndex -lt 0) { throw "Unknown wave stage $RequestedStage" }
    foreach ($earlierStageId in @($script:StageOrder | Select-Object -First $requestedIndex)) {
        $earlierStage = @($Stages | Where-Object { [string]$_.id -ceq $earlierStageId })
        if ($earlierStage.Count -ne 1 -or [string]$earlierStage[0].status -cne 'validated') {
            throw "Cannot start stage $RequestedStage before stage $earlierStageId is validated"
        }
    }
    return $true
}

function Assert-Wave3OracleReciprocity {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object[]]$Documents)

    $tests = @{}
    $mutants = @{}
    foreach ($document in $Documents) {
        $workerId = [string]$document.worker_id
        if (@($document.tests).Count -ne 8 -or @($document.mutants).Count -ne 8) {
            throw "Oracle worker $workerId must provide exactly 8 tests and 8 mutants"
        }
        $expectedTestIds = @(1..8 | ForEach-Object { "$workerId.T$_" })
        $expectedMutantIds = @(1..8 | ForEach-Object { "$workerId.M$_" })
        $actualTestIds = @($document.tests | ForEach-Object { [string]$_.test_id } | Sort-Object)
        $actualMutantIds = @($document.mutants | ForEach-Object { [string]$_.mutant_id } | Sort-Object)
        if (($actualTestIds -join ',') -cne (@($expectedTestIds | Sort-Object) -join ',')) {
            throw "Oracle worker $workerId must use exactly IDs $($expectedTestIds -join ',')"
        }
        if (($actualMutantIds -join ',') -cne (@($expectedMutantIds | Sort-Object) -join ',')) {
            throw "Oracle worker $workerId must use exactly IDs $($expectedMutantIds -join ',')"
        }
        foreach ($test in @($document.tests)) {
            $id = [string]$test.test_id
            if (@($test.mutant_ids).Count -ne 1) {
                throw "Oracle test $id must name exactly one mutant"
            }
            $expectedMutantId = "$workerId.M$($id.Substring(($workerId + '.T').Length))"
            if ([string]$test.mutant_ids[0] -cne $expectedMutantId) {
                throw "Oracle test $id must name only matching mutant $expectedMutantId"
            }
            if ($tests.ContainsKey($id)) { throw "O-stage test IDs must be globally unique: $id" }
            $tests[$id] = $test
        }
        foreach ($mutant in @($document.mutants)) {
            $id = [string]$mutant.mutant_id
            if (@($mutant.expected_killer_ids).Count -ne 1) {
                throw "Oracle mutant $id must name exactly one expected killer"
            }
            $expectedTestId = "$workerId.T$($id.Substring(($workerId + '.M').Length))"
            if ([string]$mutant.expected_killer_ids[0] -cne $expectedTestId) {
                throw "Oracle mutant $id must name only matching test $expectedTestId"
            }
            if ($mutants.ContainsKey($id)) { throw "O-stage mutant IDs must be globally unique: $id" }
            $mutants[$id] = $mutant
        }
    }
    foreach ($testId in @($tests.Keys)) {
        foreach ($mutantIdValue in @($tests[$testId].mutant_ids)) {
            $mutantId = [string]$mutantIdValue
            if (-not $mutants.ContainsKey($mutantId)) {
                throw "Test $testId names unknown mutant $mutantId"
            }
            if ($testId -notin @($mutants[$mutantId].expected_killer_ids)) {
                throw "Test $testId and mutant $mutantId are not mapped bidirectionally"
            }
        }
    }
    foreach ($mutantId in @($mutants.Keys)) {
        foreach ($testIdValue in @($mutants[$mutantId].expected_killer_ids)) {
            $testId = [string]$testIdValue
            if (-not $tests.ContainsKey($testId)) {
                throw "Mutant $mutantId names unknown killer $testId"
            }
            if ($mutantId -notin @($tests[$testId].mutant_ids)) {
                throw "Mutant $mutantId and test $testId are not mapped bidirectionally"
            }
        }
    }
    return $true
}

function Stop-Wave3ProcessTree {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][string]$ExpectedStartUtc,
        [Parameter(Mandatory = $true)][string]$ExpectedExecutablePath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$RequiredCommandLineMarkers
    )

    $identity = Get-Wave3LiveProcessIdentity -ProcessId $ProcessId `
        -ExpectedStartUtc $ExpectedStartUtc -ExpectedExecutablePath $ExpectedExecutablePath `
        -RequiredCommandLineMarkers $RequiredCommandLineMarkers
    if (-not $identity.exists) { return $false }
    if (-not $identity.trusted) {
        throw "Refusing to stop uncertain PID $ProcessId`: $($identity.reason)"
    }

    & "$env:SystemRoot\System32\taskkill.exe" /PID $ProcessId /T /F *> $null
    $taskkillExit = $LASTEXITCODE
    if ($taskkillExit -ne 0 -and (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) {
        throw "taskkill failed for process tree $ProcessId with exit code $taskkillExit"
    }
    return $true
}

function Assert-Wave3FrozenHarness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$SupervisorPath,
        [Parameter(Mandatory = $true)][string]$CommonModulePath,
        [Parameter(Mandatory = $true)][string]$WorkerScriptPath
    )

    $entries = @(
        [pscustomobject]@{
            label = 'supervisor'
            state_field = 'supervisor_sha256'
            path = $SupervisorPath
        },
        [pscustomobject]@{
            label = 'common module'
            state_field = 'common_module_sha256'
            path = $CommonModulePath
        },
        [pscustomobject]@{
            label = 'worker script'
            state_field = 'worker_script_sha256'
            path = $WorkerScriptPath
        }
    )
    foreach ($entry in $entries) {
        $expected = if ($State -is [System.Collections.IDictionary]) {
            if ($State.Contains([string]$entry.state_field)) {
                [string]$State[[string]$entry.state_field]
            }
            else { $null }
        }
        else {
            $property = $State.PSObject.Properties[[string]$entry.state_field]
            if ($null -ne $property) { [string]$property.Value } else { $null }
        }
        if ([string]::IsNullOrWhiteSpace($expected)) {
            throw "Run state does not freeze the $($entry.label) hash"
        }
        if (-not (Test-Path -LiteralPath $entry.path -PathType Leaf)) {
            throw "Frozen $($entry.label) is missing: $($entry.path)"
        }
        $actual = Get-Wave3Sha256 -LiteralPath $entry.path
        if ($actual -cne $expected) {
            throw "Frozen $($entry.label) changed after run creation. Expected $expected, found $actual"
        }
    }
    return $true
}

function Get-Wave3BudgetViolation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][datetimeoffset]$StartedUtc,
        [Parameter(Mandatory = $true)][datetimeoffset]$NowUtc,
        [Parameter(Mandatory = $true)][int64]$TotalTokens,
        [Parameter(Mandatory = $true)][int64]$ToolCalls,
        [Parameter(Mandatory = $true)]$Budget,
        [int64]$RunTotalTokens = 0,
        [int64]$RunTokenCeiling = 7500000
    )

    $elapsedSeconds = [math]::Max(0.0, ($NowUtc.ToUniversalTime() -
        $StartedUtc.ToUniversalTime()).TotalSeconds)
    $checks = @(
        [pscustomobject]@{
            kind = 'run_total_tokens'
            observed = $RunTotalTokens
            limit = $RunTokenCeiling
        },
        [pscustomobject]@{
            kind = 'worker_total_tokens'
            observed = $TotalTokens
            limit = [int64]$Budget.max_tokens
        },
        [pscustomobject]@{
            kind = 'worker_tool_calls'
            observed = $ToolCalls
            limit = [int64]$Budget.max_tool_calls
        },
        [pscustomobject]@{
            kind = 'worker_wall_seconds'
            observed = $elapsedSeconds
            limit = [double]$Budget.timeout_seconds
        }
    )
    foreach ($check in $checks) {
        if ([double]$check.observed -gt [double]$check.limit) {
            return [pscustomobject]@{
                kind = [string]$check.kind
                observed = $check.observed
                limit = $check.limit
            }
        }
    }
    return $null
}

function Get-Wave3BudgetEnforcementPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Violations,
        [string[]]$RunningWorkerIds = @()
    )

    $violatingWorkerIds = @($Violations.Keys | Sort-Object)
    $abortStage = @($Violations.Values | Where-Object {
        [string]$_.kind -eq 'run_total_tokens'
    }).Count -gt 0
    $stopWorkerIds = if ($abortStage) {
        @($violatingWorkerIds + @($RunningWorkerIds) | Sort-Object -Unique)
    }
    else { @($violatingWorkerIds) }
    $continueWorkerIds = if ($abortStage) {
        @()
    }
    else {
        @($RunningWorkerIds | Where-Object { $_ -notin $violatingWorkerIds } |
            Sort-Object -Unique)
    }
    return [pscustomobject]@{
        abort_stage = $abortStage
        violating_worker_ids = @($violatingWorkerIds)
        stop_worker_ids = @($stopWorkerIds)
        continue_worker_ids = @($continueWorkerIds)
    }
}

function Get-Wave3FailureEnforcementPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$LiveStatusByWorker,
        [Parameter(Mandatory = $true)][string[]]$StageWorkerIds
    )

    $identityMismatchIds = @($StageWorkerIds | Where-Object {
        [string]$LiveStatusByWorker[$_] -eq 'identity_mismatch'
    } | Sort-Object)
    $ordinaryFailureIds = @($StageWorkerIds | Where-Object {
        [string]$LiveStatusByWorker[$_] -in @('failed', 'lost', 'launch_failed')
    } | Sort-Object)
    $runningIds = @($StageWorkerIds | Where-Object {
        [string]$LiveStatusByWorker[$_] -eq 'running'
    } | Sort-Object)
    return [pscustomobject]@{
        abort_stage = $identityMismatchIds.Count -gt 0
        identity_mismatch_ids = @($identityMismatchIds)
        ordinary_failure_ids = @($ordinaryFailureIds)
        peer_ids_to_stop = if ($identityMismatchIds.Count) { @($runningIds) } else { @() }
        peer_ids_to_continue = if ($identityMismatchIds.Count) { @() } else { @($runningIds) }
    }
}

Export-ModuleMember -Function @(
    'Get-Wave3Sha256',
    'Write-Wave3AtomicText',
    'Write-Wave3AtomicJson',
    'Resolve-Wave3ContainedPath',
    'Test-Wave3JsonDocument',
    'Assert-Wave3EvidenceSources',
    'Read-Wave3Config',
    'Assert-Wave3FrozenState',
    'Get-Wave3SessionMetrics',
    'Assert-Wave3MonotonicSessionMetrics',
    'Get-Wave3ProcessLifetime',
    'Test-Wave3ProcessIdentityRecord',
    'Get-Wave3LiveProcessIdentity',
    'Get-Wave3FailClosedDecision',
    'Assert-Wave3SafeDirectoryTree',
    'Assert-Wave3ArtifactFile',
    'Invoke-Wave3SemanticGate',
    'Assert-Wave3ExactWorkspaceInventory',
    'Assert-Wave3ExactWorkspacePathSet',
    'Get-Wave3DependencyArtifactIndex',
    'Assert-Wave3DependencyArtifactReference',
    'Assert-Wave3DependencyArtifactReferences',
    'Assert-Wave3SelectedCandidateReviewConsensus',
    'Assert-Wave3Milestone',
    'Assert-Wave3RequirementIds',
    'Assert-Wave3SerialStageStart',
    'Assert-Wave3OracleReciprocity',
    'Stop-Wave3ProcessTree',
    'Assert-Wave3FrozenHarness',
    'Get-Wave3ArtifactCheckpointDecision',
    'Get-Wave3BudgetViolation',
    'Get-Wave3BudgetEnforcementPlan',
    'Get-Wave3FailureEnforcementPlan'
)
