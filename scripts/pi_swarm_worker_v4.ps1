[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PiCommand,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Model,
    [Parameter(Mandatory = $true)][string]$RepositoryRoot,
    [Parameter(Mandatory = $true)][string]$TaskFile,
    [Parameter(Mandatory = $true)][string]$OutputFile,
    [Parameter(Mandatory = $true)][string]$ErrorFile,
    [Parameter(Mandatory = $true)][string]$ExitFile,
    [Parameter(Mandatory = $true)][string]$SessionDirectory,
    [Parameter(Mandatory = $true)][string]$SessionId,
    [Parameter(Mandatory = $true)][string]$WorkerName,
    [string]$WorkingDirectory,
    [string]$ToolAllowlist = 'read,grep,find,ls',
    [ValidateSet('off', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max')]
    [string]$ThinkingLevel = 'high'
)

$ErrorActionPreference = 'Stop'
$exitCode = 1
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)

try {
    $launchDirectory = if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        $RepositoryRoot
    }
    else {
        $WorkingDirectory
    }
    if (-not (Test-Path -LiteralPath $launchDirectory -PathType Container)) {
        throw "Pi working directory does not exist: $launchDirectory"
    }
    Push-Location -LiteralPath $launchDirectory
    $taskArgument = '@' + $TaskFile
    $piArguments = @(
        '--model', $Model,
        '--thinking', $ThinkingLevel,
        '--mode', 'text',
        '--print',
        '--tools', $ToolAllowlist,
        '--no-extensions',
        '--no-skills',
        '--no-prompt-templates',
        '--no-context-files',
        '--approve',
        '--session-dir', $SessionDirectory,
        '--session-id', $SessionId,
        '--name', $WorkerName,
        $taskArgument
    )
    & $PiCommand @piArguments 1> $OutputFile 2> $ErrorFile
    $exitCode = $LASTEXITCODE
}
catch {
    [System.IO.File]::AppendAllText(
        $ErrorFile,
        $_.Exception.ToString() + [Environment]::NewLine,
        $utf8NoBom
    )
    $exitCode = 1
}
finally {
    Pop-Location -ErrorAction SilentlyContinue
    $exitDirectory = [System.IO.Path]::GetDirectoryName(
        [System.IO.Path]::GetFullPath($ExitFile)
    )
    $exitLeaf = [System.IO.Path]::GetFileName($ExitFile)
    $exitTemporary = Join-Path $exitDirectory (
        ".$exitLeaf.tmp-$PID-$([guid]::NewGuid().ToString('N'))"
    )
    [System.IO.File]::WriteAllText(
        $exitTemporary,
        ([string]$exitCode + [Environment]::NewLine),
        $utf8NoBom
    )
    [System.IO.File]::Move($exitTemporary, $ExitFile, $false)
}

exit $exitCode
