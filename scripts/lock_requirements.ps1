[CmdletBinding()]
param(
    [switch]$Check
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("webssh-lock-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null

function New-LockFile {
    param(
        [Parameter(Mandatory)] [string]$InputFile,
        [Parameter(Mandatory)] [string]$LockName
    )

    $temporaryLock = Join-Path $temporaryDirectory $LockName
    & uv pip compile $InputFile --universal --generate-hashes --no-header --output-file $temporaryLock | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "uv could not compile $InputFile."
    }

    $lockText = "--require-hashes`n" + [System.IO.File]::ReadAllText($temporaryLock)
    [System.IO.File]::WriteAllText($temporaryLock, $lockText, [System.Text.UTF8Encoding]::new($false))
    return $temporaryLock
}

function Test-ByteEqual {
    param(
        [Parameter(Mandatory)] [string]$Expected,
        [Parameter(Mandatory)] [string]$Actual
    )

    [byte[]]$expectedBytes = [System.IO.File]::ReadAllBytes($Expected)
    [byte[]]$actualBytes = [System.IO.File]::ReadAllBytes($Actual)
    return [System.Linq.Enumerable]::SequenceEqual($expectedBytes, $actualBytes)
}

try {
    Push-Location $projectRoot
    $runtimeLock = New-LockFile -InputFile "requirements.in" -LockName "requirements.txt"
    $testLock = New-LockFile -InputFile "requirements-test.in" -LockName "requirements-test.txt"
    $graphLock = New-LockFile -InputFile "requirements-graph.in" -LockName "requirements-graph.txt"

    foreach ($lock in @($runtimeLock, $testLock, $graphLock)) {
        $committedLock = Join-Path $projectRoot (Split-Path $lock -Leaf)
        if ($Check) {
            if (-not (Test-ByteEqual -Expected $committedLock -Actual $lock)) {
                throw "$committedLock is out of date. Run pwsh -File scripts/lock_requirements.ps1 and commit the result."
            }
        }
        else {
            Move-Item -LiteralPath $lock -Destination $committedLock -Force
        }
    }
}
finally {
    Pop-Location -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $temporaryDirectory -Force -Recurse -ErrorAction SilentlyContinue
}
