[CmdletBinding()]
param(
    [switch]$Check,
    [switch]$Upgrade
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("webssh-lock-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null

if ($Check -and $Upgrade) {
    throw "-Check and -Upgrade cannot be used together."
}

function New-LockFile {
    param(
        [Parameter(Mandatory)] [string]$InputFile,
        [Parameter(Mandatory)] [string]$LockName
    )

    $temporaryLock = Join-Path $temporaryDirectory $LockName
    $committedLock = Join-Path $projectRoot $LockName
    if (Test-Path -LiteralPath $committedLock) {
        Copy-Item -LiteralPath $committedLock -Destination $temporaryLock
    }
    $compileArguments = @(
        "pip", "compile", $InputFile,
        "--universal",
        "--python-version", "3.11",
        "--generate-hashes",
        "--no-header",
        "--output-file", $temporaryLock
    )
    if ($Upgrade) {
        $compileArguments += "--upgrade"
    }
    & uv @compileArguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "uv could not compile $InputFile."
    }

    $lockText = "--require-hashes`n" + [System.IO.File]::ReadAllText($temporaryLock)
    [System.IO.File]::WriteAllText($temporaryLock, $lockText, [System.Text.UTF8Encoding]::new($false))
    return $temporaryLock
}

function Test-TextEqual {
    param(
        [Parameter(Mandatory)] [string]$Expected,
        [Parameter(Mandatory)] [string]$Actual
    )

    $expectedText = [System.IO.File]::ReadAllText($Expected).Replace("`r`n", "`n")
    $actualText = [System.IO.File]::ReadAllText($Actual).Replace("`r`n", "`n")
    return $expectedText -ceq $actualText
}

try {
    Push-Location $projectRoot
    $runtimeLock = New-LockFile -InputFile "requirements.in" -LockName "requirements.txt"
    $testLock = New-LockFile -InputFile "requirements-test.in" -LockName "requirements-test.txt"
    $graphLock = New-LockFile -InputFile "requirements-graph.in" -LockName "requirements-graph.txt"

    foreach ($lock in @($runtimeLock, $testLock, $graphLock)) {
        $committedLock = Join-Path $projectRoot (Split-Path $lock -Leaf)
        if ($Check) {
            if (-not (Test-TextEqual -Expected $committedLock -Actual $lock)) {
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
