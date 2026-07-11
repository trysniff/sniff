$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$targetDir = Join-Path $repoRoot 'target_dogfood_clean'

if (-not $targetDir.StartsWith($repoRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to use a target dir outside the repository: $targetDir"
}

if (Test-Path -LiteralPath $targetDir) {
    Remove-Item -LiteralPath $targetDir -Recurse -Force
}

$env:CARGO_INCREMENTAL = '0'
try {
    Push-Location $repoRoot
    try {
        cargo test --target-dir $targetDir --test dogfood -- --nocapture
    }
    finally {
        Pop-Location
    }
}
finally {
    Remove-Item Env:CARGO_INCREMENTAL -ErrorAction SilentlyContinue
}
