param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("x86_64", "aarch64")]
    [string]$Architecture,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $true)]
    [string]$WorkDirectory
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RustToolchain = "1.96.0"
$RustAnalyzerCommit = "b54a82b321c9617c5cf0b07ac0f12c08f7bc5902"
$CargoCommit = "30a34c6821b57de0aaec83a901aca39f88f6778c"
$Target = "$Architecture-pc-windows-msvc"
$AssetName = "sniff-rust-indexer-$Target"
$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$RustAnalyzerPatch = Join-Path $RepositoryRoot "tools\indexers\patches\rust-analyzer-windows-appcontainer.patch"
$RustStdPatch = Join-Path $RepositoryRoot "tools\indexers\patches\rust-std-windows-appcontainer.patch"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Command failed with exit code $LASTEXITCODE"
    }
}

function Checkout-ExactCommit {
    param(
        [string]$Url,
        [string]$Commit,
        [string]$Directory
    )
    if (Test-Path -LiteralPath $Directory) {
        throw "Refusing to reuse source directory: $Directory"
    }
    Invoke-Checked git clone --filter=blob:none --no-checkout $Url $Directory
    Invoke-Checked git -C $Directory fetch --depth 1 origin $Commit
    Invoke-Checked git -C $Directory checkout --detach FETCH_HEAD
    $actual = (& git -C $Directory rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $actual -ne $Commit) {
        throw "Source identity mismatch for ${Url}: expected $Commit, received $actual"
    }
}

function Write-DeterministicZip {
    param(
        [string]$BundleDirectory,
        [string]$Destination
    )
    Add-Type -AssemblyName System.IO.Compression
    $stream = [System.IO.File]::Open($Destination, [System.IO.FileMode]::CreateNew)
    try {
        $archive = [System.IO.Compression.ZipArchive]::new(
            $stream,
            [System.IO.Compression.ZipArchiveMode]::Create,
            $false
        )
        try {
            foreach ($name in @("cargo.exe", "rust-analyzer.exe")) {
                $source = Join-Path $BundleDirectory "bin\$name"
                $entry = $archive.CreateEntry(
                    "bin/$name",
                    [System.IO.Compression.CompressionLevel]::NoCompression
                )
                $entry.LastWriteTime = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
                $input = [System.IO.File]::OpenRead($source)
                $output = $entry.Open()
                try {
                    $input.CopyTo($output)
                } finally {
                    $output.Dispose()
                    $input.Dispose()
                }
            }
        } finally {
            $archive.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

if (Test-Path -LiteralPath $WorkDirectory) {
    throw "Refusing to reuse work directory: $WorkDirectory"
}
if (Test-Path -LiteralPath $OutputDirectory) {
    throw "Refusing to reuse output directory: $OutputDirectory"
}
New-Item -ItemType Directory -Path $WorkDirectory | Out-Null
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null

Invoke-Checked rustup toolchain install $RustToolchain --profile minimal --component rust-src
Invoke-Checked rustup target add --toolchain $RustToolchain $Target

$RustAnalyzerSource = Join-Path $WorkDirectory "rust-analyzer"
$CargoSource = Join-Path $WorkDirectory "cargo"
Checkout-ExactCommit "https://github.com/rust-lang/rust-analyzer.git" $RustAnalyzerCommit $RustAnalyzerSource
Checkout-ExactCommit "https://github.com/rust-lang/cargo.git" $CargoCommit $CargoSource
Invoke-Checked git -C $RustAnalyzerSource apply --check $RustAnalyzerPatch
Invoke-Checked git -C $RustAnalyzerSource apply $RustAnalyzerPatch

$Sysroot = (& rustc "+$RustToolchain" --print sysroot).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Failed to resolve the pinned Rust sysroot"
}
$RustSource = Join-Path $Sysroot "lib\rustlib\src\rust"
Invoke-Checked git -C $RustSource apply --check $RustStdPatch
$RustSourcePatched = $false
try {
    Invoke-Checked git -C $RustSource apply $RustStdPatch
    $RustSourcePatched = $true
    $env:RUSTC_BOOTSTRAP = "1"

    $env:CFG_RELEASE = "0.3.2997-standalone"
    $env:CARGO_TARGET_DIR = Join-Path $WorkDirectory "rust-analyzer-target"
    Push-Location $RustAnalyzerSource
    try {
        Invoke-Checked cargo "+$RustToolchain" build -Z "build-std=std,panic_abort" --target $Target --release --locked -j 2 -p rust-analyzer
    } finally {
        Pop-Location
    }

    $env:CFG_RELEASE = "1.96.0"
    $env:CFG_RELEASE_CHANNEL = "stable"
    $env:CARGO_COMMIT_HASH = $CargoCommit
    $env:CARGO_COMMIT_SHORT_HASH = "30a34c682"
    $env:CARGO_COMMIT_DATE = "2026-05-25"
    $env:CARGO_TARGET_DIR = Join-Path $WorkDirectory "cargo-target"
    Push-Location $CargoSource
    try {
        Invoke-Checked cargo "+$RustToolchain" build -Z "build-std=std,panic_abort" --target $Target --release --locked -j 2 -p cargo
    } finally {
        Pop-Location
    }
} finally {
    if ($RustSourcePatched) {
        Invoke-Checked git -C $RustSource apply --reverse $RustStdPatch
    }
}

$Bundle = Join-Path $OutputDirectory $AssetName
$Bin = Join-Path $Bundle "bin"
New-Item -ItemType Directory -Path $Bin | Out-Null
$RustAnalyzer = Join-Path $WorkDirectory "rust-analyzer-target\$Target\release\rust-analyzer.exe"
$Cargo = Join-Path $WorkDirectory "cargo-target\$Target\release\cargo.exe"
Copy-Item -LiteralPath $RustAnalyzer -Destination (Join-Path $Bin "rust-analyzer.exe")
Copy-Item -LiteralPath $Cargo -Destination (Join-Path $Bin "cargo.exe")

$RustAnalyzerVersion = (& (Join-Path $Bin "rust-analyzer.exe") --version).Trim()
$CargoVersion = (& (Join-Path $Bin "cargo.exe") -Vv) -join "`n"
if ($RustAnalyzerVersion -ne "rust-analyzer 0.3.2997-standalone (b54a82b321 2026-08-02)") {
    throw "Unexpected rust-analyzer identity: $RustAnalyzerVersion"
}
if (-not $CargoVersion.Contains("commit-hash: $CargoCommit")) {
    throw "Unexpected Cargo identity: $CargoVersion"
}

$Archive = Join-Path $OutputDirectory "$AssetName.zip"
Write-DeterministicZip $Bundle $Archive
$RustAnalyzerHash = (Get-FileHash -Algorithm SHA256 (Join-Path $Bin "rust-analyzer.exe")).Hash.ToLowerInvariant()
$CargoHash = (Get-FileHash -Algorithm SHA256 (Join-Path $Bin "cargo.exe")).Hash.ToLowerInvariant()
$ArchiveHash = (Get-FileHash -Algorithm SHA256 $Archive).Hash.ToLowerInvariant()
@(
    "$RustAnalyzerHash  bin/rust-analyzer.exe"
    "$CargoHash  bin/cargo.exe"
    "$ArchiveHash  $AssetName.zip"
) | Set-Content -Encoding ascii (Join-Path $OutputDirectory "$AssetName.sha256")

$Provenance = [ordered]@{
    schema = "trysniff.windows-rust-indexer.v1"
    target = $Target
    rust_toolchain = $RustToolchain
    rust_analyzer_commit = $RustAnalyzerCommit
    cargo_commit = $CargoCommit
    rust_analyzer_patch_sha256 = (Get-FileHash -Algorithm SHA256 $RustAnalyzerPatch).Hash.ToLowerInvariant()
    rust_std_patch_sha256 = (Get-FileHash -Algorithm SHA256 $RustStdPatch).Hash.ToLowerInvariant()
    rust_analyzer_sha256 = $RustAnalyzerHash
    cargo_sha256 = $CargoHash
    archive_sha256 = $ArchiveHash
}
$ProvenancePath = Join-Path $OutputDirectory "$AssetName.provenance.json"
[System.IO.File]::WriteAllText(
    $ProvenancePath,
    ($Provenance | ConvertTo-Json),
    [System.Text.UTF8Encoding]::new($false)
)
Write-Output "ARCHIVE=$Archive"
Write-Output "SHA256=$ArchiveHash"
