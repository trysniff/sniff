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
[UInt32]$SourceDateEpoch = 1785628800
$Target = "$Architecture-pc-windows-msvc"
$AssetName = "sniff-rust-indexer-$Target"
$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$RustAnalyzerPatch = Join-Path $RepositoryRoot "tools\indexers\patches\rust-analyzer-windows-appcontainer.patch"
$RustStdPatch = Join-Path $RepositoryRoot "tools\indexers\patches\rust-std-windows-appcontainer.patch"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,
        [string[]]$ArgumentList = @()
    )
    & $Executable @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "$Executable failed with exit code $LASTEXITCODE"
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
    Invoke-Checked -Executable "git" -ArgumentList @(
        "clone", "--config", "core.autocrlf=false", "--filter=blob:none", "--no-checkout",
        $Url, $Directory
    )
    Invoke-Checked -Executable "git" -ArgumentList @(
        "-C", $Directory, "fetch", "--depth", "1", "origin", $Commit
    )
    Invoke-Checked -Executable "git" -ArgumentList @(
        "-C", $Directory, "checkout", "--detach", "FETCH_HEAD"
    )
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

function Assert-NoHostBuildPaths {
    param(
        [string[]]$BinaryPaths,
        [string[]]$HostPaths
    )
    $encoding = [System.Text.Encoding]::GetEncoding(28591)
    foreach ($binary in $BinaryPaths) {
        $contents = $encoding.GetString([System.IO.File]::ReadAllBytes($binary))
        foreach ($path in $HostPaths) {
            foreach ($variant in @($path, $path.Replace("\", "/")) | Select-Object -Unique) {
                if ($contents.IndexOf($variant, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    throw "Built binary contains an unremapped host path ${variant}: $binary"
                }
            }
        }
    }
}

function Assert-ReproduciblePeImage {
    param([string[]]$BinaryPaths)
    foreach ($binary in $BinaryPaths) {
        $bytes = [System.IO.File]::ReadAllBytes($binary)
        if ($bytes.Length -lt 0x40 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
            throw "Built binary is not a PE image: $binary"
        }
        $peOffset = [System.BitConverter]::ToInt32($bytes, 0x3c)
        if ($peOffset -lt 0 -or $peOffset + 12 -gt $bytes.Length) {
            throw "Built binary has an invalid PE header offset: $binary"
        }
        $timestamp = [System.BitConverter]::ToUInt32($bytes, $peOffset + 8)
        if ($timestamp -eq $SourceDateEpoch) {
            throw "PE image uses the source epoch as a mutable timestamp instead of a /Brepro content hash: $binary"
        }

        $optionalHeader = $peOffset + 24
        $magic = [System.BitConverter]::ToUInt16($bytes, $optionalHeader)
        $dataDirectory = switch ($magic) {
            0x10b { $optionalHeader + 96 }
            0x20b { $optionalHeader + 112 }
            default { throw "Built binary has an unsupported PE optional header: $binary" }
        }
        $debugRva = [System.BitConverter]::ToUInt32($bytes, $dataDirectory + (6 * 8))
        $debugSize = [System.BitConverter]::ToUInt32($bytes, $dataDirectory + (6 * 8) + 4)
        if ($debugRva -eq 0 -or $debugSize -eq 0) {
            continue
        }
        if ($debugSize % 28 -ne 0) {
            throw "Built binary has a malformed PE debug directory: $binary"
        }

        $sectionCount = [System.BitConverter]::ToUInt16($bytes, $peOffset + 6)
        $optionalHeaderSize = [System.BitConverter]::ToUInt16($bytes, $peOffset + 20)
        $sectionTable = $optionalHeader + $optionalHeaderSize
        $debugOffset = $null
        for ($index = 0; $index -lt $sectionCount; $index++) {
            $section = $sectionTable + ($index * 40)
            $virtualSize = [System.BitConverter]::ToUInt32($bytes, $section + 8)
            $virtualAddress = [System.BitConverter]::ToUInt32($bytes, $section + 12)
            $rawSize = [System.BitConverter]::ToUInt32($bytes, $section + 16)
            $rawOffset = [System.BitConverter]::ToUInt32($bytes, $section + 20)
            $mappedSize = [Math]::Max($virtualSize, $rawSize)
            if ($debugRva -ge $virtualAddress -and $debugRva -lt $virtualAddress + $mappedSize) {
                $debugOffset = $rawOffset + ($debugRva - $virtualAddress)
                break
            }
        }
        if ($null -eq $debugOffset -or $debugOffset + $debugSize -gt $bytes.Length) {
            throw "Built binary has an unmappable PE debug directory: $binary"
        }
        for ($offset = $debugOffset; $offset -lt $debugOffset + $debugSize; $offset += 28) {
            $debugType = [System.BitConverter]::ToUInt32($bytes, $offset + 12)
            if ($debugType -eq 2) {
                throw "PE image contains a nondeterministic CodeView/PDB record: $binary"
            }
        }
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
$PhysicalWorkDirectory = (Resolve-Path -LiteralPath $WorkDirectory).Path
$BuildDrive = "R:"
$BuildDriveRoot = "$BuildDrive\"
if (Test-Path -LiteralPath $BuildDriveRoot) {
    throw "Deterministic build drive is already in use: $BuildDrive"
}
Invoke-Checked -Executable "subst.exe" -ArgumentList @($BuildDrive, $PhysicalWorkDirectory)
$WorkDirectory = $BuildDriveRoot
$DeterministicHomeNames = @("CARGO_HOME", "RUSTUP_HOME")
$OriginalDeterministicHomes = @{}
foreach ($name in $DeterministicHomeNames) {
    $OriginalDeterministicHomes[$name] = [System.Environment]::GetEnvironmentVariable(
        $name,
        [System.EnvironmentVariableTarget]::Process
    )
}
try {
$env:CARGO_HOME = Join-Path $WorkDirectory "cargo-home"
$env:RUSTUP_HOME = Join-Path $WorkDirectory "rustup-home"
New-Item -ItemType Directory -Path $env:CARGO_HOME | Out-Null
New-Item -ItemType Directory -Path $env:RUSTUP_HOME | Out-Null

Invoke-Checked -Executable "rustup" -ArgumentList @(
    "toolchain", "install", $RustToolchain, "--profile", "minimal", "--component", "rust-src"
)
Invoke-Checked -Executable "rustup" -ArgumentList @(
    "target", "add", "--toolchain", $RustToolchain, $Target
)

$RustAnalyzerSource = Join-Path $WorkDirectory "rust-analyzer"
$CargoSource = Join-Path $WorkDirectory "cargo"
Checkout-ExactCommit "https://github.com/rust-lang/rust-analyzer.git" $RustAnalyzerCommit $RustAnalyzerSource
Checkout-ExactCommit "https://github.com/rust-lang/cargo.git" $CargoCommit $CargoSource
Invoke-Checked -Executable "git" -ArgumentList @(
    "-C", $RustAnalyzerSource, "apply", "--check", $RustAnalyzerPatch
)
Invoke-Checked -Executable "git" -ArgumentList @(
    "-C", $RustAnalyzerSource, "apply", $RustAnalyzerPatch
)

$Sysroot = (& rustc "+$RustToolchain" --print sysroot).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Failed to resolve the pinned Rust sysroot"
}
$RustSource = Join-Path $Sysroot "lib\rustlib\src\rust"
$CargoHome = (Resolve-Path -LiteralPath $env:CARGO_HOME).Path
$PathRemaps = @(
    [ordered]@{ Source = $env:USERPROFILE; Destination = "Z:\host-home" }
    [ordered]@{ Source = $RepositoryRoot; Destination = "Z:\sniff-source" }
    [ordered]@{ Source = $PhysicalWorkDirectory; Destination = "Z:\sniff-build" }
    [ordered]@{ Source = $CargoHome; Destination = "Z:\cargo-home" }
    [ordered]@{ Source = $Sysroot; Destination = "Z:\rust-toolchain" }
)
$RejectedHostPaths = @(
    $env:USERPROFILE
    $RepositoryRoot
    $PhysicalWorkDirectory
    $Sysroot
)
$EncodedRustFlags = [System.Collections.Generic.List[string]]::new()
foreach ($remap in $PathRemaps) {
    foreach ($variant in @(
        [ordered]@{ Source = $remap.Source; Destination = $remap.Destination }
        [ordered]@{
            Source = $remap.Source.Replace("\", "/")
            Destination = $remap.Destination.Replace("\", "/")
        }
    )) {
        $EncodedRustFlags.Add("--remap-path-prefix")
        $EncodedRustFlags.Add("$($variant.Source)=$($variant.Destination)")
    }
}
$EncodedRustFlags.Add("-C")
$EncodedRustFlags.Add("link-arg=/Brepro")
$EncodedRustFlags.Add("-C")
$EncodedRustFlags.Add("link-arg=/DEBUG:NONE")

$BuildEnvironmentNames = @(
    "CARGO_BUILD_RUSTFLAGS"
    "CARGO_COMMIT_DATE"
    "CARGO_COMMIT_HASH"
    "CARGO_COMMIT_SHORT_HASH"
    "CARGO_ENCODED_RUSTFLAGS"
    "CARGO_INCREMENTAL"
    "CARGO_TARGET_DIR"
    "CFG_RELEASE"
    "CFG_RELEASE_CHANNEL"
    "RUSTC_BOOTSTRAP"
    "RUSTC_WORKSPACE_WRAPPER"
    "RUSTC_WRAPPER"
    "RUSTFLAGS"
    "SOURCE_DATE_EPOCH"
)
$OriginalBuildEnvironment = @{}
foreach ($name in $BuildEnvironmentNames) {
    $OriginalBuildEnvironment[$name] = [System.Environment]::GetEnvironmentVariable(
        $name,
        [System.EnvironmentVariableTarget]::Process
    )
    [System.Environment]::SetEnvironmentVariable(
        $name,
        $null,
        [System.EnvironmentVariableTarget]::Process
    )
}

try {
    $env:CARGO_ENCODED_RUSTFLAGS = $EncodedRustFlags -join [char]0x1f
    $env:CARGO_INCREMENTAL = "0"
    $env:SOURCE_DATE_EPOCH = $SourceDateEpoch.ToString([System.Globalization.CultureInfo]::InvariantCulture)
    Invoke-Checked -Executable "git" -ArgumentList @(
        "-C", $RustSource, "apply", "--check", $RustStdPatch
    )
    $RustSourcePatched = $false
    try {
        Invoke-Checked -Executable "git" -ArgumentList @(
            "-C", $RustSource, "apply", $RustStdPatch
        )
        $RustSourcePatched = $true
        $env:RUSTC_BOOTSTRAP = "1"

        $env:CFG_RELEASE = "0.3.2997-standalone"
        $env:CARGO_TARGET_DIR = Join-Path $WorkDirectory "rust-analyzer-target"
        Push-Location $RustAnalyzerSource
        try {
            Invoke-Checked -Executable "cargo" -ArgumentList @(
                "+$RustToolchain", "build", "-Z", "build-std=std,panic_abort", "--target", $Target,
                "--release", "--locked", "-j", "2", "-p", "rust-analyzer"
            )
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
            Invoke-Checked -Executable "cargo" -ArgumentList @(
                "+$RustToolchain", "build", "-Z", "build-std=std,panic_abort", "--target", $Target,
                "--release", "--locked", "-j", "2", "-p", "cargo"
            )
        } finally {
            Pop-Location
        }
    } finally {
        if ($RustSourcePatched) {
            Invoke-Checked -Executable "git" -ArgumentList @(
                "-C", $RustSource, "apply", "--reverse", $RustStdPatch
            )
        }
    }
} finally {
    foreach ($name in $BuildEnvironmentNames) {
        [System.Environment]::SetEnvironmentVariable(
            $name,
            $OriginalBuildEnvironment[$name],
            [System.EnvironmentVariableTarget]::Process
        )
    }
}

$Bundle = Join-Path $OutputDirectory $AssetName
$Bin = Join-Path $Bundle "bin"
New-Item -ItemType Directory -Path $Bin | Out-Null
$RustAnalyzer = Join-Path $WorkDirectory "rust-analyzer-target\$Target\release\rust-analyzer.exe"
$Cargo = Join-Path $WorkDirectory "cargo-target\$Target\release\cargo.exe"
Copy-Item -LiteralPath $RustAnalyzer -Destination (Join-Path $Bin "rust-analyzer.exe")
Copy-Item -LiteralPath $Cargo -Destination (Join-Path $Bin "cargo.exe")
Assert-NoHostBuildPaths `
    -BinaryPaths @((Join-Path $Bin "rust-analyzer.exe"), (Join-Path $Bin "cargo.exe")) `
    -HostPaths $RejectedHostPaths
Assert-ReproduciblePeImage `
    -BinaryPaths @((Join-Path $Bin "rust-analyzer.exe"), (Join-Path $Bin "cargo.exe"))

$RustAnalyzerVersion = (& (Join-Path $Bin "rust-analyzer.exe") --version).Trim()
$CargoVersion = (& (Join-Path $Bin "cargo.exe") -Vv) -join "`n"
if ($RustAnalyzerVersion -notmatch '^rust-analyzer 0\.3\.2997-standalone \(([0-9a-f]+) 2026-08-02\)$') {
    throw "Unexpected rust-analyzer identity: $RustAnalyzerVersion"
}
$RustAnalyzerCommitPrefix = $Matches[1]
if ($RustAnalyzerCommitPrefix.Length -lt 9 -or -not $RustAnalyzerCommit.StartsWith($RustAnalyzerCommitPrefix)) {
    throw "Unexpected rust-analyzer commit abbreviation: $RustAnalyzerCommitPrefix"
}
if (-not $CargoVersion.Contains("commit-hash: $CargoCommit")) {
    throw "Unexpected Cargo identity: $CargoVersion"
}

$Archive = Join-Path $OutputDirectory "$AssetName.zip"
Write-DeterministicZip $Bundle $Archive
$RustAnalyzerHash = (Get-FileHash -Algorithm SHA256 (Join-Path $Bin "rust-analyzer.exe")).Hash.ToLowerInvariant()
$CargoHash = (Get-FileHash -Algorithm SHA256 (Join-Path $Bin "cargo.exe")).Hash.ToLowerInvariant()
$ArchiveHash = (Get-FileHash -Algorithm SHA256 $Archive).Hash.ToLowerInvariant()
$SniffSourceCommit = (& git -C $RepositoryRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $SniffSourceCommit -notmatch "^[0-9a-f]{40}$") {
    throw "Failed to resolve the Sniff source commit"
}
@(
    "$RustAnalyzerHash  bin/rust-analyzer.exe"
    "$CargoHash  bin/cargo.exe"
    "$ArchiveHash  $AssetName.zip"
) | Set-Content -Encoding ascii (Join-Path $OutputDirectory "$AssetName.sha256")

$Provenance = [ordered]@{
    schema = "trysniff.windows-rust-indexer.v1"
    reproducible_build_contract = "windows-rust-v2"
    linker_reproducibility = "msvc-/Brepro-/DEBUG:NONE"
    source_date_epoch = $SourceDateEpoch.ToString([System.Globalization.CultureInfo]::InvariantCulture)
    sniff_source_commit = $SniffSourceCommit
    build_script_sha256 = (Get-FileHash -Algorithm SHA256 $PSCommandPath).Hash.ToLowerInvariant()
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
} finally {
    foreach ($name in $DeterministicHomeNames) {
        [System.Environment]::SetEnvironmentVariable(
            $name,
            $OriginalDeterministicHomes[$name],
            [System.EnvironmentVariableTarget]::Process
        )
    }
    Invoke-Checked -Executable "subst.exe" -ArgumentList @($BuildDrive, "/D")
}
