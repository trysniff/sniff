param(
    [Parameter(Mandatory = $true)]
    [string]$BundleDirectory,

    [Parameter(Mandatory = $true)]
    [string]$ArchivePath,

    [Parameter(Mandatory = $true)]
    [string]$ProvenancePath,

    [Parameter(Mandatory = $true)]
    [string]$ChecksumPath,

    [Parameter(Mandatory = $true)]
    [string]$SbomPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-Equal {
    param([object]$Actual, [object]$Expected, [string]$Description)
    if ($Actual -cne $Expected) {
        throw "$Description mismatch: expected '$Expected', got '$Actual'"
    }
}

function Get-RelativeName {
    param([string]$Name)
    return $Name.Replace('\', '/').TrimStart('/')
}

$provenance = Get-Content -Raw -LiteralPath $ProvenancePath | ConvertFrom-Json
Assert-Equal $provenance.schema "trysniff.windows-rust-indexer.v1" "Provenance schema"
if ($provenance.target -cnotin @("x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc")) {
    throw "Unexpected Windows Rust indexer target: $($provenance.target)"
}
$assetName = "sniff-rust-indexer-$($provenance.target)"
Assert-Equal (Split-Path -Leaf $BundleDirectory) $assetName "Bundle name"
Assert-Equal (Split-Path -Leaf $ArchivePath) "$assetName.zip" "Archive name"
Assert-Equal (Split-Path -Leaf $ChecksumPath) "$assetName.sha256" "Checksum file name"
Assert-Equal (Split-Path -Leaf $SbomPath) "$assetName.spdx.json" "SBOM name"

$expected = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
$expected.Add("bin/cargo.exe", @{
    hash = $provenance.cargo_sha256
    version = $provenance.cargo_commit
})
$expected.Add("bin/rust-analyzer.exe", @{
    hash = $provenance.rust_analyzer_sha256
    version = $provenance.rust_analyzer_commit
})
Assert-Equal @($expected.Keys).Count 2 "Expected executable count"
$actualFiles = @(Get-ChildItem -LiteralPath $BundleDirectory -Recurse -File)
Assert-Equal $actualFiles.Count 2 "Bundle file count"
foreach ($name in $expected.Keys) {
    $entry = $expected[$name]
    if ($entry.hash -cnotmatch '^[0-9a-f]{64}$' -or $entry.version -cnotmatch '^[0-9a-f]{40}$') {
        throw "Invalid pinned source commit or SHA256 in provenance for $name"
    }
    $binaryPath = Join-Path $BundleDirectory ($name.Replace('/', [IO.Path]::DirectorySeparatorChar))
    if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {
        throw "Missing executable: $name"
    }
    Assert-Equal (Get-FileHash -Algorithm SHA256 -LiteralPath $binaryPath).Hash.ToLowerInvariant() $entry.hash "$name SHA256"
}
foreach ($file in $actualFiles) {
    $relative = [IO.Path]::GetRelativePath($BundleDirectory, $file.FullName).Replace('\', '/')
    if (-not $expected.ContainsKey($relative)) {
        throw "Unexpected bundle file: $relative"
    }
}
Assert-Equal (Get-FileHash -Algorithm SHA256 -LiteralPath $ArchivePath).Hash.ToLowerInvariant() $provenance.archive_sha256 "Archive SHA256"
$checksumLines = @(Get-Content -LiteralPath $ChecksumPath)
Assert-Equal $checksumLines.Count 3 "Checksum line count"
$checksums = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
foreach ($line in $checksumLines) {
    if ($line -cnotmatch '^([0-9a-f]{64})  (.+)$' -or $checksums.ContainsKey($Matches[2])) {
        throw "Invalid or duplicate checksum line: $line"
    }
    $checksums[$Matches[2]] = $Matches[1]
}
foreach ($name in $expected.Keys) {
    Assert-Equal $checksums[$name] $expected[$name].hash "$name checksum record"
}
Assert-Equal $checksums["$assetName.zip"] $provenance.archive_sha256 "Archive checksum record"

Add-Type -AssemblyName System.IO.Compression
$archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
try {
    Assert-Equal $archive.Entries.Count 2 "Archive entry count"
    $seenArchiveEntries = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($entry in $archive.Entries) {
        if (-not $expected.ContainsKey($entry.FullName) -or -not $seenArchiveEntries.Add($entry.FullName)) {
            throw "Unexpected or duplicate archive entry: $($entry.FullName)"
        }
        $stream = $entry.Open()
        $hasher = [Security.Cryptography.SHA256]::Create()
        try {
            $hash = [Convert]::ToHexString($hasher.ComputeHash($stream)).ToLowerInvariant()
            Assert-Equal $hash $expected[$entry.FullName].hash "$($entry.FullName) archive entry"
        } finally {
            $hasher.Dispose()
            $stream.Dispose()
        }
    }
} finally {
    $archive.Dispose()
}

$sbom = Get-Content -Raw -LiteralPath $SbomPath | ConvertFrom-Json
Assert-Equal $sbom.spdxVersion "SPDX-2.3" "SPDX version"
Assert-Equal $sbom.SPDXID "SPDXRef-DOCUMENT" "SPDX document ID"
Assert-Equal @($sbom.files).Count 2 "SPDX file count"
Assert-Equal @($sbom.packages).Count 3 "SPDX package count"
if (-not $sbom.creationInfo -or -not $sbom.creationInfo.creators) {
    throw "SPDX creation metadata is missing"
}

$seenFiles = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
foreach ($file in $sbom.files) {
    $name = Get-RelativeName $file.fileName
    if (-not $expected.ContainsKey($name) -or $seenFiles.ContainsKey($name)) {
        throw "Unexpected or duplicate SPDX file: $name"
    }
    $seenFiles[$name] = $file
    $binaryPath = Join-Path $BundleDirectory ($name.Replace('/', [IO.Path]::DirectorySeparatorChar))
    foreach ($checksum in @($file.checksums)) {
        if ($checksum.algorithm -cnotin @("SHA1", "SHA256")) {
            throw "Unexpected SPDX checksum algorithm for $name"
        }
        $actual = (Get-FileHash -Algorithm $checksum.algorithm -LiteralPath $binaryPath).Hash.ToLowerInvariant()
        $placeholder = $checksum.algorithm -ceq "SHA1" -and $checksum.checksumValue -ceq ('0' * 40)
        if (-not $placeholder -and $checksum.checksumValue -cne $actual) {
            throw "Incorrect existing SPDX checksum for $name"
        }
    }
    $file.checksums = @(@{ algorithm = "SHA256"; checksumValue = $expected[$name].hash })
}

$rootPackages = @($sbom.packages | Where-Object {
    $_.PSObject.Properties.Name -ccontains "primaryPackagePurpose" -and $_.primaryPackagePurpose -ceq "FILE"
})
Assert-Equal $rootPackages.Count 1 "SPDX root package count"
$root = $rootPackages[0]
$oldRootId = $root.SPDXID
$root.SPDXID = "SPDXRef-Package-$($assetName.Replace('_', '-'))"
$root.name = $assetName
$root | Add-Member -Force -NotePropertyName sourceInfo -NotePropertyValue "Binary bundle; this SBOM inventories shipped executables, not statically linked dependencies."

$seenPackages = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
foreach ($package in @($sbom.packages | Where-Object { $_.SPDXID -cne $root.SPDXID })) {
    $matches = @($expected.Keys | Where-Object {
        $package.name -ceq $_ -or
        $package.sourceInfo -cmatch ([regex]::Escape("\" + $_.Replace('/', '\')) + '$')
    })
    Assert-Equal $matches.Count 1 "SPDX binary package identity"
    $name = $matches[0]
    if ($seenPackages.ContainsKey($name)) {
        throw "Duplicate SPDX binary package: $name"
    }
    $seenPackages[$name] = $package
    $package.name = $name
    $package.versionInfo = $expected[$name].version
    $package.sourceInfo = "Built from pinned source commit $($expected[$name].version); executable SHA256 $($expected[$name].hash)."
}
Assert-Equal $seenPackages.Count 2 "SPDX binary package count"
foreach ($relationship in $sbom.relationships) {
    if ($relationship.spdxElementId -ceq $oldRootId) {
        $relationship.spdxElementId = $root.SPDXID
    }
    if ($relationship.relatedSpdxElement -ceq $oldRootId) {
        $relationship.relatedSpdxElement = $root.SPDXID
    }
}
$ids = @($sbom.files.SPDXID) + @($sbom.packages.SPDXID)
Assert-Equal (@($ids | Select-Object -Unique).Count) $ids.Count "Unique SPDX IDs"
foreach ($id in $ids) {
    if ($id -cnotmatch '^SPDXRef-[A-Za-z0-9.-]+$') {
        throw "Invalid SPDX ID: $id"
    }
}
foreach ($relationship in $sbom.relationships) {
    if ($relationship.spdxElementId -cnotin $ids -and $relationship.spdxElementId -cne "SPDXRef-DOCUMENT") {
        throw "Unresolved SPDX relationship source: $($relationship.spdxElementId)"
    }
    if ($relationship.relatedSpdxElement -cnotin $ids) {
        throw "Unresolved SPDX relationship target: $($relationship.relatedSpdxElement)"
    }
}
Assert-Equal @($sbom.relationships).Count 5 "SPDX relationship count"
foreach ($name in $expected.Keys) {
    $packageId = $seenPackages[$name].SPDXID
    $fileId = $seenFiles[$name].SPDXID
    Assert-Equal @($sbom.relationships | Where-Object {
        $_.spdxElementId -ceq $packageId -and $_.relatedSpdxElement -ceq $fileId -and $_.relationshipType -ceq "OTHER"
    }).Count 1 "$name package-to-file relationship"
    Assert-Equal @($sbom.relationships | Where-Object {
        $_.spdxElementId -ceq $root.SPDXID -and $_.relatedSpdxElement -ceq $packageId -and $_.relationshipType -ceq "CONTAINS"
    }).Count 1 "$name root-to-package relationship"
}
Assert-Equal @($sbom.relationships | Where-Object {
    $_.spdxElementId -ceq "SPDXRef-DOCUMENT" -and $_.relatedSpdxElement -ceq $root.SPDXID -and $_.relationshipType -ceq "DESCRIBES"
}).Count 1 "SPDX document relationship"
$sbom.name = $assetName
$finalizerCreator = "Tool: sniff-windows-rust-sbom-finalizer-1"
if ($sbom.creationInfo.creators -cnotcontains $finalizerCreator) {
    $sbom.creationInfo.creators = @($sbom.creationInfo.creators) + @($finalizerCreator)
}
$sbom.documentNamespace = ""
$canonicalDocument = $sbom | ConvertTo-Json -Depth 32 -Compress
$documentHash = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($canonicalDocument))
).ToLowerInvariant()
$sbom.documentNamespace = "https://github.com/trysniff/sniff/sbom/$assetName/$documentHash"
$temporary = "$SbomPath.tmp"
try {
    [IO.File]::WriteAllText($temporary, ($sbom | ConvertTo-Json -Depth 32), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $SbomPath -Force
} finally {
    if (Test-Path -LiteralPath $temporary) {
        Remove-Item -LiteralPath $temporary
    }
}
