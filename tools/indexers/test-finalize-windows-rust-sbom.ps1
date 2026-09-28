$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$temp = Join-Path ([IO.Path]::GetTempPath()) ("sniff-sbom-test-" + [guid]::NewGuid())
$asset = "sniff-rust-indexer-x86_64-pc-windows-msvc"
$bundle = Join-Path $temp $asset
$archive = Join-Path $temp "$asset.zip"
$provenancePath = Join-Path $temp "$asset.provenance.json"
$checksumPath = Join-Path $temp "$asset.sha256"
$sbomPath = Join-Path $temp "$asset.spdx.json"
$finalizer = Join-Path $PSScriptRoot "finalize-windows-rust-sbom.ps1"

function Invoke-Finalizer {
    & $finalizer -BundleDirectory $bundle -ArchivePath $archive `
        -ProvenancePath $provenancePath -ChecksumPath $checksumPath -SbomPath $sbomPath
}

function Assert-Rejected {
    param([scriptblock]$Mutation, [string]$Case)
    [IO.File]::WriteAllText($sbomPath, $originalSbom, [Text.UTF8Encoding]::new($false))
    & $Mutation
    $before = [IO.File]::ReadAllText($sbomPath)
    try {
        Invoke-Finalizer
        throw "Expected rejection: $Case"
    } catch {
        if ($_.Exception.Message -ceq "Expected rejection: $Case") {
            throw
        }
    }
    if ([IO.File]::ReadAllText($sbomPath) -cne $before) {
        throw "Failed verification changed the SBOM: $Case"
    }
}

try {
    New-Item -ItemType Directory -Path (Join-Path $bundle "bin") -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $bundle "bin\cargo.exe"), "cargo fixture")
    [IO.File]::WriteAllText((Join-Path $bundle "bin\rust-analyzer.exe"), "rust-analyzer fixture")
    $cargoHash = (Get-FileHash -Algorithm SHA256 (Join-Path $bundle "bin\cargo.exe")).Hash.ToLowerInvariant()
    $analyzerHash = (Get-FileHash -Algorithm SHA256 (Join-Path $bundle "bin\rust-analyzer.exe")).Hash.ToLowerInvariant()
    $zip = [IO.Compression.ZipFile]::Open($archive, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in @("cargo.exe", "rust-analyzer.exe")) {
            $entry = $zip.CreateEntry("bin/$name")
            $inputStream = [IO.File]::OpenRead((Join-Path $bundle "bin\$name"))
            $outputStream = $entry.Open()
            try { $inputStream.CopyTo($outputStream) } finally {
                $outputStream.Dispose()
                $inputStream.Dispose()
            }
        }
    } finally { $zip.Dispose() }
    $archiveHash = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant()
    $provenance = @{
        schema = "trysniff.windows-rust-indexer.v1"
        target = "x86_64-pc-windows-msvc"
        cargo_sha256 = $cargoHash
        rust_analyzer_sha256 = $analyzerHash
        archive_sha256 = $archiveHash
        cargo_commit = "a" * 40
        rust_analyzer_commit = "b" * 40
    }
    [IO.File]::WriteAllText($provenancePath, ($provenance | ConvertTo-Json))
    @(
        "$analyzerHash  bin/rust-analyzer.exe"
        "$cargoHash  bin/cargo.exe"
        "$archiveHash  $asset.zip"
    ) | Set-Content -Encoding ascii -LiteralPath $checksumPath
    $sbom = @{
        spdxVersion = "SPDX-2.3"
        SPDXID = "SPDXRef-DOCUMENT"
        name = "CI temporary path"
        documentNamespace = "https://example.com/temporary"
        creationInfo = @{ creators = @("Tool: syft-1.42.3"); created = "2026-01-01T00:00:00Z" }
        packages = @(
            @{ SPDXID = "SPDXRef-Cargo"; name = "\bin\cargo"; sourceInfo = "acquired package info from the following paths: \bin\cargo.exe"; versionInfo = "UNKNOWN"; filesAnalyzed = $false }
            @{ SPDXID = "SPDXRef-Analyzer"; name = "\bin\rust-analyzer"; sourceInfo = "acquired package info from the following paths: \bin\rust-analyzer.exe"; versionInfo = "UNKNOWN"; filesAnalyzed = $false }
            @{ SPDXID = "SPDXRef-Root"; name = "CI temporary path"; primaryPackagePurpose = "FILE"; filesAnalyzed = $false }
        )
        files = @(
            @{ SPDXID = "SPDXRef-CargoFile"; fileName = "\bin\cargo.exe"; checksums = @(@{ algorithm = "SHA1"; checksumValue = "0" * 40 }) }
            @{ SPDXID = "SPDXRef-AnalyzerFile"; fileName = "\bin\rust-analyzer.exe"; checksums = @(@{ algorithm = "SHA1"; checksumValue = "0" * 40 }) }
        )
        relationships = @(
            @{ spdxElementId = "SPDXRef-Cargo"; relatedSpdxElement = "SPDXRef-CargoFile"; relationshipType = "OTHER" }
            @{ spdxElementId = "SPDXRef-Analyzer"; relatedSpdxElement = "SPDXRef-AnalyzerFile"; relationshipType = "OTHER" }
            @{ spdxElementId = "SPDXRef-Root"; relatedSpdxElement = "SPDXRef-Cargo"; relationshipType = "CONTAINS" }
            @{ spdxElementId = "SPDXRef-Root"; relatedSpdxElement = "SPDXRef-Analyzer"; relationshipType = "CONTAINS" }
            @{ spdxElementId = "SPDXRef-DOCUMENT"; relatedSpdxElement = "SPDXRef-Root"; relationshipType = "DESCRIBES" }
        )
    }
    $originalSbom = $sbom | ConvertTo-Json -Depth 20
    [IO.File]::WriteAllText($sbomPath, $originalSbom)
    Invoke-Finalizer
    $finished = Get-Content -Raw -LiteralPath $sbomPath | ConvertFrom-Json
    foreach ($file in $finished.files) {
        if ($file.checksums[0].algorithm -cne "SHA256" -or $file.checksums[0].checksumValue -ceq ('0' * 64)) {
            throw "Finalized SBOM lacks a real SHA256"
        }
        if ($file.fileName -cnotmatch '^\./bin/(cargo|rust-analyzer)\.exe$') {
            throw "Finalized SBOM file name is not canonical"
        }
    }
    if ($finished.creationInfo.creators -cnotcontains "Tool: sniff-windows-rust-sbom-finalizer-1") {
        throw "Finalized SBOM does not attribute the verifier"
    }
    foreach ($id in @($finished.packages.SPDXID) + @($finished.files.SPDXID)) {
        if ($id -cnotmatch '^SPDXRef-[A-Za-z0-9.-]+$') {
            throw "Invalid finalized SPDX ID: $id"
        }
    }
    $namespace = $finished.documentNamespace
    Invoke-Finalizer
    if ((Get-Content -Raw -LiteralPath $sbomPath | ConvertFrom-Json).documentNamespace -cne $namespace) {
        throw "Finalized SBOM namespace changed on rerun"
    }

    Assert-Rejected { Set-Content -LiteralPath (Join-Path $bundle "bin\cargo.exe") -Value "tampered" } "changed bundle byte"
    [IO.File]::WriteAllText((Join-Path $bundle "bin\cargo.exe"), "cargo fixture")
    Assert-Rejected { [IO.File]::WriteAllText((Join-Path $bundle "bin\extra.exe"), "extra") } "extra bundle file"
    Remove-Item -LiteralPath (Join-Path $bundle "bin\extra.exe")
    Assert-Rejected {
        $bad = $originalSbom | ConvertFrom-Json
        $bad.files[0].checksums[0].checksumValue = "f" * 40
        [IO.File]::WriteAllText($sbomPath, ($bad | ConvertTo-Json -Depth 20))
    } "incorrect existing checksum"
    Assert-Rejected {
        $bad = $originalSbom | ConvertFrom-Json
        $bad.relationships[0].relatedSpdxElement = "SPDXRef-AnalyzerFile"
        [IO.File]::WriteAllText($sbomPath, ($bad | ConvertTo-Json -Depth 20))
    } "mislinked package"
    Assert-Rejected {
        $bad = $originalSbom | ConvertFrom-Json
        $bad.files[1].fileName = $bad.files[0].fileName
        [IO.File]::WriteAllText($sbomPath, ($bad | ConvertTo-Json -Depth 20))
    } "duplicate file"
    Assert-Rejected {
        $bad = $originalSbom | ConvertFrom-Json
        $bad.files[0].fileName = "\BIN\CARGO.EXE"
        [IO.File]::WriteAllText($sbomPath, ($bad | ConvertTo-Json -Depth 20))
    } "uppercase SPDX file path"
    Assert-Rejected {
        $bad = $originalSbom | ConvertFrom-Json
        $bad.files[0].fileName = "\\bin\cargo.exe"
        [IO.File]::WriteAllText($sbomPath, ($bad | ConvertTo-Json -Depth 20))
    } "double-leading-separator SPDX file path"
    Assert-Rejected {
        $bad = $originalSbom | ConvertFrom-Json
        $bad.packages[0].sourceInfo = "acquired package info from the following paths: \bin\rust-analyzer.exe"
        [IO.File]::WriteAllText($sbomPath, ($bad | ConvertTo-Json -Depth 20))
    } "contradictory package evidence"
    Assert-Rejected {
        $bad = $originalSbom | ConvertFrom-Json
        $bad.packages[0].filesAnalyzed = $true
        [IO.File]::WriteAllText($sbomPath, ($bad | ConvertTo-Json -Depth 20))
    } "unsupported file-analysis claim"
    Assert-Rejected {
        $zip = [IO.Compression.ZipFile]::Open($archive, [IO.Compression.ZipArchiveMode]::Update)
        try {
            $zip.GetEntry("bin/cargo.exe").Delete()
            $entry = $zip.CreateEntry("BIN/CARGO.EXE")
            $stream = $entry.Open()
            try {
                $bytes = [Text.Encoding]::UTF8.GetBytes("cargo fixture")
                $stream.Write($bytes, 0, $bytes.Length)
            } finally { $stream.Dispose() }
        } finally { $zip.Dispose() }
        $newHash = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant()
        $changedProvenance = $provenance.Clone()
        $changedProvenance.archive_sha256 = $newHash
        [IO.File]::WriteAllText($provenancePath, ($changedProvenance | ConvertTo-Json))
        @(
            "$analyzerHash  bin/rust-analyzer.exe"
            "$cargoHash  bin/cargo.exe"
            "$newHash  $asset.zip"
        ) | Set-Content -Encoding ascii -LiteralPath $checksumPath
    } "uppercase archive entry"
    Write-Output "Windows Rust SBOM finalizer tests passed"
} finally {
    if (Test-Path -LiteralPath $temp) {
        $resolvedTemp = [IO.Path]::GetFullPath($temp).TrimEnd([IO.Path]::DirectorySeparatorChar)
        $expectedParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar)
        if ([IO.Path]::GetDirectoryName($resolvedTemp) -cne $expectedParent -or
            -not [IO.Path]::GetFileName($resolvedTemp).StartsWith("sniff-sbom-test-")) {
            throw "Refusing to remove an unexpected test directory: $resolvedTemp"
        }
        Remove-Item -LiteralPath $temp -Recurse -Force
    }
}
