#!/usr/bin/env python3
"""Validate and transport the frozen historical-v2 assessment state."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import sys
import tarfile
from collections.abc import Mapping, Sequence
from typing import Any

ALLOWED_ARCHIVE_ROOTS = frozenset(
    {
        "historical-v2-assessment-state",
        "historical-v2-assessment-work",
        "historical-v2-assessment-frame",
        "historical-v2-assessment-transport",
    }
)
MAX_ARCHIVE_MEMBERS = 2_000_000
MAX_EXTRACTED_BYTES = 20 * 1024 * 1024 * 1024
MAX_MEMBER_PATH_BYTES = 4096
TOOLS_WORKFLOW = ".github/workflows/sniffbench-historical-v2-tools.yml"
TOOLS_ARTIFACT_PREFIX = "historical-v2-assessment-tools-"
TOOLS_ARTIFACT_MAX_BYTES = 128 * 1024 * 1024
TOOLS_PROVENANCE_SCHEMA = "sniffbench-historical-v2-tools-provenance-v1"

FRAME_RUN_ID = 32_804_623_556
FRAME_RUN_ATTEMPT = 1
FRAME_COLLECTOR_SHA = "8681f9c379c4e4817c7ed49f06f47f4c47d1f91b"
FRAME_ARTIFACT_ID = 9_547_888_605
FRAME_ARTIFACT_NAME = "historical-v2-frame-32804623556"
FRAME_ARTIFACT_DIGEST = (
    "sha256:542174315793a4a46c5c897ef549273f3202a36afdf464ed9ddaa65cc9ffbe7b"
)
FRAME_ARTIFACT_SIZE = 25_669_281
FRAME_CHECKSUMS_SHA256 = (
    "d7c0bb8d0c47d58ad9d30017ca30201c317445eac9f865e3d7dd1cfcb7f228c2"
)
DATASET_REVISION = "40faf2c1bb160de625f3c3270ac9d62ea45f3f9c"
PROTOCOL_SHA256 = "deb98a285867fc5ea52761c252839d74268f239824bfc1a82027a352695cfc6f"
FRAME_SHA256 = "f0df01a6d8e1de08cec21c10bc232f65c375bca28092c53ffb78b8e6954dbf32"
EXCLUSION_MANIFEST_SHA256 = (
    "1a6d6c9c4e58bcb2b30161c13d3711a8bf028ccbb666c7e6d965df4fb933f08c"
)
SELECTION_SHA256 = "d37f4bef7616e5da5dd08b161e497432aa42c5eba32d633da9a9b431d65e98e3"
PAYLOADS_SHA256 = "16b1da8b149a1ecc9d101eef05435b9d1ac504044ebbd644922d39ecc3999bd5"
STORAGE_MIGRATION_NAME = "compact-stage-artifact-json-v1"
STORAGE_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-collector-storage-migration-v1"
)
STORAGE_MIGRATION_FROM_COLLECTOR_SHA = (
    "655093e6d55bdcb6e85560136f07c20c35f1f4ba"
)
STORAGE_MIGRATION_TO_COLLECTOR_SHA = (
    "bb658f593e144a659624c294c0db133facb29003"
)
STORAGE_MIGRATION_SOURCE_RUN_ID = 33_085_745_961
STORAGE_MIGRATION_SOURCE_ARTIFACT_ID = 9_662_095_012
STORAGE_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:94585d826d841663b295bcc04519d1b568ecdd98714e7ecc7dc0e03074d2c4a0"
)
STORAGE_MIGRATION_SOURCE_ARTIFACT_SIZE = 348_102_634

GO_PREPARATION_MIGRATION_NAME = "package-scoped-go-dependency-preparation-v1"
GO_PREPARATION_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-go-preparation-migration-v1"
)
GO_PREPARATION_MIGRATION_FROM_COLLECTOR_SHA = STORAGE_MIGRATION_TO_COLLECTOR_SHA
GO_PREPARATION_MIGRATION_SOURCE_RUN_ID = 33_138_117_044
GO_PREPARATION_MIGRATION_SOURCE_ARTIFACT_ID = 9_674_042_205
GO_PREPARATION_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:f01e1a276cef8a9204ccfd047a51bb80c30bc351beac30ff764e55c4285a8cad"
)
GO_PREPARATION_MIGRATION_SOURCE_ARTIFACT_SIZE = 126_829_676

GO_MODULE_DOWNLOAD_MIGRATION_NAME = "declared-go-module-dependency-preparation-v1"
GO_MODULE_DOWNLOAD_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-go-module-download-migration-v1"
)
GO_MODULE_DOWNLOAD_MIGRATION_FROM_COLLECTOR_SHA = (
    "103d417c1fd90b2021c20f711e738d2c987b4fe0"
)
GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_RUN_ID = 33_172_568_078
GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_ARTIFACT_ID = 9_687_113_771
GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:e369c48d6c9df58f294edc48a4d9ede079dbd16ab008df75b404d8331f591e68"
)
GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_ARTIFACT_SIZE = 139_547_601

GO_PROJECT_ROOT_MIGRATION_NAME = "strict-go-project-root-validation-v1"
GO_PROJECT_ROOT_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-go-project-root-validation-migration-v1"
)
GO_PROJECT_ROOT_MIGRATION_FROM_COLLECTOR_SHA = (
    "8c66843fa6a889b2d61136bc97775ae70c28b459"
)
GO_PROJECT_ROOT_MIGRATION_SOURCE_RUN_ID = 33_206_916_893
GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_ID = 9_700_530_746
GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:d3b2ab951c6693d2e71863570bdca7df981311126265d434d37e1dbb29a91c0f"
)
GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_SIZE = 214_017_406

GO_EOF_PARSER_MIGRATION_NAME = "valid-go-eof-parser-v1"
GO_EOF_PARSER_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-go-eof-parser-migration-v1"
)
GO_EOF_PARSER_MIGRATION_FROM_COLLECTOR_SHA = (
    "eac13353d39aa3f6b0dd0a27f6236d39637e6ce5"
)
GO_EOF_PARSER_MIGRATION_SOURCE_RUN_ID = 33_222_053_747
GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_ID = 9_707_546_228
GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:c84330141739d038d247b9ab732b25474d9e6f14eddd0e66dfa6ef1307b588f2"
)
GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_SIZE = 154_813_306

RESUME_SYMLINK_MIGRATION_NAME = "validated-resume-symlink-extraction-v1"
RESUME_SYMLINK_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-resume-symlink-extraction-migration-v1"
)
RESUME_SYMLINK_MIGRATION_FROM_COLLECTOR_SHA = (
    "e044b4cdd238b13429f9c364eb3370e3939ffef7"
)
RESUME_SYMLINK_MIGRATION_SOURCE_RUN_ID = 33_277_931_633
RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_ID = 9_725_671_517
RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:1be3107f6857e785e6d5ca5316009f354464065bb8de6adeb4737d6c0c769936"
)
RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_SIZE = 390_116_536

GIT_BLOB_SOURCE_CENSUS_MIGRATION_NAME = "committed-git-blob-source-census-v1"
GIT_BLOB_SOURCE_CENSUS_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-committed-git-blob-source-census-migration-v1"
)
GIT_BLOB_SOURCE_CENSUS_MIGRATION_FROM_COLLECTOR_SHA = (
    "94cd25a2689da1fae589d35074663a741554ad4f"
)
GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_RUN_ID = 33_294_497_203
GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_ID = 9_730_689_446
GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:f12fc0d45e1bc226a58c82731123ed5d6bbd1b51f0851758ec21cc35fe28228d"
)
GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_SIZE = 435_876_651

BOUNDED_GO_SEMANTIC_MIGRATION_NAME = "bounded-go-semantic-indexing-v1"
BOUNDED_GO_SEMANTIC_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-bounded-go-semantic-indexing-migration-v1"
)
BOUNDED_GO_SEMANTIC_MIGRATION_FROM_COLLECTOR_SHA = (
    "ce0854638539d3862176abfd74b0d7e854eeaf0e"
)
BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_RUN_ID = 33_367_134_527
BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_ID = 9_755_742_430
BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:fc4d21bf9780f2489e562bf3fa598d7e09530736f4b4e628b71a95f3251de17e"
)
BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_SIZE = 328_326_113

HOSTED_SEAL_MARGIN_MIGRATION_NAME = "hosted-semantic-seal-margin-v1"
HOSTED_SEAL_MARGIN_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-hosted-semantic-seal-margin-migration-v1"
)
HOSTED_SEAL_MARGIN_MIGRATION_FROM_COLLECTOR_SHA = (
    "a697637ab5a0b68aeccc796df410d164fadf6abd"
)
HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_RUN_ID = 33_655_327_837
HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_ID = 9_856_923_702
HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:41354adaea64b1c3ef1e82116ca995ca19ec7e92c7c7a48a13619dc9dab8dbdd"
)
HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_SIZE = 369_624_965

GO_SEMANTIC_ASSEMBLY_MIGRATION_NAME = "resumable-go-semantic-assembly-v1"
GO_SEMANTIC_ASSEMBLY_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-resumable-go-semantic-assembly-migration-v1"
)
GO_SEMANTIC_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA = (
    "14cb74ec87663377463bbbe272ec48e3d478464b"
)
GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_RUN_ID = 33_693_790_826
GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_ID = 9_871_249_545
GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:c4df6dc3298ead628449f6049e9aeada3c08c4185f0db091cf106fce428d4e86"
)
GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_SIZE = 373_052_082

FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_NAME = (
    "finalized-go-semantic-compaction-v1"
)
FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-finalized-go-semantic-compaction-migration-v1"
)
FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_FROM_COLLECTOR_SHA = (
    "04b9eb6a30bb997aa23c046af5ed99719a4fdb53"
)
FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_RUN_ID = 33_719_054_949
FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_ID = 9_879_759_973
FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:c5ea8869939496f173a6dfcf8d4190e5ca26418b1c9daf47469b73e5279e6cec"
)
FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_SIZE = 382_505_430

INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_NAME = (
    "indexed-semantic-snapshot-projection-v1"
)
INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-indexed-semantic-snapshot-projection-migration-v1"
)
INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_FROM_COLLECTOR_SHA = (
    "311c6f087c4145ba3c6d1841c4dd58ff92cf21e4"
)
INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_RUN_ID = 33_730_932_228
INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_ID = 9_884_076_774
INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:9c34131a7d2ca09b647795aede94c909350bdaf455cb413db5ebca7783910587"
)
INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_SIZE = 337_799_271

NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_NAME = (
    "batched-source-normalized-semantic-snapshot-v1"
)
NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-batched-source-normalized-semantic-snapshot-migration-v1"
)
NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_FROM_COLLECTOR_SHA = (
    "379c2719695fc059351c9e4ad74a42d2e6500fd2"
)
NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_RUN_ID = 33_746_871_459
NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_ID = 9_890_267_578
NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:dee513c46e6ee8195a1ba37241afd913a03a950241ea7d8dbbefc2304e5cfa18"
)
NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_SIZE = 337_800_342

PUBLIC_SURFACE_REPLAY_MIGRATION_NAME = "compiler-public-surface-replay-v1"
PUBLIC_SURFACE_REPLAY_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-compiler-public-surface-replay-migration-v1"
)
PUBLIC_SURFACE_REPLAY_MIGRATION_FROM_COLLECTOR_SHA = (
    "a1efdefb64589ff4990df89f6dd2115b4b63e5e4"
)
PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_RUN_ID = 33_838_973_146
PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID = 9_924_391_093
PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:050cff3a04a2b928c0afc87ba2f2cefa7a7ac983fa6fec4ff3a505906bfd324a"
)
PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE = 354_317_693

EXECUTABLE_BLOB_MIGRATION_NAME = "executable-git-blob-project-model-v1"
EXECUTABLE_BLOB_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-executable-git-blob-project-model-migration-v1"
)
EXECUTABLE_BLOB_MIGRATION_FROM_COLLECTOR_SHA = (
    "06f8d091f6fe5facb9439672b0ded19848b3f332"
)
EXECUTABLE_BLOB_MIGRATION_SOURCE_RUN_ID = 34_388_257_384
EXECUTABLE_BLOB_MIGRATION_SOURCE_HEAD_SHA = (
    "a9c86b17dc690f163a196b0f1d99e4d7f1615fd8"
)
EXECUTABLE_BLOB_MIGRATION_SOURCE_ARTIFACT_ID = 10_119_014_000
EXECUTABLE_BLOB_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:f97a3c95013716aa339c6e7d47c91d93884e5a6e7e1c4e4568a05e92c95d73b8"
)
EXECUTABLE_BLOB_MIGRATION_SOURCE_ARTIFACT_SIZE = 325_146_342

GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_NAME = (
    "go-project-model-dependency-preparation-v1"
)
GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-go-project-model-dependency-preparation-migration-v1"
)
GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_FROM_COLLECTOR_SHA = (
    "35d561b3b2570264f19c7b0b6e5c6bbc91e477c2"
)
GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_RUN_ID = 34_398_047_970
GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_HEAD_SHA = (
    "35d561b3b2570264f19c7b0b6e5c6bbc91e477c2"
)
GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_ARTIFACT_ID = 10_122_421_174
GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:6a991ff985db8756ae0bd6592ab73b60f757e875ef302f77817408f94c4e1133"
)
GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_ARTIFACT_SIZE = 325_146_524

SOURCE_CENSUS_PROGRESS_MIGRATION_NAME = "resumable-source-census-progress-v1"
SOURCE_CENSUS_PROGRESS_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-resumable-source-census-progress-migration-v1"
)
SOURCE_CENSUS_PROGRESS_MIGRATION_FROM_COLLECTOR_SHA = (
    "4ff5bd9541eb38637c36197664d728a13a2d84c5"
)
SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_RUN_ID = 34_497_607_306
SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_HEAD_SHA = (
    "c395884d8402931c554fe9c8983c6a79658ae289"
)
SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_ARTIFACT_ID = 10_161_246_414
SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:eac6077b1a99af7047969abcd9381e87a5490e6fb39f5d9c1f45f4c5d31c420b"
)
SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_ARTIFACT_SIZE = 325_147_098

BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_NAME = (
    "bounded-source-census-artifact-v1"
)
BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-bounded-source-census-artifact-migration-v1"
)
BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_FROM_COLLECTOR_SHA = (
    "ae708e7c44b42bbdcc08065d46e362e95d510e9b"
)
BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_RUN_ID = 34_524_704_772
BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_HEAD_SHA = (
    "ae708e7c44b42bbdcc08065d46e362e95d510e9b"
)
BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_ARTIFACT_ID = 10_171_478_461
BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:cd59d6e58d19d446be67da8e5022c77791463ee4fdd81c2c998456ab3d96fcdd"
)
BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_ARTIFACT_SIZE = 354_792_493

EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_NAME = (
    "exact-go-semantic-compiler-world-v1"
)
EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-exact-go-semantic-compiler-world-migration-v1"
)
EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_FROM_COLLECTOR_SHA = (
    "93d57f6377a7bb185da7115bf8c19f8f4ac7f7e4"
)
EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_RUN_ID = 34_559_823_453
EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_HEAD_SHA = (
    "93d57f6377a7bb185da7115bf8c19f8f4ac7f7e4"
)
EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_ARTIFACT_ID = 10_183_984_866
EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:1812dd2cea156dcb74a9c3752bf7ab218ff34ece10446a88afdd2cce13bd39be"
)
EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_ARTIFACT_SIZE = 456_087_092

SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_NAME = (
    "source-required-go-semantic-worlds-v1"
)
SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-source-required-go-semantic-worlds-migration-v1"
)
SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_FROM_COLLECTOR_SHA = (
    "082aa95d20f98d380f2907aac09154ecda7b6293"
)
SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_RUN_ID = 34_576_173_950
SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_HEAD_SHA = (
    "082aa95d20f98d380f2907aac09154ecda7b6293"
)
SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_ID = 10_190_009_834
SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:95de029d8163cf4e595c5e9dfca9315059b169b7e546249bc2a5802f78beac45"
)
SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_SIZE = 475_036_861

SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_NAME = (
    "semantic-progress-observability-v1"
)
SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-semantic-progress-observability-migration-v1"
)
SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_FROM_COLLECTOR_SHA = (
    "877104efb2e1566a8ba6e3f8e6e9229fa5428754"
)
SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_RUN_ID = 34_630_668_866
SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_HEAD_SHA = (
    "176c59f4b39e5ea22a89fde142e728240779064b"
)
SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_ARTIFACT_ID = 10_277_235_002
SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:ebbac31340a9cd671e9135930856369c03a8e8ed9f3de9ba8645f1dae94cc071"
)
SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_ARTIFACT_SIZE = 510_295_640

SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_NAME = (
    "semantic-incomplete-world-first-v1"
)
SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-semantic-incomplete-world-first-migration-v1"
)
SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_FROM_COLLECTOR_SHA = (
    "65391487441767274efe4d4610643063afe6ebfe"
)
SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_RUN_ID = 34_649_320_871
SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_HEAD_SHA = (
    "65391487441767274efe4d4610643063afe6ebfe"
)
SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_ARTIFACT_ID = 10_283_960_367
SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:8973a60ea8e4a115a0ab4dc9e8a7ff8391f5de5e9c3ff48b7b3e488d5727fbe0"
)
SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_ARTIFACT_SIZE = 484_506_905

BOUNDED_SEMANTIC_DURATION_MIGRATION_NAME = "bounded-semantic-duration-v1"
BOUNDED_SEMANTIC_DURATION_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-bounded-semantic-duration-migration-v1"
)
BOUNDED_SEMANTIC_DURATION_MIGRATION_FROM_COLLECTOR_SHA = (
    "3e830d3c961e4e69b62ef54576d627ceee17c7a2"
)
BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_RUN_ID = 34_665_686_880
BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_HEAD_SHA = (
    "3e830d3c961e4e69b62ef54576d627ceee17c7a2"
)
BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_ARTIFACT_ID = 10_289_381_799
BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:e246495bd91c3cbbcfcafe2233887a0ccffd9c261965ca62a436b9f429ebbb3d"
)
BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_ARTIFACT_SIZE = 527_511_016

INFERRED_SCIP_KIND_REPLAY_MIGRATION_NAME = "inferred-scip-kind-replay-v1"
INFERRED_SCIP_KIND_REPLAY_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-inferred-scip-kind-replay-migration-v1"
)
INFERRED_SCIP_KIND_REPLAY_MIGRATION_FROM_COLLECTOR_SHA = (
    "eb91c01ace2a0339068ed55d60627f0e93324801"
)
INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_RUN_ID = 34_675_013_530
INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_HEAD_SHA = (
    "eb91c01ace2a0339068ed55d60627f0e93324801"
)
INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID = 10_292_207_111
INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:65c8e588a7201234c3f24e6191237b296653b021df4b3ca1f6b3b1abff365e9f"
)
INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE = 711_391_178
INFERRED_SCIP_KIND_REPLAY_STAGE_ORDER = (
    "0001-payload",
    "0002-materialization",
    "0003-test-materialization",
    "0004-source-census",
    "0005-semantic-census",
)
INFERRED_SCIP_KIND_REPLAY_STAGE_SHA256 = {
    "0001-payload": {
        "_transaction.json": "d8bed734ce57e912011acb9a774d5d71849afbe9fab4ff782f717c9026527b78",
        "artifact.json": "9498bd10600d3bf8b43ca53db8c9001551bb024946d83959c5a04d2dc216f402",
        "checkpoint.json": "c62d552f59fcc23579e111c3962f7be8b4b387d7b727706ef24a6129df5d65f4",
    },
    "0002-materialization": {
        "_transaction.json": "e8d98285cd818854cce925b2e5ee9d828c76a71d41e08e77c98e99f65eae09fd",
        "artifact.json": "62acf21942e28ff5fb39728621597f54ceb435e1a280816d31fbd4606c528b30",
        "checkpoint.json": "763d899aceedef410ccb183b0e5bdb7affa99040a528715d9503591d4df6e56f",
    },
    "0003-test-materialization": {
        "_transaction.json": "d3a4293b039505bfa23e134a56ab876abb9d18ba332bd949709ffffbe5c1ab40",
        "artifact.json": "356a49e6977c2e9120362f7c891ffff5f43114060b21c34dada2d7debc6abf01",
        "checkpoint.json": "4eedc4ee23321831509df50025d8550b0dbeafee939ed71cb420814dffa22b4e",
    },
    "0004-source-census": {
        "_transaction.json": "ca0b1d1e6cfd6eb7fc909a4616ba04507810ea4dfef541fdb214c8ef2838e7cb",
        "artifact.json": "f6e4cedb65bd3ab9ead8c7b18f01891166c70f22e8df9384249cf0d6fcd5c5a6",
        "checkpoint.json": "69bfea58a577430dba13fb0176b572426f498c8d62591aa28b28d68398264c5b",
    },
    "0005-semantic-census": {
        "_transaction.json": "2dc808c4b06df8aa2e64df19e07af75464415d4c4d392509e1a6c114b328b6a1",
        "artifact.json": "8e3236e31324ecf20fabfde4453f9ea4b6acd7617aa307347f87b80cca1b63ae",
        "checkpoint.json": "77e3a3aea395607b40cb1f0b019e53b598449ab06b0a0819fc8e4be494d1c2cc",
    },
}

GO_PACKAGE_ROOT_WORLD_MIGRATION_NAME = "committed-go-package-root-worlds-v1"
GO_PACKAGE_ROOT_WORLD_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-committed-go-package-root-worlds-migration-v1"
)
GO_PACKAGE_ROOT_WORLD_MIGRATION_FROM_COLLECTOR_SHA = (
    "44806e08e8e5d13a007f3f206814059b5338ac63"
)
GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_RUN_ID = 34_707_516_664
GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_HEAD_SHA = (
    "44806e08e8e5d13a007f3f206814059b5338ac63"
)
GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_ARTIFACT_ID = 10_302_940_888
GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:0100cabc412f7f1f959153203ccf31982761d8603f5beb61aff99d696739c33b"
)
GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_ARTIFACT_SIZE = 854_088_786

SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_NAME = (
    "checkpointed-semantic-variant-assembly-v1"
)
SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-checkpointed-semantic-variant-assembly-migration-v1"
)
SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA = (
    "addbbdc1f912cbf40f6013fc1fa199c3da902530"
)
SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_RUN_ID = 34_722_747_642
SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_HEAD_SHA = (
    "addbbdc1f912cbf40f6013fc1fa199c3da902530"
)
SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_ID = 10_306_857_706
SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:7ac224e06c5f492de673f20817d6eb249f13410b0a39458450a2752263e8d8ba"
)
SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_SIZE = 858_760_429

QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_NAME = (
    "bounded-qualification-project-model-v8-replay-v1"
)
QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-bounded-qualification-project-model-v8-replay-migration-v1"
)
QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_FROM_COLLECTOR_SHA = (
    "79c2aa27c4ce13eab850f547785a88434d6ed766"
)
QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_RUN_ID = 34_759_391_724
QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_HEAD_SHA = (
    "79c2aa27c4ce13eab850f547785a88434d6ed766"
)
QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID = 10_318_806_056
QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:8d5e9fef77aa04f6fd779393115367c7fe801c819b0a6ce72b199591168783cd"
)
QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE = 1_283_912_373
QUALIFICATION_PROJECT_MODEL_REPLAY_SLOTS = {
    122: {
        "canonical_repository": "vmware/govmomi",
        "committed_stage_count": 6,
        "retained_checkpoint_sha256": (
            "9da2d231fd20f3db6e04ea0a05dbdd0cfff28e0386d5c64ebec79e8b1d1b7ba7"
        ),
    },
    123: {
        "canonical_repository": "kyverno/chainsaw",
        "committed_stage_count": 4,
        "retained_checkpoint_sha256": (
            "80a169533ecd56c5a6909ada364034f266c9d5681662e58705621350a5bd7cc3"
        ),
    },
}

QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_NAME = (
    "bounded-qualification-project-model-v9-replay-v1"
)
QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-bounded-qualification-project-model-v9-replay-migration-v1"
)
QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_FROM_COLLECTOR_SHA = (
    "f464096ca72580e12b2da10389a24d4389754d2b"
)
QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_RUN_ID = (
    QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_RUN_ID
)
QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_HEAD_SHA = (
    QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_HEAD_SHA
)
QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID = (
    QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID
)
QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST
)
QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE = (
    QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE
)
QUALIFICATION_PROJECT_MODEL_V9_REPLAY_SLOTS = {
    122: QUALIFICATION_PROJECT_MODEL_REPLAY_SLOTS[122],
    123: QUALIFICATION_PROJECT_MODEL_REPLAY_SLOTS[123],
    124: {
        "canonical_repository": "prometheus/prometheus",
        "committed_stage_count": 3,
    },
}

QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_NAME = (
    "bounded-qualification-project-model-v10-replay-v1"
)
QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-bounded-qualification-project-model-v10-replay-migration-v1"
)
QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_FROM_COLLECTOR_SHA = (
    "2247c9053d673f7caec13a3152427a30da205e0b"
)
QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_RUN_ID = 34_843_737_582
QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_HEAD_SHA = (
    "2247c9053d673f7caec13a3152427a30da205e0b"
)
QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID = 10_347_714_093
QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:4cff11183792a707dbc0e5bf6583d7aad2265a63ce21c5081fee9f0ad56b9234"
)
QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE = 1_067_048_647
QUALIFICATION_PROJECT_MODEL_V10_REPLAY_SLOTS = {
    122: {
        "canonical_repository": "vmware/govmomi",
        "committed_stage_count": 4,
        "source_progress": True,
        "retained_checkpoint_sha256": (
            QUALIFICATION_PROJECT_MODEL_REPLAY_SLOTS[122][
                "retained_checkpoint_sha256"
            ]
        ),
    },
    123: {
        "canonical_repository": "kyverno/chainsaw",
        "committed_stage_count": 4,
        "source_progress": True,
        "retained_checkpoint_sha256": (
            QUALIFICATION_PROJECT_MODEL_REPLAY_SLOTS[123][
                "retained_checkpoint_sha256"
            ]
        ),
    },
    124: {
        "canonical_repository": "prometheus/prometheus",
        "committed_stage_count": 3,
        "source_progress": True,
    },
}

GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_NAME = (
    "go-standalone-source-ownership-v1"
)
GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-go-standalone-source-ownership-migration-v1"
)
GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_FROM_COLLECTOR_SHA = (
    "f18873a8fb8f879ac9d3f1dffdc9c3449eabc522"
)
GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_RUN_ID = 34_931_690_309
GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_HEAD_SHA = (
    "f18873a8fb8f879ac9d3f1dffdc9c3449eabc522"
)
GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_ARTIFACT_ID = 10_382_138_769
GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:fc47dc979759b2840338ab389e45f46d9c299af7272e2b185e708b0114572d54"
)
GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_ARTIFACT_SIZE = 1_067_048_443

GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_NAME = "go-semantic-boundary-assembly-v1"
GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-go-semantic-boundary-assembly-migration-v1"
)
GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA = (
    "224ff8a7882536c0ae96b1dfe34525a50e5b91a2"
)
GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_RUN_ID = 35_126_388_117
GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_HEAD_SHA = (
    "e011ff116fd0fd04c454a7d92175ee489aa8a532"
)
GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_ID = 10_461_135_713
GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:29469e430ba3760fbf2604ac63aa6f4b9482d04bc3552ea6a7f5e2882a19d9b9"
)
GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_SIZE = 1_262_678_372

GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_NAME = "go-semantic-unit-phase-timing-v1"
GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-go-semantic-unit-phase-timing-migration-v1"
)
GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_FROM_COLLECTOR_SHA = (
    "f2e4e6f1bf7aae6df4c193ebd25211f231ff75cf"
)
GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_RUN_ID = 35_290_374_088
GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_HEAD_SHA = (
    "f2e4e6f1bf7aae6df4c193ebd25211f231ff75cf"
)
GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_ARTIFACT_ID = 10_526_926_678
GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:45fed6b648fd6377c0a5b014758bbf26a963a38f14688b4dd00444202f2a3381"
)
GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_ARTIFACT_SIZE = 1_286_257_888

SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_NAME = (
    "semantic-validation-assembly-timing-v1"
)
SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-semantic-validation-assembly-timing-migration-v1"
)
SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_FROM_COLLECTOR_SHA = (
    "f0b44732bc16a7d3a09ea5f20e143cf645a37a12"
)
SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_RUN_ID = 35_309_192_839
SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_HEAD_SHA = (
    "f0b44732bc16a7d3a09ea5f20e143cf645a37a12"
)
SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_ARTIFACT_ID = 10_533_102_121
SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:0a28217c76a2b81e9ff4e71ee043530734c7978c64809e1359b944c2989cc810"
)
SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_ARTIFACT_SIZE = 1_296_693_074

SEMANTIC_PROJECTION_INDEXING_MIGRATION_NAME = "semantic-projection-indexing-v1"
SEMANTIC_PROJECTION_INDEXING_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-semantic-projection-indexing-migration-v1"
)
SEMANTIC_PROJECTION_INDEXING_MIGRATION_FROM_COLLECTOR_SHA = (
    "d80dcaf034e6a85d10738a081cc9247ce30f87ea"
)
SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_RUN_ID = 35_319_410_967
SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_HEAD_SHA = (
    "d80dcaf034e6a85d10738a081cc9247ce30f87ea"
)
SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_ARTIFACT_ID = 10_536_778_609
SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:9006ca0f80f630dc251bcd0bbb94619598b02df0f1cde8a6a5add13c2ad30d78"
)
SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_ARTIFACT_SIZE = 1_307_115_286

SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_NAME = "semantic-public-binding-index-v1"
SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-semantic-public-binding-index-migration-v1"
)
SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_FROM_COLLECTOR_SHA = (
    "4fa9de2360813f19b243f10e535115d4168226fc"
)
SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_RUN_ID = 35_329_733_304
SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_HEAD_SHA = (
    "4fa9de2360813f19b243f10e535115d4168226fc"
)
SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_ARTIFACT_ID = 10_541_400_372
SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:ae96760d176189b895a77ee8675e011f0af027d3ce5779cf5c97cf860c71aea4"
)
SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_ARTIFACT_SIZE = 1_441_846_590

GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_NAME = (
    "go-compiler-census-evidence-replay-v1"
)
GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-go-compiler-census-evidence-replay-migration-v1"
)
GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_FROM_COLLECTOR_SHA = (
    "6c74699c738cba2b11f0e5e355e4c33db8656eef"
)
GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_RUN_ID = 35_344_715_106
GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_HEAD_SHA = (
    "6c74699c738cba2b11f0e5e355e4c33db8656eef"
)
GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID = 10_547_257_303
GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:0e82dd2fbe0af08e9eab91e42d40689070f180a0898f59a24e7dfe37ddae103a"
)
GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE = 517_968_656

GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_NAME = (
    "go-semantic-required-document-coverage-v1"
)
GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_CONTRACT = (
    "sniffbench-historical-v2-go-semantic-required-document-coverage-migration-v1"
)
GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_FROM_COLLECTOR_SHA = (
    "d954a0b7b28ad21bd7d6f9a0d245c3913107c303"
)
GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_RUN_ID = 35_424_510_834
GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_HEAD_SHA = (
    "d954a0b7b28ad21bd7d6f9a0d245c3913107c303"
)
GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_ARTIFACT_ID = 10_578_104_629
GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_ARTIFACT_DIGEST = (
    "sha256:eab66ec32ca8660157577a40ad3d5535537db6842324c4beea19d3b8800475b1"
)
GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_ARTIFACT_SIZE = 864_426_158

FRAME_FILE_SHA256 = {
    "environment.txt": "2e87f3c3e1b2005f6b6d09b1bf1b82d30a9433636c3c67f0806cc68e80ab6800",
    "exclusions.json": "74bccb100eb48ab87952bd7eec137b2285edbc68d2547715bc0e06a80e029f76",
    "frame.json": "de8dca6b0248229171a3e82f61b3e59e324ebca47c902e315628d4335120719f",
    "provenance.json": "f6f237a948ffb9de8a4dfefda285f2cf8a9d90777f3700bf69ca53f2f19a45be",
    "selection.json": "e6f06b0b887168205dcaa1d903ffcf54efe6199ea730ee118b28ad8e24925853",
    "selected-payloads.json": "cc27d9274e9d969015055945a9c93df178732835ac3a4312af93acb1b1d66124",
}


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _plain_file(path: pathlib.Path, label: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{label} is not a plain file: {path}")


def _plain_directory(path: pathlib.Path, label: str) -> None:
    if not path.is_dir() or path.is_symlink():
        raise ValueError(f"{label} is not a plain directory: {path}")


def _read_json(path: pathlib.Path, label: str) -> Any:
    _plain_file(path, label)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid {label}: {error}") from error


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _require_exact_fields(
    value: Mapping[str, Any], expected: Mapping[str, Any], label: str
) -> None:
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            raise ValueError(f"{label} field drifted: {key}")


def _exact_plain_child(
    parent: pathlib.Path, name: str, label: str
) -> pathlib.Path:
    _plain_directory(parent, f"{label} parent")
    parent_resolved = parent.resolve(strict=True)
    child = parent.joinpath(name)
    _plain_directory(child, label)
    child_resolved = child.resolve(strict=True)
    if child_resolved.parent != parent_resolved or child_resolved.name != name:
        raise ValueError(f"{label} escaped its parent")
    return child_resolved


def _require_exact_directory_children(
    root: pathlib.Path,
    expected_directories: set[str],
    label: str,
) -> None:
    _plain_directory(root, label)
    observed_directories: set[str] = set()
    try:
        entries = list(os.scandir(root))
    except OSError as error:
        raise ValueError(f"failed to enumerate {label}: {error}") from error
    for entry in entries:
        if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
            raise ValueError(f"{label} contains an unexpected entry: {entry.name}")
        observed_directories.add(entry.name)
    if observed_directories != expected_directories:
        raise ValueError(f"{label} directory set drifted")


def _require_exact_file_children(
    root: pathlib.Path,
    expected_files: set[str],
    label: str,
) -> None:
    _plain_directory(root, label)
    observed_files: set[str] = set()
    try:
        entries = list(os.scandir(root))
    except OSError as error:
        raise ValueError(f"failed to enumerate {label}: {error}") from error
    for entry in entries:
        if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
            raise ValueError(f"{label} contains an unexpected entry: {entry.name}")
        observed_files.add(entry.name)
    if observed_files != expected_files:
        raise ValueError(f"{label} file set drifted")


def _validate_plain_tree(root: pathlib.Path, label: str) -> None:
    _plain_directory(root, label)
    try:
        entries = list(os.scandir(root))
    except OSError as error:
        raise ValueError(f"failed to enumerate {label}: {error}") from error
    for entry in entries:
        if entry.is_symlink():
            raise ValueError(f"{label} contains a symlink: {entry.name}")
        if entry.is_dir(follow_symlinks=False):
            _validate_plain_tree(pathlib.Path(entry.path), label)
        elif not entry.is_file(follow_symlinks=False):
            raise ValueError(f"{label} contains a non-regular entry: {entry.name}")


def _named_work_progress_roots(
    language_root: pathlib.Path, name: str
) -> list[pathlib.Path]:
    roots: list[pathlib.Path] = []
    try:
        entries = list(os.scandir(language_root))
    except OSError as error:
        raise ValueError(f"failed to enumerate Go work root: {error}") from error
    for entry in entries:
        if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
            raise ValueError(f"Go work root contains an unexpected entry: {entry.name}")
        slot_root = _exact_plain_child(language_root, entry.name, "Go work slot")
        progress_root = slot_root.joinpath(name)
        try:
            progress_root.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ValueError(f"failed to inspect {name}: {error}") from error
        roots.append(_exact_plain_child(slot_root, name, f"{name} root"))
    roots.sort()
    return roots


def _remove_validated_plain_tree(root: pathlib.Path, label: str) -> None:
    try:
        entries = list(os.scandir(root))
    except OSError as error:
        raise ValueError(f"failed to enumerate {label}: {error}") from error
    for entry in entries:
        path = pathlib.Path(entry.path)
        if entry.is_symlink():
            raise ValueError(f"{label} changed to a symlink during migration")
        try:
            if entry.is_dir(follow_symlinks=False):
                _remove_validated_plain_tree(path, label)
                path.rmdir()
            elif entry.is_file(follow_symlinks=False):
                path.unlink()
            else:
                raise ValueError(f"{label} changed during migration")
        except OSError as error:
            raise ValueError(f"failed to remove {label}: {error}") from error


def migrate_source_required_go_semantic_progress(
    manifest_path: pathlib.Path,
    state_root: pathlib.Path,
    work_root: pathlib.Path,
    frame_run_id: int,
    migration_name: str,
    source_run_id: int,
    source_head_sha: str,
    source_artifact_id: int,
    source_artifact_digest: str,
    source_artifact_size: int,
) -> None:
    if migration_name != SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_NAME:
        raise ValueError("semantic progress migration is not allowlisted")
    if (
        source_run_id != SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_RUN_ID
        or source_head_sha
        != SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_HEAD_SHA
        or source_artifact_id
        != SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_ID
        or source_artifact_digest
        != SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_DIGEST
        or source_artifact_size
        != SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_SIZE
    ):
        raise ValueError("semantic progress migration source artifact drifted")
    manifest = _require_mapping(
        _read_json(manifest_path, "transport manifest"), "transport manifest"
    )
    if manifest.get("schema_version") != 20:
        raise ValueError("semantic progress migration requires manifest schema 20")
    if (
        validate_manifest(manifest_path, frame_run_id)
        != SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_FROM_COLLECTOR_SHA
    ):
        raise ValueError("semantic progress migration source collector drifted")

    if state_root.name != "historical-v2-assessment-state":
        raise ValueError("semantic progress migration state root name drifted")
    if work_root.name != "historical-v2-assessment-work":
        raise ValueError("semantic progress migration work root name drifted")
    _require_exact_directory_children(state_root, {"go"}, "assessment state root")
    _require_exact_directory_children(work_root, {"go"}, "assessment work root")
    state_language = _exact_plain_child(state_root, "go", "Go state root")
    work_language = _exact_plain_child(work_root, "go", "Go work root")
    _plain_file(state_language.joinpath("slot-0122.lock"), "Go state slot lock")
    state_slot = _exact_plain_child(state_language, "slot-0122", "Go state slot")
    work_slot = _exact_plain_child(work_language, "slot-0122", "Go work slot")

    source_stage = _exact_plain_child(
        state_slot, "0004-source-census", "committed source census stage"
    )
    checkpoint = _require_mapping(
        _read_json(source_stage.joinpath("checkpoint.json"), "source census checkpoint"),
        "source census checkpoint",
    )
    _require_exact_fields(
        checkpoint,
        {
            "schema_version": 1,
            "checkpoint_contract": "sniffbench-historical-v2-slot-stage-checkpoint-v1",
            "selection_sha256": SELECTION_SHA256,
            "language": "go",
            "slot_number": 122,
            "sequence": 4,
            "stage": "source_census",
        },
        "source census checkpoint",
    )
    outcome = _require_mapping(checkpoint.get("outcome"), "source census outcome")
    _require_exact_fields(
        outcome,
        {"status": "completed", "artifact_kind": "source_census"},
        "source census outcome",
    )
    if any(entry.name.startswith("0005-") for entry in state_slot.iterdir()):
        raise ValueError("semantic progress migration found a committed semantic stage")

    source_progress = _exact_plain_child(
        work_slot, "source-progress", "source progress root"
    )
    _require_exact_directory_children(
        source_progress, {"base", "patched"}, "source progress root"
    )
    semantic_progress = _exact_plain_child(
        work_slot, "semantic-progress", "semantic progress root"
    )
    if _named_work_progress_roots(work_language, "semantic-progress") != [
        semantic_progress
    ]:
        raise ValueError("semantic progress migration scope drifted")
    _validate_plain_tree(semantic_progress, "semantic progress root")
    _remove_validated_plain_tree(semantic_progress, "semantic progress root")
    try:
        semantic_progress.rmdir()
    except OSError as error:
        raise ValueError(f"failed to remove semantic progress root: {error}") from error
    if semantic_progress.exists():
        raise ValueError("semantic progress root survived migration")


def migrate_inferred_scip_kind_replay(
    manifest_path: pathlib.Path,
    state_root: pathlib.Path,
    work_root: pathlib.Path,
    frame_run_id: int,
    migration_name: str,
    source_run_id: int,
    source_head_sha: str,
    source_artifact_id: int,
    source_artifact_digest: str,
    source_artifact_size: int,
) -> None:
    if migration_name != INFERRED_SCIP_KIND_REPLAY_MIGRATION_NAME:
        raise ValueError("SCIP kind replay migration is not allowlisted")
    if (
        source_run_id != INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_RUN_ID
        or source_head_sha != INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_HEAD_SHA
        or source_artifact_id
        != INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID
        or source_artifact_digest
        != INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST
        or source_artifact_size
        != INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE
    ):
        raise ValueError("SCIP kind replay migration source artifact drifted")
    manifest = _require_mapping(
        _read_json(manifest_path, "transport manifest"), "transport manifest"
    )
    if manifest.get("schema_version") != 24:
        raise ValueError("SCIP kind replay migration requires manifest schema 24")
    if (
        validate_manifest(manifest_path, frame_run_id)
        != INFERRED_SCIP_KIND_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
    ):
        raise ValueError("SCIP kind replay migration source collector drifted")

    if state_root.name != "historical-v2-assessment-state":
        raise ValueError("SCIP kind replay state root name drifted")
    if work_root.name != "historical-v2-assessment-work":
        raise ValueError("SCIP kind replay work root name drifted")
    _require_exact_directory_children(state_root, {"go"}, "assessment state root")
    _require_exact_directory_children(work_root, {"go"}, "assessment work root")
    state_language = _exact_plain_child(state_root, "go", "Go state root")
    work_language = _exact_plain_child(work_root, "go", "Go work root")
    _plain_file(state_language.joinpath("slot-0122.lock"), "Go state slot lock")
    state_slot = _exact_plain_child(state_language, "slot-0122", "Go state slot")
    _require_exact_directory_children(
        state_slot,
        {
            "0001-payload",
            "0002-materialization",
            "0003-test-materialization",
            "0004-source-census",
            "0005-semantic-census",
        },
        "Go state slot 122",
    )

    stages: dict[str, pathlib.Path] = {}
    expected_files = {"_transaction.json", "artifact.json", "checkpoint.json"}
    if set(INFERRED_SCIP_KIND_REPLAY_STAGE_SHA256) != set(
        INFERRED_SCIP_KIND_REPLAY_STAGE_ORDER
    ):
        raise ValueError("SCIP kind replay stage hash table drifted")
    for stage_name in INFERRED_SCIP_KIND_REPLAY_STAGE_ORDER:
        expected_hashes = INFERRED_SCIP_KIND_REPLAY_STAGE_SHA256[stage_name]
        label = f"committed {stage_name} stage"
        stage = _exact_plain_child(state_slot, stage_name, label)
        _require_exact_file_children(stage, expected_files, label)
        for name, expected in expected_hashes.items():
            if _sha256(stage.joinpath(name)) != expected:
                raise ValueError(f"SCIP kind replay stage drifted: {stage_name}/{name}")
        stages[stage_name] = stage

    work_slot = work_language.joinpath("slot-0122")
    try:
        work_slot.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise ValueError(
            f"failed to inspect SCIP kind replay work slot: {error}"
        ) from error
    else:
        raise ValueError("SCIP kind replay found stale slot work")

    for stage_name in reversed(INFERRED_SCIP_KIND_REPLAY_STAGE_ORDER[1:]):
        stage = stages[stage_name]
        label = f"committed {stage_name} stage"
        _remove_validated_plain_tree(stage, label)
        try:
            stage.rmdir()
        except OSError as error:
            raise ValueError(f"failed to remove {label}: {error}") from error
        if stage.exists():
            raise ValueError(f"SCIP kind replay stage survived migration: {stage_name}")
    _require_exact_directory_children(
        state_slot,
        {"0001-payload"},
        "rewound Go state slot 122",
    )


def _validate_replay_file_commitments(
    stage: pathlib.Path, label: str, committed_files: Any
) -> None:
    if not isinstance(committed_files, list) or len(committed_files) != 2:
        raise ValueError(f"{label} transaction file commitments drifted")
    for item, expected_name in zip(
        committed_files, ("artifact.json", "checkpoint.json")
    ):
        commitment = _require_mapping(item, f"{label} file commitment")
        if set(commitment) != {"name", "sha256", "byte_count"}:
            raise ValueError(f"{label} file commitment field set drifted")
        if commitment.get("name") != expected_name:
            raise ValueError(f"{label} committed filename drifted")
        expected_sha256 = commitment.get("sha256")
        if (
            not isinstance(expected_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
        ):
            raise ValueError(f"{label} committed file hash is invalid")
        expected_size = _positive_json_integer(
            commitment.get("byte_count"), f"{label} committed file byte count"
        )
        committed_path = stage.joinpath(expected_name)
        _plain_file(committed_path, f"{label} committed file")
        try:
            observed_size = committed_path.stat().st_size
        except OSError as error:
            raise ValueError(
                f"failed to inspect {label} committed file: {error}"
            ) from error
        if observed_size != expected_size or _sha256(committed_path) != expected_sha256:
            raise ValueError(f"{label} committed file changed")


def _validate_replay_stage_transaction(
    stage: pathlib.Path,
    slot_number: int,
    canonical_repository: str,
    sequence: int,
    stage_name: str,
    previous_checkpoint_sha256: str | None,
) -> str:
    label = f"Go slot {slot_number} {stage_name} stage"
    _require_exact_file_children(
        stage, {"_transaction.json", "artifact.json", "checkpoint.json"}, label
    )
    checkpoint_path = stage.joinpath("checkpoint.json")
    checkpoint = _require_mapping(
        _read_json(checkpoint_path, f"{label} checkpoint"), f"{label} checkpoint"
    )
    if set(checkpoint) != {
        "schema_version",
        "checkpoint_contract",
        "selection_sha256",
        "language",
        "slot_number",
        "canonical_repository",
        "sequence",
        "previous_checkpoint_sha256",
        "stage",
        "outcome",
        "checkpoint_sha256",
    }:
        raise ValueError(f"{label} checkpoint field set drifted")
    _require_exact_fields(
        checkpoint,
        {
            "schema_version": 1,
            "checkpoint_contract": (
                "sniffbench-historical-v2-slot-stage-checkpoint-v1"
            ),
            "selection_sha256": SELECTION_SHA256,
            "language": "go",
            "slot_number": slot_number,
            "canonical_repository": canonical_repository,
            "sequence": sequence,
            "previous_checkpoint_sha256": previous_checkpoint_sha256,
            "stage": stage_name,
        },
        f"{label} checkpoint",
    )
    checkpoint_sha256 = checkpoint.get("checkpoint_sha256")
    if (
        not isinstance(checkpoint_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", checkpoint_sha256) is None
    ):
        raise ValueError(f"{label} checkpoint commitment is invalid")
    outcome = _require_mapping(checkpoint.get("outcome"), f"{label} outcome")
    if set(outcome) != {"status", "artifact_kind", "artifact_sha256"}:
        raise ValueError(f"{label} outcome field set drifted")
    if outcome.get("status") != "completed":
        raise ValueError(f"{label} is not completed")
    if not isinstance(outcome.get("artifact_kind"), str) or not outcome.get(
        "artifact_kind"
    ):
        raise ValueError(f"{label} artifact kind is invalid")
    artifact_sha256 = outcome.get("artifact_sha256")
    if (
        not isinstance(artifact_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", artifact_sha256) is None
    ):
        raise ValueError(f"{label} artifact commitment is invalid")

    transaction = _require_mapping(
        _read_json(stage.joinpath("_transaction.json"), f"{label} transaction"),
        f"{label} transaction",
    )
    if set(transaction) != {
        "schema_version",
        "transaction_contract",
        "sequence",
        "checkpoint_sha256",
        "files",
    }:
        raise ValueError(f"{label} transaction field set drifted")
    _require_exact_fields(
        transaction,
        {
            "schema_version": 1,
            "transaction_contract": (
                "sniffbench-historical-v2-slot-stage-transaction-v1"
            ),
            "sequence": sequence,
            "checkpoint_sha256": checkpoint_sha256,
        },
        f"{label} transaction",
    )
    _validate_replay_file_commitments(stage, label, transaction.get("files"))
    return checkpoint_sha256


def _validate_qualification_project_model_replay_slot(
    state_language: pathlib.Path,
    work_language: pathlib.Path,
    slot_number: int,
    expected: Mapping[str, Any],
    stage_names: Sequence[str],
) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path | None]:
    _plain_file(
        state_language.joinpath(f"slot-{slot_number:04}.lock"),
        f"Go state slot {slot_number} lock",
    )
    state_slot = _exact_plain_child(
        state_language, f"slot-{slot_number:04}", f"Go state slot {slot_number}"
    )
    committed_stage_count = int(expected["committed_stage_count"])
    expected_directories = {
        f"{sequence:04}-{stage_names[sequence - 1].replace('_', '-')}"
        for sequence in range(1, committed_stage_count + 1)
    }
    _require_exact_directory_children(
        state_slot, expected_directories, f"Go state slot {slot_number}"
    )
    previous_checkpoint_sha256: str | None = None
    for sequence in range(1, committed_stage_count + 1):
        stage_name = stage_names[sequence - 1]
        stage = _exact_plain_child(
            state_slot,
            f"{sequence:04}-{stage_name.replace('_', '-')}",
            f"Go slot {slot_number} committed stage",
        )
        previous_checkpoint_sha256 = _validate_replay_stage_transaction(
            stage,
            slot_number,
            str(expected["canonical_repository"]),
            sequence,
            stage_name,
            previous_checkpoint_sha256,
        )
        if sequence == 3 and (
            previous_checkpoint_sha256 != expected["retained_checkpoint_sha256"]
        ):
            raise ValueError(
                f"Go slot {slot_number} retained checkpoint commitment drifted"
            )

    work_slot = _exact_plain_child(
        work_language, f"slot-{slot_number:04}", f"Go work slot {slot_number}"
    )
    source_progress = _exact_plain_child(
        work_slot, "source-progress", f"Go slot {slot_number} source progress"
    )
    _require_exact_directory_children(
        source_progress,
        {"base", "patched"},
        f"Go slot {slot_number} source progress",
    )
    _validate_plain_tree(source_progress, f"Go slot {slot_number} source progress")
    semantic_progress = None
    if slot_number == 122:
        semantic_progress = _exact_plain_child(
            work_slot,
            "semantic-progress",
            "Go slot 122 semantic progress",
        )
        _validate_plain_tree(semantic_progress, "Go slot 122 semantic progress")
    return state_slot, work_slot, source_progress, semantic_progress


def _remove_qualification_project_model_replay_root(
    root: pathlib.Path, label: str
) -> None:
    _remove_validated_plain_tree(root, label)
    try:
        root.rmdir()
    except OSError as error:
        raise ValueError(f"failed to remove {label}: {error}") from error


def _apply_qualification_project_model_replay(
    state_slots: Mapping[int, pathlib.Path],
    work_slots: Mapping[int, pathlib.Path],
    source_progress_roots: Sequence[pathlib.Path],
    semantic_progress_roots: Sequence[pathlib.Path],
    stage_names: Sequence[str],
) -> None:
    for progress in (*semantic_progress_roots, *source_progress_roots):
        _remove_qualification_project_model_replay_root(
            progress, "qualification project-model progress"
        )
    for slot_number, state_slot in state_slots.items():
        committed_stage_count = int(
            QUALIFICATION_PROJECT_MODEL_REPLAY_SLOTS[slot_number][
                "committed_stage_count"
            ]
        )
        for sequence in range(committed_stage_count, 3, -1):
            stage_name = stage_names[sequence - 1]
            stage = _exact_plain_child(
                state_slot,
                f"{sequence:04}-{stage_name.replace('_', '-')}",
                f"Go slot {slot_number} stale stage",
            )
            _remove_qualification_project_model_replay_root(
                stage, f"Go slot {slot_number} stale stage"
            )
        _require_exact_directory_children(
            state_slot,
            {
                "0001-payload",
                "0002-materialization",
                "0003-test-materialization",
            },
            f"rewound Go state slot {slot_number}",
        )
        for progress_name in ("source-progress", "semantic-progress"):
            if work_slots[slot_number].joinpath(progress_name).exists():
                raise ValueError(
                    f"Go slot {slot_number} {progress_name} survived migration"
                )


def migrate_qualification_project_model_replay(
    manifest_path: pathlib.Path,
    state_root: pathlib.Path,
    work_root: pathlib.Path,
    frame_run_id: int,
    migration_name: str,
    source_run_id: int,
    source_head_sha: str,
    source_artifact_id: int,
    source_artifact_digest: str,
    source_artifact_size: int,
) -> None:
    if migration_name != QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_NAME:
        raise ValueError(
            "qualification project-model replay migration is not allowlisted"
        )
    if (
        source_run_id != QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_RUN_ID
        or source_head_sha
        != QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_HEAD_SHA
        or source_artifact_id
        != QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID
        or source_artifact_digest
        != QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST
        or source_artifact_size
        != QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE
    ):
        raise ValueError("qualification project-model replay source artifact drifted")
    manifest = _require_mapping(
        _read_json(manifest_path, "transport manifest"), "transport manifest"
    )
    if manifest.get("schema_version") != 27:
        raise ValueError(
            "qualification project-model replay requires manifest schema 27"
        )
    if (
        validate_manifest(manifest_path, frame_run_id)
        != QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
    ):
        raise ValueError("qualification project-model replay source collector drifted")
    if state_root.name != "historical-v2-assessment-state":
        raise ValueError("qualification project-model replay state root name drifted")
    if work_root.name != "historical-v2-assessment-work":
        raise ValueError("qualification project-model replay work root name drifted")
    _require_exact_directory_children(state_root, {"go"}, "assessment state root")
    _require_exact_directory_children(work_root, {"go"}, "assessment work root")
    state_language = _exact_plain_child(state_root, "go", "Go state root")
    work_language = _exact_plain_child(work_root, "go", "Go work root")

    stage_names = (
        "payload",
        "materialization",
        "test_materialization",
        "source_census",
        "semantic_census",
        "assessment_identity",
    )
    state_slots: dict[int, pathlib.Path] = {}
    work_slots: dict[int, pathlib.Path] = {}
    source_progress_roots: list[pathlib.Path] = []
    semantic_progress_roots: list[pathlib.Path] = []
    for slot_number, expected in QUALIFICATION_PROJECT_MODEL_REPLAY_SLOTS.items():
        state_slot, work_slot, source_progress, semantic_progress = (
            _validate_qualification_project_model_replay_slot(
                state_language,
                work_language,
                slot_number,
                expected,
                stage_names,
            )
        )
        state_slots[slot_number] = state_slot
        work_slots[slot_number] = work_slot
        source_progress_roots.append(source_progress)
        if semantic_progress is not None:
            semantic_progress_roots.append(semantic_progress)

    if _named_work_progress_roots(work_language, "source-progress") != sorted(
        source_progress_roots
    ):
        raise ValueError("qualification project-model source progress scope drifted")
    if _named_work_progress_roots(work_language, "semantic-progress") != sorted(
        semantic_progress_roots
    ):
        raise ValueError("qualification project-model semantic progress scope drifted")
    _apply_qualification_project_model_replay(
        state_slots,
        work_slots,
        source_progress_roots,
        semantic_progress_roots,
        stage_names,
    )


def _validate_qualification_project_model_v9_replay_slot(
    state_language: pathlib.Path,
    work_language: pathlib.Path,
    slot_number: int,
    expected: Mapping[str, Any],
) -> None:
    _plain_file(
        state_language.joinpath(f"slot-{slot_number:04}.lock"),
        f"Go state slot {slot_number} lock",
    )
    state_slot = _exact_plain_child(
        state_language, f"slot-{slot_number:04}", f"Go state slot {slot_number}"
    )
    stage_names = ("payload", "materialization", "test_materialization")
    _require_exact_directory_children(
        state_slot,
        {
            f"{sequence:04}-{stage_name.replace('_', '-')}"
            for sequence, stage_name in enumerate(stage_names, start=1)
        },
        f"Go state slot {slot_number}",
    )
    previous_checkpoint_sha256: str | None = None
    for sequence, stage_name in enumerate(stage_names, start=1):
        stage = _exact_plain_child(
            state_slot,
            f"{sequence:04}-{stage_name.replace('_', '-')}",
            f"Go slot {slot_number} committed stage",
        )
        previous_checkpoint_sha256 = _validate_replay_stage_transaction(
            stage,
            slot_number,
            str(expected["canonical_repository"]),
            sequence,
            stage_name,
            previous_checkpoint_sha256,
        )
    retained_checkpoint_sha256 = expected.get("retained_checkpoint_sha256")
    if (
        retained_checkpoint_sha256 is not None
        and previous_checkpoint_sha256 != retained_checkpoint_sha256
    ):
        raise ValueError(
            f"Go slot {slot_number} retained checkpoint commitment drifted"
        )
    _exact_plain_child(
        work_language, f"slot-{slot_number:04}", f"Go work slot {slot_number}"
    )


def migrate_qualification_project_model_v9_replay(
    manifest_path: pathlib.Path,
    state_root: pathlib.Path,
    work_root: pathlib.Path,
    frame_run_id: int,
    migration_name: str,
    source_run_id: int,
    source_head_sha: str,
    source_artifact_id: int,
    source_artifact_digest: str,
    source_artifact_size: int,
) -> None:
    if migration_name != QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_NAME:
        raise ValueError(
            "qualification project-model v9 replay migration is not allowlisted"
        )
    if (
        source_run_id
        != QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_RUN_ID
        or source_head_sha
        != QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_HEAD_SHA
        or source_artifact_id
        != QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID
        or source_artifact_digest
        != QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST
        or source_artifact_size
        != QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE
    ):
        raise ValueError(
            "qualification project-model v9 replay source artifact drifted"
        )
    manifest = _require_mapping(
        _read_json(manifest_path, "transport manifest"), "transport manifest"
    )
    if manifest.get("schema_version") != 28:
        raise ValueError(
            "qualification project-model v9 replay requires manifest schema 28"
        )
    if (
        validate_manifest(manifest_path, frame_run_id)
        != QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
    ):
        raise ValueError(
            "qualification project-model v9 replay source collector drifted"
        )
    if state_root.name != "historical-v2-assessment-state":
        raise ValueError(
            "qualification project-model v9 replay state root name drifted"
        )
    if work_root.name != "historical-v2-assessment-work":
        raise ValueError(
            "qualification project-model v9 replay work root name drifted"
        )
    _require_exact_directory_children(state_root, {"go"}, "assessment state root")
    _require_exact_directory_children(work_root, {"go"}, "assessment work root")
    state_language = _exact_plain_child(state_root, "go", "Go state root")
    work_language = _exact_plain_child(work_root, "go", "Go work root")
    for slot_number, expected in QUALIFICATION_PROJECT_MODEL_V9_REPLAY_SLOTS.items():
        _validate_qualification_project_model_v9_replay_slot(
            state_language, work_language, slot_number, expected
        )
    if _named_work_progress_roots(work_language, "source-progress"):
        raise ValueError("qualification project-model v9 source progress survived")
    if _named_work_progress_roots(work_language, "semantic-progress"):
        raise ValueError("qualification project-model v9 semantic progress survived")


def _validate_qualification_project_model_v10_replay_slot(
    state_language: pathlib.Path,
    work_language: pathlib.Path,
    slot_number: int,
    expected: Mapping[str, Any],
) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path | None]:
    _plain_file(
        state_language.joinpath(f"slot-{slot_number:04}.lock"),
        f"Go state slot {slot_number} lock",
    )
    state_slot = _exact_plain_child(
        state_language, f"slot-{slot_number:04}", f"Go state slot {slot_number}"
    )
    stage_names = ("payload", "materialization", "test_materialization", "source_census")
    committed_stage_count = int(expected["committed_stage_count"])
    _require_exact_directory_children(
        state_slot,
        {
            f"{sequence:04}-{stage_names[sequence - 1].replace('_', '-')}"
            for sequence in range(1, committed_stage_count + 1)
        },
        f"Go state slot {slot_number}",
    )
    previous_checkpoint_sha256: str | None = None
    for sequence in range(1, committed_stage_count + 1):
        stage_name = stage_names[sequence - 1]
        stage = _exact_plain_child(
            state_slot,
            f"{sequence:04}-{stage_name.replace('_', '-')}",
            f"Go slot {slot_number} committed stage",
        )
        previous_checkpoint_sha256 = _validate_replay_stage_transaction(
            stage,
            slot_number,
            str(expected["canonical_repository"]),
            sequence,
            stage_name,
            previous_checkpoint_sha256,
        )
        if sequence == 3 and (
            retained_checkpoint_sha256 := expected.get("retained_checkpoint_sha256")
        ) is not None and previous_checkpoint_sha256 != retained_checkpoint_sha256:
            raise ValueError(
                f"Go slot {slot_number} retained checkpoint commitment drifted"
            )

    work_slot = _exact_plain_child(
        work_language, f"slot-{slot_number:04}", f"Go work slot {slot_number}"
    )
    source_progress = None
    if expected.get("source_progress") is True:
        source_progress = _exact_plain_child(
            work_slot,
            "source-progress",
            f"Go slot {slot_number} source progress",
        )
        _require_exact_directory_children(
            source_progress,
            {"base", "patched"},
            f"Go slot {slot_number} source progress",
        )
        _validate_plain_tree(source_progress, f"Go slot {slot_number} source progress")
    return state_slot, work_slot, source_progress


def migrate_qualification_project_model_v10_replay(
    manifest_path: pathlib.Path,
    state_root: pathlib.Path,
    work_root: pathlib.Path,
    frame_run_id: int,
    migration_name: str,
    source_run_id: int,
    source_head_sha: str,
    source_artifact_id: int,
    source_artifact_digest: str,
    source_artifact_size: int,
) -> None:
    if migration_name != QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_NAME:
        raise ValueError(
            "qualification project-model v10 replay migration is not allowlisted"
        )
    if (
        source_run_id != QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_RUN_ID
        or source_head_sha
        != QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_HEAD_SHA
        or source_artifact_id
        != QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID
        or source_artifact_digest
        != QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST
        or source_artifact_size
        != QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE
    ):
        raise ValueError(
            "qualification project-model v10 replay source artifact drifted"
        )
    manifest = _require_mapping(
        _read_json(manifest_path, "transport manifest"), "transport manifest"
    )
    if manifest.get("schema_version") != 29:
        raise ValueError(
            "qualification project-model v10 replay requires manifest schema 29"
        )
    if (
        validate_manifest(manifest_path, frame_run_id)
        != QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
    ):
        raise ValueError(
            "qualification project-model v10 replay source collector drifted"
        )
    if state_root.name != "historical-v2-assessment-state":
        raise ValueError(
            "qualification project-model v10 replay state root name drifted"
        )
    if work_root.name != "historical-v2-assessment-work":
        raise ValueError(
            "qualification project-model v10 replay work root name drifted"
        )
    _require_exact_directory_children(state_root, {"go"}, "assessment state root")
    _require_exact_directory_children(work_root, {"go"}, "assessment work root")
    state_language = _exact_plain_child(state_root, "go", "Go state root")
    work_language = _exact_plain_child(work_root, "go", "Go work root")
    state_slots: dict[int, pathlib.Path] = {}
    work_slots: dict[int, pathlib.Path] = {}
    source_progress_roots: list[pathlib.Path] = []
    for slot_number, expected in QUALIFICATION_PROJECT_MODEL_V10_REPLAY_SLOTS.items():
        state_slot, work_slot, source_progress = (
            _validate_qualification_project_model_v10_replay_slot(
                state_language, work_language, slot_number, expected
            )
        )
        state_slots[slot_number] = state_slot
        work_slots[slot_number] = work_slot
        if source_progress is not None:
            source_progress_roots.append(source_progress)
    if _named_work_progress_roots(work_language, "source-progress") != sorted(
        source_progress_roots
    ):
        raise ValueError("qualification project-model v10 source progress scope drifted")
    if _named_work_progress_roots(work_language, "semantic-progress"):
        raise ValueError("qualification project-model v10 semantic progress survived")

    for progress in source_progress_roots:
        _remove_qualification_project_model_replay_root(
            progress, "qualification project-model v10 source progress"
        )
    for slot_number, state_slot in state_slots.items():
        committed_stage_count = int(
            QUALIFICATION_PROJECT_MODEL_V10_REPLAY_SLOTS[slot_number][
                "committed_stage_count"
            ]
        )
        if committed_stage_count == 4:
            stage = _exact_plain_child(
                state_slot,
                "0004-source-census",
                f"Go slot {slot_number} stale source-census stage",
            )
            _remove_qualification_project_model_replay_root(
                stage, f"Go slot {slot_number} stale source-census stage"
            )
        _require_exact_directory_children(
            state_slot,
            {"0001-payload", "0002-materialization", "0003-test-materialization"},
            f"rewound Go state slot {slot_number}",
        )
        for progress_name in ("source-progress", "semantic-progress"):
            if work_slots[slot_number].joinpath(progress_name).exists():
                raise ValueError(
                    f"Go slot {slot_number} {progress_name} survived v10 migration"
                )

def _positive_json_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def validate_tools_provenance(
    run_path: pathlib.Path,
    artifacts_path: pathlib.Path,
    repository: str,
    head_sha: str,
    tools_run_id: int,
    assessment_run_id: int,
    assessment_run_attempt: int,
    output_path: pathlib.Path,
) -> dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{40}", head_sha) is None:
        raise ValueError("assessment tools head SHA is invalid")
    if not repository or "\n" in repository or "\r" in repository:
        raise ValueError("assessment tools repository is invalid")

    run = _require_mapping(_read_json(run_path, "tools workflow run"), "tools workflow run")
    _require_exact_fields(
        run,
        {
            "event": "workflow_dispatch",
            "head_branch": "main",
            "path": TOOLS_WORKFLOW,
            "status": "completed",
            "conclusion": "success",
            "head_sha": head_sha,
        },
        "tools workflow run",
    )
    if _positive_json_integer(run.get("id"), "tools workflow run ID") != tools_run_id:
        raise ValueError("tools workflow run ID drifted")
    run_attempt = _positive_json_integer(
        run.get("run_attempt"), "tools workflow run attempt"
    )
    if run_attempt != 1:
        raise ValueError("tools workflow run attempt drifted")
    head_repository = _require_mapping(
        run.get("head_repository"), "tools workflow head repository"
    )
    if head_repository.get("full_name") != repository:
        raise ValueError("tools workflow repository drifted")

    listing = _require_mapping(
        _read_json(artifacts_path, "tools artifact listing"),
        "tools artifact listing",
    )
    if _positive_json_integer(
        listing.get("total_count"), "tools artifact total count"
    ) != 1:
        raise ValueError("tools workflow must publish exactly one artifact")
    artifacts = listing.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        raise ValueError("tools artifact listing must contain exactly one artifact")
    artifact = _require_mapping(artifacts[0], "tools artifact")
    expected_name = f"{TOOLS_ARTIFACT_PREFIX}{head_sha}"
    _require_exact_fields(
        artifact,
        {"name": expected_name},
        "tools artifact",
    )
    if artifact.get("expired") is not False:
        raise ValueError("tools artifact is expired or has invalid expiry state")
    artifact_id = _positive_json_integer(artifact.get("id"), "tools artifact ID")
    artifact_size = _positive_json_integer(
        artifact.get("size_in_bytes"), "tools artifact size"
    )
    if artifact_size > TOOLS_ARTIFACT_MAX_BYTES:
        raise ValueError("tools artifact exceeds the size limit")
    artifact_digest = artifact.get("digest")
    if not isinstance(artifact_digest, str) or re.fullmatch(
        r"sha256:[0-9a-f]{64}", artifact_digest
    ) is None:
        raise ValueError("tools artifact digest is invalid")

    provenance = {
        "artifact_digest": artifact_digest,
        "artifact_id": artifact_id,
        "artifact_name": expected_name,
        "artifact_size": artifact_size,
        "assessment_run_attempt": assessment_run_attempt,
        "assessment_run_id": assessment_run_id,
        "schema": TOOLS_PROVENANCE_SCHEMA,
        "tools_head_sha": head_sha,
        "tools_run_attempt": run_attempt,
        "tools_run_id": tools_run_id,
        "tools_workflow": TOOLS_WORKFLOW,
    }
    _positive_json_integer(assessment_run_id, "assessment workflow run ID")
    _positive_json_integer(assessment_run_attempt, "assessment workflow run attempt")
    _plain_directory(output_path.parent, "tools provenance parent")
    try:
        with output_path.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(provenance, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as error:
        raise ValueError(f"failed to create tools provenance: {error}") from error
    return provenance


def _normalized_link(path: pathlib.PurePosixPath, target_text: str) -> list[str]:
    if "\\" in target_text:
        raise ValueError(f"non-portable archive link: {path}")
    target = pathlib.PurePosixPath(target_text)
    if target.is_absolute():
        raise ValueError(f"absolute archive link: {path}")
    normalized: list[str] = []
    for part in path.parent.joinpath(target).parts:
        if part == "..":
            if not normalized:
                raise ValueError(f"escaping archive link: {path}")
            normalized.pop()
        elif part not in ("", "."):
            normalized.append(part)
    return normalized


def _validate_archive_members(payload: tarfile.TarFile) -> None:
    members = payload.getmembers()
    if not members:
        raise ValueError("assessment archive is empty")
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise ValueError("assessment archive exceeds the member-count limit")

    seen_roots: set[str] = set()
    seen_paths: set[pathlib.PurePosixPath] = set()
    root_directories: set[str] = set()
    symlink_paths: set[pathlib.PurePosixPath] = set()
    extracted_bytes = 0
    for member in members:
        if "\\" in member.name:
            raise ValueError(f"non-portable archive member: {member.name}")
        if len(member.name.encode("utf-8")) > MAX_MEMBER_PATH_BYTES:
            raise ValueError(f"archive member path is too long: {member.name}")
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ValueError(f"unsafe archive member: {member.name}")
        if path.parts[0] not in ALLOWED_ARCHIVE_ROOTS:
            raise ValueError(f"unexpected archive member: {member.name}")
        if path in seen_paths:
            raise ValueError(f"duplicate archive member: {member.name}")
        if not (member.isfile() or member.isdir() or member.issym()):
            raise ValueError(f"unsupported archive member: {member.name}")

        seen_paths.add(path)
        seen_roots.add(path.parts[0])
        if len(path.parts) == 1 and member.isdir():
            root_directories.add(path.parts[0])
        if member.isfile():
            if member.size < 0:
                raise ValueError(f"archive member has a negative size: {member.name}")
            extracted_bytes += member.size
            if extracted_bytes > MAX_EXTRACTED_BYTES:
                raise ValueError("assessment archive exceeds the extracted-byte limit")
        elif member.issym():
            symlink_paths.add(path)
            normalized = _normalized_link(path, member.linkname)
            if not normalized or normalized[0] != path.parts[0]:
                raise ValueError(f"cross-root archive link: {member.name}")

    if seen_roots != ALLOWED_ARCHIVE_ROOTS:
        raise ValueError(f"assessment archive roots differ: {sorted(seen_roots)}")
    if root_directories != ALLOWED_ARCHIVE_ROOTS:
        raise ValueError(
            f"assessment archive root directories differ: {sorted(root_directories)}"
        )
    for path in seen_paths:
        for parent in path.parents:
            if parent in symlink_paths:
                raise ValueError(f"archive member descends through a link: {path}")


def _validated_archive_filter(
    member: tarfile.TarInfo, destination: str
) -> tarfile.TarInfo | None:
    if member.issym():
        # Archive-wide validation already proves that links are relative,
        # same-root, and never parents of another member. Avoid data_filter's
        # filesystem realpath check, which rejects valid Git worktree links
        # whose target passes through a regular .git indirection file.
        return member
    return tarfile.data_filter(member, destination)


def validate_archive(archive: pathlib.Path) -> None:
    _plain_file(archive, "assessment archive")
    try:
        with tarfile.open(archive, "r:gz") as payload:
            _validate_archive_members(payload)
    except (OSError, tarfile.TarError) as error:
        raise ValueError(f"invalid assessment archive: {error}") from error


def extract_resume(archive: pathlib.Path, destination: pathlib.Path) -> None:
    _plain_file(archive, "resume archive")
    _plain_directory(destination, "resume destination")
    for root in ALLOWED_ARCHIVE_ROOTS:
        if destination.joinpath(root).exists():
            raise ValueError(
                f"resume destination already contains archive root: {root}"
            )
    try:
        with tarfile.open(archive, "r:gz") as payload:
            _validate_archive_members(payload)
            payload.extractall(path=destination, filter=_validated_archive_filter)
    except (OSError, tarfile.TarError) as error:
        raise ValueError(f"failed to extract assessment archive: {error}") from error
    for root in ALLOWED_ARCHIVE_ROOTS:
        _plain_directory(destination.joinpath(root), "restored assessment root")


def validate_frame(frame_root: pathlib.Path) -> None:
    _plain_directory(frame_root, "frame root")
    expected_files = set(FRAME_FILE_SHA256) | {"SHA256SUMS"}
    observed_files = set()
    for path in frame_root.iterdir():
        _plain_file(path, "frame artifact")
        observed_files.add(path.name)
    if observed_files != expected_files:
        raise ValueError(f"frame files differ: {sorted(observed_files)}")

    checksums = frame_root.joinpath("SHA256SUMS")
    if _sha256(checksums) != FRAME_CHECKSUMS_SHA256:
        raise ValueError("frame SHA256SUMS commitment drifted")
    expected_checksum_text = "".join(
        f"{digest}  {name}\n" for name, digest in FRAME_FILE_SHA256.items()
    )
    if checksums.read_text(encoding="utf-8") != expected_checksum_text:
        raise ValueError("frame SHA256SUMS contents drifted")
    for name, expected_digest in FRAME_FILE_SHA256.items():
        if _sha256(frame_root.joinpath(name)) != expected_digest:
            raise ValueError(f"frame file commitment drifted: {name}")

    provenance = _require_mapping(
        _read_json(frame_root.joinpath("provenance.json"), "frame provenance"),
        "frame provenance",
    )
    expected_provenance = {
        "schema_version": 1,
        "repository": "trysniff/sniff",
        "collector_revision": FRAME_COLLECTOR_SHA,
        "workflow_run_id": str(FRAME_RUN_ID),
        "workflow_run_attempt": str(FRAME_RUN_ATTEMPT),
        "model_provider_access": False,
    }
    if provenance != expected_provenance:
        raise ValueError("frame provenance drifted")

    frame = _require_mapping(
        _read_json(frame_root.joinpath("frame.json"), "frame"), "frame"
    )
    _require_exact_fields(
        frame,
        {
            "dataset_revision": DATASET_REVISION,
            "protocol_sha256": PROTOCOL_SHA256,
            "frame_sha256": FRAME_SHA256,
            "row_count": 126_300,
            "eligible_count": 13_774,
            "excluded_count": 112_526,
        },
        "frame",
    )
    exclusions = _require_mapping(
        _read_json(frame_root.joinpath("exclusions.json"), "exclusions"),
        "exclusions",
    )
    _require_exact_fields(
        exclusions,
        {
            "protocol_sha256": PROTOCOL_SHA256,
            "manifest_sha256": EXCLUSION_MANIFEST_SHA256,
            "repository_count": 615,
        },
        "exclusions",
    )
    selection = _require_mapping(
        _read_json(frame_root.joinpath("selection.json"), "selection"), "selection"
    )
    _require_exact_fields(
        selection,
        {
            "protocol_sha256": PROTOCOL_SHA256,
            "frame_sha256": FRAME_SHA256,
            "selection_sha256": SELECTION_SHA256,
            "selected_count": 664,
            "unfilled_slot_count": 104,
        },
        "selection",
    )
    payloads = _require_mapping(
        _read_json(frame_root.joinpath("selected-payloads.json"), "payloads"),
        "payloads",
    )
    _require_exact_fields(
        payloads,
        {
            "protocol_sha256": PROTOCOL_SHA256,
            "frame_sha256": FRAME_SHA256,
            "selection_sha256": SELECTION_SHA256,
            "payloads_sha256": PAYLOADS_SHA256,
            "selected_count": 664,
        },
        "payloads",
    )


def _manifest_base(frame_run_id: int, collector_sha: str) -> dict[str, Any]:
    if frame_run_id != FRAME_RUN_ID:
        raise ValueError(f"frame run ID must be {FRAME_RUN_ID}")
    if re.fullmatch(r"[0-9a-f]{40}", collector_sha) is None:
        raise ValueError("assessment collector SHA is invalid")
    return {
        "collector_sha": collector_sha,
        "exclusion_manifest_sha256": EXCLUSION_MANIFEST_SHA256,
        "frame_artifact_digest": FRAME_ARTIFACT_DIGEST,
        "frame_artifact_id": FRAME_ARTIFACT_ID,
        "frame_artifact_name": FRAME_ARTIFACT_NAME,
        "frame_artifact_size": FRAME_ARTIFACT_SIZE,
        "frame_checksums_sha256": FRAME_CHECKSUMS_SHA256,
        "frame_collector_sha": FRAME_COLLECTOR_SHA,
        "frame_repository": "trysniff/sniff",
        "frame_run_attempt": FRAME_RUN_ATTEMPT,
        "frame_run_id": FRAME_RUN_ID,
        "frame_sha256": FRAME_SHA256,
        "frame_workflow": ".github/workflows/sniffbench-historical-v2-frame.yml",
        "model_provider_access": False,
        "payloads_sha256": PAYLOADS_SHA256,
        "protocol_sha256": PROTOCOL_SHA256,
        "selection_sha256": SELECTION_SHA256,
    }


def _manifest(frame_run_id: int, collector_sha: str) -> dict[str, Any]:
    value = _manifest_base(frame_run_id, collector_sha)
    value["schema_version"] = 1
    return value


def _migrated_manifest(
    frame_run_id: int,
    collector_sha: str,
    migrations: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    value = _manifest_base(frame_run_id, collector_sha)
    value["collector_migrations"] = [dict(migration) for migration in migrations]
    value["schema_version"] = len(migrations) + 1
    return value


def initialize_manifest(
    path: pathlib.Path, collector_sha: str, frame_run_id: int
) -> None:
    value = _manifest(frame_run_id, collector_sha)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
    except OSError as error:
        raise ValueError(f"failed to create transport manifest: {error}") from error


def validate_manifest(path: pathlib.Path, frame_run_id: int) -> str:
    value = _require_mapping(
        _read_json(path, "transport manifest"), "transport manifest"
    )
    collector_sha = value.get("collector_sha")
    if not isinstance(collector_sha, str):
        raise ValueError("transport manifest collector SHA is missing")
    schema_version = value.get("schema_version")
    if schema_version == 1:
        expected = _manifest(frame_run_id, collector_sha)
    elif schema_version in range(2, 39):
        migrations = value.get("collector_migrations")
        expected_count = schema_version - 1
        if not isinstance(migrations, list) or len(migrations) != expected_count:
            raise ValueError("transport manifest collector migration is invalid")
        migration_values = [
            _require_mapping(item, "transport manifest collector migration")
            for item in migrations
        ]
        _validate_collector_migrations(migration_values, collector_sha)
        expected = _migrated_manifest(
            frame_run_id, collector_sha, migration_values
        )
    else:
        raise ValueError("transport manifest schema version is unsupported")
    if value != expected:
        differing = sorted(
            key
            for key in set(value) | set(expected)
            if value.get(key) != expected.get(key)
        )
        raise ValueError(f"transport manifest drifted: {differing}")
    return collector_sha


def _migration_record(
    migration_name: str,
    target_collector_sha: str,
    source_run_id: int,
    source_head_sha: str,
    source_artifact_id: int,
    source_artifact_digest: str,
    source_artifact_size: int,
) -> dict[str, Any]:
    if migration_name == STORAGE_MIGRATION_NAME:
        contract = STORAGE_MIGRATION_CONTRACT
        source_collector_sha = STORAGE_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == GO_PREPARATION_MIGRATION_NAME:
        contract = GO_PREPARATION_MIGRATION_CONTRACT
        source_collector_sha = GO_PREPARATION_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == GO_MODULE_DOWNLOAD_MIGRATION_NAME:
        contract = GO_MODULE_DOWNLOAD_MIGRATION_CONTRACT
        source_collector_sha = GO_MODULE_DOWNLOAD_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == GO_PROJECT_ROOT_MIGRATION_NAME:
        contract = GO_PROJECT_ROOT_MIGRATION_CONTRACT
        source_collector_sha = GO_PROJECT_ROOT_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == GO_EOF_PARSER_MIGRATION_NAME:
        contract = GO_EOF_PARSER_MIGRATION_CONTRACT
        source_collector_sha = GO_EOF_PARSER_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == RESUME_SYMLINK_MIGRATION_NAME:
        contract = RESUME_SYMLINK_MIGRATION_CONTRACT
        source_collector_sha = RESUME_SYMLINK_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == GIT_BLOB_SOURCE_CENSUS_MIGRATION_NAME:
        contract = GIT_BLOB_SOURCE_CENSUS_MIGRATION_CONTRACT
        source_collector_sha = GIT_BLOB_SOURCE_CENSUS_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == BOUNDED_GO_SEMANTIC_MIGRATION_NAME:
        contract = BOUNDED_GO_SEMANTIC_MIGRATION_CONTRACT
        source_collector_sha = BOUNDED_GO_SEMANTIC_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == HOSTED_SEAL_MARGIN_MIGRATION_NAME:
        contract = HOSTED_SEAL_MARGIN_MIGRATION_CONTRACT
        source_collector_sha = HOSTED_SEAL_MARGIN_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == GO_SEMANTIC_ASSEMBLY_MIGRATION_NAME:
        contract = GO_SEMANTIC_ASSEMBLY_MIGRATION_CONTRACT
        source_collector_sha = GO_SEMANTIC_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_NAME:
        contract = FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_CONTRACT
        source_collector_sha = (
            FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_FROM_COLLECTOR_SHA
        )
    elif migration_name == INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_NAME:
        contract = INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_CONTRACT
        source_collector_sha = (
            INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_FROM_COLLECTOR_SHA
        )
    elif migration_name == NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_NAME:
        contract = NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_CONTRACT
        source_collector_sha = NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == PUBLIC_SURFACE_REPLAY_MIGRATION_NAME:
        contract = PUBLIC_SURFACE_REPLAY_MIGRATION_CONTRACT
        source_collector_sha = PUBLIC_SURFACE_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == EXECUTABLE_BLOB_MIGRATION_NAME:
        contract = EXECUTABLE_BLOB_MIGRATION_CONTRACT
        source_collector_sha = EXECUTABLE_BLOB_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_NAME:
        contract = GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_CONTRACT
        source_collector_sha = GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == SOURCE_CENSUS_PROGRESS_MIGRATION_NAME:
        contract = SOURCE_CENSUS_PROGRESS_MIGRATION_CONTRACT
        source_collector_sha = SOURCE_CENSUS_PROGRESS_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_NAME:
        contract = BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_CONTRACT
        source_collector_sha = (
            BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_FROM_COLLECTOR_SHA
        )
    elif migration_name == EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_NAME:
        contract = EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_CONTRACT
        source_collector_sha = (
            EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_FROM_COLLECTOR_SHA
        )
    elif migration_name == SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_NAME:
        contract = SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_CONTRACT
        source_collector_sha = (
            SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_FROM_COLLECTOR_SHA
        )
    elif migration_name == SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_NAME:
        contract = SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_CONTRACT
        source_collector_sha = (
            SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_FROM_COLLECTOR_SHA
        )
    elif migration_name == SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_NAME:
        contract = SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_CONTRACT
        source_collector_sha = (
            SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_FROM_COLLECTOR_SHA
        )
    elif migration_name == BOUNDED_SEMANTIC_DURATION_MIGRATION_NAME:
        contract = BOUNDED_SEMANTIC_DURATION_MIGRATION_CONTRACT
        source_collector_sha = BOUNDED_SEMANTIC_DURATION_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == INFERRED_SCIP_KIND_REPLAY_MIGRATION_NAME:
        contract = INFERRED_SCIP_KIND_REPLAY_MIGRATION_CONTRACT
        source_collector_sha = INFERRED_SCIP_KIND_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == GO_PACKAGE_ROOT_WORLD_MIGRATION_NAME:
        contract = GO_PACKAGE_ROOT_WORLD_MIGRATION_CONTRACT
        source_collector_sha = GO_PACKAGE_ROOT_WORLD_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_NAME:
        contract = SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_CONTRACT
        source_collector_sha = SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_NAME:
        contract = QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_CONTRACT
        source_collector_sha = (
            QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
        )
    elif migration_name == QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_NAME:
        contract = QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_CONTRACT
        source_collector_sha = (
            QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
        )
    elif migration_name == QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_NAME:
        contract = QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_CONTRACT
        source_collector_sha = (
            QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
        )
    elif migration_name == GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_NAME:
        contract = GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_CONTRACT
        source_collector_sha = (
            GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_FROM_COLLECTOR_SHA
        )
    elif migration_name == GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_NAME:
        contract = GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_CONTRACT
        source_collector_sha = GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_NAME:
        contract = GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_CONTRACT
        source_collector_sha = GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_NAME:
        contract = SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_CONTRACT
        source_collector_sha = (
            SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_FROM_COLLECTOR_SHA
        )
    elif migration_name == SEMANTIC_PROJECTION_INDEXING_MIGRATION_NAME:
        contract = SEMANTIC_PROJECTION_INDEXING_MIGRATION_CONTRACT
        source_collector_sha = SEMANTIC_PROJECTION_INDEXING_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_NAME:
        contract = SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_CONTRACT
        source_collector_sha = SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_FROM_COLLECTOR_SHA
    elif migration_name == GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_NAME:
        contract = GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_CONTRACT
        source_collector_sha = (
            GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
        )
    elif migration_name == GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_NAME:
        contract = GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_CONTRACT
        source_collector_sha = (
            GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_FROM_COLLECTOR_SHA
        )
    else:
        raise ValueError("transport manifest collector migration is not allowlisted")
    return {
        "from_collector_sha": source_collector_sha,
        "migration_contract": contract,
        "migration_name": migration_name,
        "source_artifact_digest": source_artifact_digest,
        "source_artifact_id": source_artifact_id,
        "source_artifact_size": source_artifact_size,
        "source_head_sha": source_head_sha,
        "source_run_id": source_run_id,
        "to_collector_sha": target_collector_sha,
    }


def _expected_storage_migration() -> dict[str, Any]:
    return _migration_record(
        STORAGE_MIGRATION_NAME,
        STORAGE_MIGRATION_TO_COLLECTOR_SHA,
        STORAGE_MIGRATION_SOURCE_RUN_ID,
        STORAGE_MIGRATION_FROM_COLLECTOR_SHA,
        STORAGE_MIGRATION_SOURCE_ARTIFACT_ID,
        STORAGE_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        STORAGE_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_go_preparation_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == GO_PREPARATION_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        GO_PREPARATION_MIGRATION_NAME,
        target_collector_sha,
        GO_PREPARATION_MIGRATION_SOURCE_RUN_ID,
        GO_PREPARATION_MIGRATION_FROM_COLLECTOR_SHA,
        GO_PREPARATION_MIGRATION_SOURCE_ARTIFACT_ID,
        GO_PREPARATION_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        GO_PREPARATION_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_go_module_download_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == GO_MODULE_DOWNLOAD_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        GO_MODULE_DOWNLOAD_MIGRATION_NAME,
        target_collector_sha,
        GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_RUN_ID,
        GO_MODULE_DOWNLOAD_MIGRATION_FROM_COLLECTOR_SHA,
        GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_ARTIFACT_ID,
        GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        GO_MODULE_DOWNLOAD_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_go_project_root_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == GO_PROJECT_ROOT_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        GO_PROJECT_ROOT_MIGRATION_NAME,
        target_collector_sha,
        GO_PROJECT_ROOT_MIGRATION_SOURCE_RUN_ID,
        GO_PROJECT_ROOT_MIGRATION_FROM_COLLECTOR_SHA,
        GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_ID,
        GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        GO_PROJECT_ROOT_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_go_eof_parser_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == GO_EOF_PARSER_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        GO_EOF_PARSER_MIGRATION_NAME,
        target_collector_sha,
        GO_EOF_PARSER_MIGRATION_SOURCE_RUN_ID,
        GO_EOF_PARSER_MIGRATION_FROM_COLLECTOR_SHA,
        GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_ID,
        GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        GO_EOF_PARSER_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_resume_symlink_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == RESUME_SYMLINK_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        RESUME_SYMLINK_MIGRATION_NAME,
        target_collector_sha,
        RESUME_SYMLINK_MIGRATION_SOURCE_RUN_ID,
        RESUME_SYMLINK_MIGRATION_FROM_COLLECTOR_SHA,
        RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_ID,
        RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        RESUME_SYMLINK_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_git_blob_source_census_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == GIT_BLOB_SOURCE_CENSUS_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        GIT_BLOB_SOURCE_CENSUS_MIGRATION_NAME,
        target_collector_sha,
        GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_RUN_ID,
        GIT_BLOB_SOURCE_CENSUS_MIGRATION_FROM_COLLECTOR_SHA,
        GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_ID,
        GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        GIT_BLOB_SOURCE_CENSUS_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_bounded_go_semantic_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == BOUNDED_GO_SEMANTIC_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        BOUNDED_GO_SEMANTIC_MIGRATION_NAME,
        target_collector_sha,
        BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_RUN_ID,
        BOUNDED_GO_SEMANTIC_MIGRATION_FROM_COLLECTOR_SHA,
        BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_ID,
        BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        BOUNDED_GO_SEMANTIC_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_hosted_seal_margin_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == HOSTED_SEAL_MARGIN_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        HOSTED_SEAL_MARGIN_MIGRATION_NAME,
        target_collector_sha,
        HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_RUN_ID,
        HOSTED_SEAL_MARGIN_MIGRATION_FROM_COLLECTOR_SHA,
        HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_ID,
        HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        HOSTED_SEAL_MARGIN_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_go_semantic_assembly_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == GO_SEMANTIC_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        GO_SEMANTIC_ASSEMBLY_MIGRATION_NAME,
        target_collector_sha,
        GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_RUN_ID,
        GO_SEMANTIC_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA,
        GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_ID,
        GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        GO_SEMANTIC_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_finalized_go_semantic_compaction_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha
        == FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_NAME,
        target_collector_sha,
        FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_RUN_ID,
        FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_FROM_COLLECTOR_SHA,
        FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_ID,
        FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_indexed_semantic_snapshot_projection_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha
        == INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_NAME,
        target_collector_sha,
        INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_RUN_ID,
        INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_FROM_COLLECTOR_SHA,
        INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_ID,
        INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_normalized_semantic_snapshot_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha
        == NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_NAME,
        target_collector_sha,
        NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_RUN_ID,
        NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_FROM_COLLECTOR_SHA,
        NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_ID,
        NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_public_surface_replay_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == PUBLIC_SURFACE_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        PUBLIC_SURFACE_REPLAY_MIGRATION_NAME,
        target_collector_sha,
        PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_RUN_ID,
        PUBLIC_SURFACE_REPLAY_MIGRATION_FROM_COLLECTOR_SHA,
        PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
        PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        PUBLIC_SURFACE_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_executable_blob_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == EXECUTABLE_BLOB_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        EXECUTABLE_BLOB_MIGRATION_NAME,
        target_collector_sha,
        EXECUTABLE_BLOB_MIGRATION_SOURCE_RUN_ID,
        EXECUTABLE_BLOB_MIGRATION_SOURCE_HEAD_SHA,
        EXECUTABLE_BLOB_MIGRATION_SOURCE_ARTIFACT_ID,
        EXECUTABLE_BLOB_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        EXECUTABLE_BLOB_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_go_project_model_dependency_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha
        == GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_NAME,
        target_collector_sha,
        GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_RUN_ID,
        GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_HEAD_SHA,
        GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_ARTIFACT_ID,
        GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_source_census_progress_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == SOURCE_CENSUS_PROGRESS_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        SOURCE_CENSUS_PROGRESS_MIGRATION_NAME,
        target_collector_sha,
        SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_RUN_ID,
        SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_HEAD_SHA,
        SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_ARTIFACT_ID,
        SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        SOURCE_CENSUS_PROGRESS_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_bounded_source_census_artifact_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha
        == BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_NAME,
        target_collector_sha,
        BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_RUN_ID,
        BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_HEAD_SHA,
        BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_ARTIFACT_ID,
        BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_exact_go_semantic_compiler_world_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha
        == EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_NAME,
        target_collector_sha,
        EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_RUN_ID,
        EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_HEAD_SHA,
        EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_ARTIFACT_ID,
        EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_source_required_go_semantic_world_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha
        == SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_NAME,
        target_collector_sha,
        SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_RUN_ID,
        SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_HEAD_SHA,
        SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_ID,
        SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_semantic_progress_observability_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha
        == SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_NAME,
        target_collector_sha,
        SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_RUN_ID,
        SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_HEAD_SHA,
        SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_ARTIFACT_ID,
        SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_semantic_incomplete_world_first_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha
        == SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_NAME,
        target_collector_sha,
        SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_RUN_ID,
        SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_HEAD_SHA,
        SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_ARTIFACT_ID,
        SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_bounded_semantic_duration_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == BOUNDED_SEMANTIC_DURATION_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        BOUNDED_SEMANTIC_DURATION_MIGRATION_NAME,
        target_collector_sha,
        BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_RUN_ID,
        BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_HEAD_SHA,
        BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_ARTIFACT_ID,
        BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        BOUNDED_SEMANTIC_DURATION_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_inferred_scip_kind_replay_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == INFERRED_SCIP_KIND_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        INFERRED_SCIP_KIND_REPLAY_MIGRATION_NAME,
        target_collector_sha,
        INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_RUN_ID,
        INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
        INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
        INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        INFERRED_SCIP_KIND_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_go_package_root_world_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == GO_PACKAGE_ROOT_WORLD_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        GO_PACKAGE_ROOT_WORLD_MIGRATION_NAME,
        target_collector_sha,
        GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_RUN_ID,
        GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_HEAD_SHA,
        GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_ARTIFACT_ID,
        GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        GO_PACKAGE_ROOT_WORLD_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_semantic_variant_assembly_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_NAME,
        target_collector_sha,
        SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_RUN_ID,
        SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_HEAD_SHA,
        SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_ID,
        SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_qualification_project_model_replay_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha
        == QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_NAME,
        target_collector_sha,
        QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_RUN_ID,
        QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
        QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
        QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_qualification_project_model_v9_replay_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha
        == QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_NAME,
        target_collector_sha,
        QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_RUN_ID,
        QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
        QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
        QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_qualification_project_model_v10_replay_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha
        == QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_NAME,
        target_collector_sha,
        QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_RUN_ID,
        QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
        QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
        QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_go_standalone_source_ownership_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha
        == GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_NAME,
        target_collector_sha,
        GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_RUN_ID,
        GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_HEAD_SHA,
        GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_ARTIFACT_ID,
        GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_go_semantic_boundary_assembly_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_NAME,
        target_collector_sha,
        GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_RUN_ID,
        GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_HEAD_SHA,
        GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_ID,
        GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_go_semantic_unit_phase_timing_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_NAME,
        target_collector_sha,
        GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_RUN_ID,
        GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_HEAD_SHA,
        GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_ARTIFACT_ID,
        GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_semantic_validation_assembly_timing_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha
        == SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_NAME,
        target_collector_sha,
        SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_RUN_ID,
        SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_HEAD_SHA,
        SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_ARTIFACT_ID,
        SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_semantic_projection_indexing_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == SEMANTIC_PROJECTION_INDEXING_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        SEMANTIC_PROJECTION_INDEXING_MIGRATION_NAME,
        target_collector_sha,
        SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_RUN_ID,
        SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_HEAD_SHA,
        SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_ARTIFACT_ID,
        SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        SEMANTIC_PROJECTION_INDEXING_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_semantic_public_binding_index_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha == SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_NAME,
        target_collector_sha,
        SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_RUN_ID,
        SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_HEAD_SHA,
        SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_ARTIFACT_ID,
        SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_go_compiler_census_evidence_replay_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha
        == GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_NAME,
        target_collector_sha,
        GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_RUN_ID,
        GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_HEAD_SHA,
        GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_ARTIFACT_ID,
        GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _expected_go_semantic_required_document_coverage_migration(
    target_collector_sha: str,
) -> dict[str, Any]:
    if (
        target_collector_sha
        == GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_FROM_COLLECTOR_SHA
        or re.fullmatch(r"[0-9a-f]{40}", target_collector_sha) is None
    ):
        raise ValueError("transport manifest collector migration target is invalid")
    return _migration_record(
        GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_NAME,
        target_collector_sha,
        GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_RUN_ID,
        GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_HEAD_SHA,
        GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_ARTIFACT_ID,
        GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_ARTIFACT_DIGEST,
        GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_SOURCE_ARTIFACT_SIZE,
    )


def _validate_collector_migrations(
    migrations: Sequence[Mapping[str, Any]], collector_sha: str
) -> None:
    if len(migrations) not in range(1, 38):
        raise ValueError("transport manifest collector migration chain is invalid")
    expected = [_expected_storage_migration()]
    if len(migrations) == 2:
        expected.append(_expected_go_preparation_migration(collector_sha))
    elif len(migrations) in range(3, 38):
        expected.append(
            _expected_go_preparation_migration(
                GO_MODULE_DOWNLOAD_MIGRATION_FROM_COLLECTOR_SHA
            )
        )
        module_download_target = (
            GO_PROJECT_ROOT_MIGRATION_FROM_COLLECTOR_SHA
            if len(migrations) >= 4
            else collector_sha
        )
        expected.append(
            _expected_go_module_download_migration(module_download_target)
        )
        if len(migrations) >= 4:
            project_root_target = (
                GO_EOF_PARSER_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) >= 5
                else collector_sha
            )
            expected.append(_expected_go_project_root_migration(project_root_target))
        if len(migrations) >= 5:
            eof_target = (
                RESUME_SYMLINK_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) >= 6
                else collector_sha
            )
            expected.append(_expected_go_eof_parser_migration(eof_target))
        if len(migrations) >= 6:
            resume_target = (
                GIT_BLOB_SOURCE_CENSUS_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) >= 7
                else collector_sha
            )
            expected.append(_expected_resume_symlink_migration(resume_target))
        if len(migrations) >= 7:
            git_blob_target = (
                BOUNDED_GO_SEMANTIC_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) >= 8
                else collector_sha
            )
            expected.append(_expected_git_blob_source_census_migration(git_blob_target))
        if len(migrations) >= 8:
            bounded_semantic_target = (
                HOSTED_SEAL_MARGIN_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) >= 9
                else collector_sha
            )
            expected.append(
                _expected_bounded_go_semantic_migration(bounded_semantic_target)
            )
        if len(migrations) >= 9:
            hosted_target = (
                GO_SEMANTIC_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) >= 10
                else collector_sha
            )
            expected.append(_expected_hosted_seal_margin_migration(hosted_target))
        if len(migrations) >= 10:
            semantic_assembly_target = (
                FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) >= 11
                else collector_sha
            )
            expected.append(
                _expected_go_semantic_assembly_migration(semantic_assembly_target)
            )
        if len(migrations) >= 11:
            finalized_compaction_target = (
                INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) >= 12
                else collector_sha
            )
            expected.append(
                _expected_finalized_go_semantic_compaction_migration(
                    finalized_compaction_target
                )
            )
        if len(migrations) >= 12:
            indexed_projection_target = (
                NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) >= 13
                else collector_sha
            )
            expected.append(
                _expected_indexed_semantic_snapshot_projection_migration(
                    indexed_projection_target
                )
            )
        if len(migrations) >= 13:
            normalized_target = (
                PUBLIC_SURFACE_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) >= 14
                else collector_sha
            )
            expected.append(
                _expected_normalized_semantic_snapshot_migration(
                    normalized_target
                )
            )
        if len(migrations) >= 14:
            public_surface_target = (
                EXECUTABLE_BLOB_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) >= 15
                else collector_sha
            )
            expected.append(
                _expected_public_surface_replay_migration(public_surface_target)
            )
        if len(migrations) >= 15:
            executable_blob_target = (
                GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) >= 16
                else collector_sha
            )
            expected.append(
                _expected_executable_blob_migration(executable_blob_target)
            )
        if len(migrations) >= 16:
            dependency_target = (
                SOURCE_CENSUS_PROGRESS_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) >= 17
                else collector_sha
            )
            expected.append(
                _expected_go_project_model_dependency_migration(dependency_target)
            )
        if len(migrations) >= 17:
            source_progress_target = (
                BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) >= 18
                else collector_sha
            )
            expected.append(
                _expected_source_census_progress_migration(source_progress_target)
            )
        if len(migrations) >= 18:
            bounded_source_target = (
                EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_FROM_COLLECTOR_SHA
                if len(migrations) >= 19
                else collector_sha
            )
            expected.append(
                _expected_bounded_source_census_artifact_migration(
                    bounded_source_target
                )
            )
        if len(migrations) >= 19:
            expected.append(
                _expected_exact_go_semantic_compiler_world_migration(
                    SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_FROM_COLLECTOR_SHA
                    if len(migrations) >= 20
                    else collector_sha
                )
            )
        if len(migrations) >= 20:
            expected.append(
                _expected_source_required_go_semantic_world_migration(
                    SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_FROM_COLLECTOR_SHA
                    if len(migrations) >= 21
                    else collector_sha
                )
            )
        if len(migrations) >= 21:
            expected.append(
                _expected_semantic_progress_observability_migration(
                    SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_FROM_COLLECTOR_SHA
                    if len(migrations) >= 22
                    else collector_sha
                )
            )
        if len(migrations) >= 22:
            expected.append(
                _expected_semantic_incomplete_world_first_migration(
                    BOUNDED_SEMANTIC_DURATION_MIGRATION_FROM_COLLECTOR_SHA
                    if len(migrations) >= 23
                    else collector_sha
                )
            )
        if len(migrations) >= 23:
            expected.append(
                _expected_bounded_semantic_duration_migration(
                    INFERRED_SCIP_KIND_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
                    if len(migrations) >= 24
                    else collector_sha
                )
            )
        if len(migrations) >= 24:
            expected.append(
                _expected_inferred_scip_kind_replay_migration(
                    GO_PACKAGE_ROOT_WORLD_MIGRATION_FROM_COLLECTOR_SHA
                    if len(migrations) >= 25
                    else collector_sha
                )
            )
        if len(migrations) >= 25:
            expected.append(
                _expected_go_package_root_world_migration(
                    SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA
                    if len(migrations) >= 26
                    else collector_sha
                )
            )
        if len(migrations) >= 26:
            expected.append(
                _expected_semantic_variant_assembly_migration(
                    QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
                    if len(migrations) >= 27
                    else collector_sha
                )
            )
        if len(migrations) >= 27:
            expected.append(
                _expected_qualification_project_model_replay_migration(
                    QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
                    if len(migrations) >= 28
                    else collector_sha
                )
            )
        if len(migrations) >= 28:
            expected.append(
                _expected_qualification_project_model_v9_replay_migration(
                    QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
                    if len(migrations) >= 29
                    else collector_sha
                )
            )
        if len(migrations) >= 29:
            expected.append(
                _expected_qualification_project_model_v10_replay_migration(
                    GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_FROM_COLLECTOR_SHA
                    if len(migrations) >= 30
                    else collector_sha
                )
            )
        if len(migrations) >= 30:
            expected.append(
                _expected_go_standalone_source_ownership_migration(
                    GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_FROM_COLLECTOR_SHA
                    if len(migrations) >= 31
                    else collector_sha
                )
            )
        if len(migrations) >= 31:
            expected.append(
                _expected_go_semantic_boundary_assembly_migration(
                    GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_FROM_COLLECTOR_SHA
                    if len(migrations) >= 32
                    else collector_sha
                )
            )
        if len(migrations) >= 32:
            expected.append(
                _expected_go_semantic_unit_phase_timing_migration(
                    SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_FROM_COLLECTOR_SHA
                    if len(migrations) >= 33
                    else collector_sha
                )
            )
        if len(migrations) >= 33:
            expected.append(
                _expected_semantic_validation_assembly_timing_migration(
                    SEMANTIC_PROJECTION_INDEXING_MIGRATION_FROM_COLLECTOR_SHA
                    if len(migrations) >= 34
                    else collector_sha
                )
            )
        if len(migrations) >= 34:
            expected.append(
                _expected_semantic_projection_indexing_migration(
                    SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_FROM_COLLECTOR_SHA
                    if len(migrations) >= 35
                    else collector_sha
                )
            )
        if len(migrations) >= 35:
            expected.append(
                _expected_semantic_public_binding_index_migration(
                    GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_FROM_COLLECTOR_SHA
                    if len(migrations) >= 36
                    else collector_sha
                )
            )
        if len(migrations) >= 36:
            expected.append(
                _expected_go_compiler_census_evidence_replay_migration(
                    GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_FROM_COLLECTOR_SHA
                    if len(migrations) >= 37
                    else collector_sha
                )
            )
        if len(migrations) >= 37:
            expected.append(
                _expected_go_semantic_required_document_coverage_migration(
                    collector_sha
                )
            )
    elif collector_sha != STORAGE_MIGRATION_TO_COLLECTOR_SHA:
        raise ValueError("transport manifest collector migration target drifted")
    if [dict(migration) for migration in migrations] != expected:
        raise ValueError("transport manifest collector migration chain drifted")
    if any(
        left["to_collector_sha"] != right["from_collector_sha"]
        for left, right in zip(expected, expected[1:])
    ):
        raise ValueError("transport manifest collector migration chain is disconnected")


def migrate_manifest(
    path: pathlib.Path,
    frame_run_id: int,
    target_collector_sha: str,
    migration_name: str,
    source_run_id: int,
    source_head_sha: str,
    source_artifact_id: int,
    source_artifact_digest: str,
    source_artifact_size: int,
) -> str:
    value = _require_mapping(
        _read_json(path, "transport manifest"), "transport manifest"
    )
    source_collector_sha = validate_manifest(path, frame_run_id)
    schema_version = value.get("schema_version")
    if schema_version == 1:
        expected_name = STORAGE_MIGRATION_NAME
        migrations: list[Mapping[str, Any]] = []
    elif schema_version == 2:
        expected_name = GO_PREPARATION_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 3:
        expected_name = GO_MODULE_DOWNLOAD_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 4:
        expected_name = GO_PROJECT_ROOT_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 5:
        expected_name = GO_EOF_PARSER_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 6:
        expected_name = RESUME_SYMLINK_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 7:
        expected_name = GIT_BLOB_SOURCE_CENSUS_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 8:
        expected_name = BOUNDED_GO_SEMANTIC_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 9:
        expected_name = HOSTED_SEAL_MARGIN_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 10:
        expected_name = GO_SEMANTIC_ASSEMBLY_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 11:
        expected_name = FINALIZED_GO_SEMANTIC_COMPACTION_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 12:
        expected_name = INDEXED_SEMANTIC_SNAPSHOT_PROJECTION_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 13:
        expected_name = NORMALIZED_SEMANTIC_SNAPSHOT_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 14:
        expected_name = PUBLIC_SURFACE_REPLAY_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 15:
        expected_name = EXECUTABLE_BLOB_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 16:
        expected_name = GO_PROJECT_MODEL_DEPENDENCY_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 17:
        expected_name = SOURCE_CENSUS_PROGRESS_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 18:
        expected_name = BOUNDED_SOURCE_CENSUS_ARTIFACT_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 19:
        expected_name = EXACT_GO_SEMANTIC_COMPILER_WORLD_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 20:
        expected_name = SOURCE_REQUIRED_GO_SEMANTIC_WORLD_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 21:
        expected_name = SEMANTIC_PROGRESS_OBSERVABILITY_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 22:
        expected_name = SEMANTIC_INCOMPLETE_WORLD_FIRST_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 23:
        expected_name = BOUNDED_SEMANTIC_DURATION_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 24:
        expected_name = INFERRED_SCIP_KIND_REPLAY_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 25:
        expected_name = GO_PACKAGE_ROOT_WORLD_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 26:
        expected_name = SEMANTIC_VARIANT_ASSEMBLY_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 27:
        expected_name = QUALIFICATION_PROJECT_MODEL_REPLAY_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 28:
        expected_name = QUALIFICATION_PROJECT_MODEL_V9_REPLAY_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 29:
        expected_name = QUALIFICATION_PROJECT_MODEL_V10_REPLAY_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 30:
        expected_name = GO_STANDALONE_SOURCE_OWNERSHIP_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 31:
        expected_name = GO_SEMANTIC_BOUNDARY_ASSEMBLY_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 32:
        expected_name = GO_SEMANTIC_UNIT_PHASE_TIMING_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 33:
        expected_name = SEMANTIC_VALIDATION_ASSEMBLY_TIMING_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 34:
        expected_name = SEMANTIC_PROJECTION_INDEXING_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 35:
        expected_name = SEMANTIC_PUBLIC_BINDING_INDEX_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 36:
        expected_name = GO_COMPILER_CENSUS_EVIDENCE_REPLAY_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    elif schema_version == 37:
        expected_name = GO_SEMANTIC_REQUIRED_DOCUMENT_COVERAGE_MIGRATION_NAME
        migrations = [
            _require_mapping(item, "transport manifest collector migration")
            for item in value.get("collector_migrations", [])
        ]
    else:
        raise ValueError("transport manifest collector migration chain is closed")
    if migration_name != expected_name:
        raise ValueError("transport manifest collector migration is out of order")
    migration = _migration_record(
        migration_name,
        target_collector_sha,
        source_run_id,
        source_head_sha,
        source_artifact_id,
        source_artifact_digest,
        source_artifact_size,
    )
    if migration["from_collector_sha"] != source_collector_sha:
        raise ValueError("transport manifest collector migration source drifted")
    migrations.append(migration)
    _validate_collector_migrations(migrations, target_collector_sha)
    migrated = _migrated_manifest(frame_run_id, target_collector_sha, migrations)
    temporary = path.with_name(f".{path.name}.migrating")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(migrated, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except OSError as error:
        raise ValueError(f"failed to migrate transport manifest: {error}") from error
    validate_manifest(path, frame_run_id)
    return target_collector_sha


def _positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be a positive integer")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    extract = commands.add_parser("extract-resume")
    extract.add_argument("archive", type=pathlib.Path)
    extract.add_argument("destination", type=pathlib.Path)

    archive = commands.add_parser("validate-archive")
    archive.add_argument("archive", type=pathlib.Path)

    frame = commands.add_parser("validate-frame")
    frame.add_argument("frame_root", type=pathlib.Path)

    initialize = commands.add_parser("initialize-manifest")
    initialize.add_argument("path", type=pathlib.Path)
    initialize.add_argument("collector_sha")
    initialize.add_argument("frame_run_id", type=_positive_integer)

    manifest = commands.add_parser("validate-manifest")
    manifest.add_argument("path", type=pathlib.Path)
    manifest.add_argument("frame_run_id", type=_positive_integer)

    migrate = commands.add_parser("migrate-manifest")
    migrate.add_argument("path", type=pathlib.Path)
    migrate.add_argument("frame_run_id", type=_positive_integer)
    migrate.add_argument("target_collector_sha")
    migrate.add_argument("migration_name")
    migrate.add_argument("source_run_id", type=_positive_integer)
    migrate.add_argument("source_head_sha")
    migrate.add_argument("source_artifact_id", type=_positive_integer)
    migrate.add_argument("source_artifact_digest")
    migrate.add_argument("source_artifact_size", type=_positive_integer)

    semantic_progress = commands.add_parser(
        "migrate-source-required-go-semantic-progress"
    )
    semantic_progress.add_argument("manifest", type=pathlib.Path)
    semantic_progress.add_argument("state_root", type=pathlib.Path)
    semantic_progress.add_argument("work_root", type=pathlib.Path)
    semantic_progress.add_argument("frame_run_id", type=_positive_integer)
    semantic_progress.add_argument("migration_name")
    semantic_progress.add_argument("source_run_id", type=_positive_integer)
    semantic_progress.add_argument("source_head_sha")
    semantic_progress.add_argument("source_artifact_id", type=_positive_integer)
    semantic_progress.add_argument("source_artifact_digest")
    semantic_progress.add_argument("source_artifact_size", type=_positive_integer)

    scip_kind_replay = commands.add_parser("migrate-inferred-scip-kind-replay")
    scip_kind_replay.add_argument("manifest", type=pathlib.Path)
    scip_kind_replay.add_argument("state_root", type=pathlib.Path)
    scip_kind_replay.add_argument("work_root", type=pathlib.Path)
    scip_kind_replay.add_argument("frame_run_id", type=_positive_integer)
    scip_kind_replay.add_argument("migration_name")
    scip_kind_replay.add_argument("source_run_id", type=_positive_integer)
    scip_kind_replay.add_argument("source_head_sha")
    scip_kind_replay.add_argument("source_artifact_id", type=_positive_integer)
    scip_kind_replay.add_argument("source_artifact_digest")
    scip_kind_replay.add_argument("source_artifact_size", type=_positive_integer)

    project_model_replay = commands.add_parser(
        "migrate-bounded-qualification-project-model-v8-replay"
    )
    project_model_replay.add_argument("manifest", type=pathlib.Path)
    project_model_replay.add_argument("state_root", type=pathlib.Path)
    project_model_replay.add_argument("work_root", type=pathlib.Path)
    project_model_replay.add_argument("frame_run_id", type=_positive_integer)
    project_model_replay.add_argument("migration_name")
    project_model_replay.add_argument("source_run_id", type=_positive_integer)
    project_model_replay.add_argument("source_head_sha")
    project_model_replay.add_argument("source_artifact_id", type=_positive_integer)
    project_model_replay.add_argument("source_artifact_digest")
    project_model_replay.add_argument(
        "source_artifact_size", type=_positive_integer
    )

    project_model_v9_replay = commands.add_parser(
        "migrate-bounded-qualification-project-model-v9-replay"
    )
    project_model_v9_replay.add_argument("manifest", type=pathlib.Path)
    project_model_v9_replay.add_argument("state_root", type=pathlib.Path)
    project_model_v9_replay.add_argument("work_root", type=pathlib.Path)
    project_model_v9_replay.add_argument("frame_run_id", type=_positive_integer)
    project_model_v9_replay.add_argument("migration_name")
    project_model_v9_replay.add_argument("source_run_id", type=_positive_integer)
    project_model_v9_replay.add_argument("source_head_sha")
    project_model_v9_replay.add_argument(
        "source_artifact_id", type=_positive_integer
    )
    project_model_v9_replay.add_argument("source_artifact_digest")
    project_model_v9_replay.add_argument(
        "source_artifact_size", type=_positive_integer
    )

    project_model_v10_replay = commands.add_parser(
        "migrate-bounded-qualification-project-model-v10-replay"
    )
    project_model_v10_replay.add_argument("manifest", type=pathlib.Path)
    project_model_v10_replay.add_argument("state_root", type=pathlib.Path)
    project_model_v10_replay.add_argument("work_root", type=pathlib.Path)
    project_model_v10_replay.add_argument("frame_run_id", type=_positive_integer)
    project_model_v10_replay.add_argument("migration_name")
    project_model_v10_replay.add_argument("source_run_id", type=_positive_integer)
    project_model_v10_replay.add_argument("source_head_sha")
    project_model_v10_replay.add_argument(
        "source_artifact_id", type=_positive_integer
    )
    project_model_v10_replay.add_argument("source_artifact_digest")
    project_model_v10_replay.add_argument(
        "source_artifact_size", type=_positive_integer
    )

    tools = commands.add_parser("validate-tools-provenance")
    tools.add_argument("run", type=pathlib.Path)
    tools.add_argument("artifacts", type=pathlib.Path)
    tools.add_argument("repository")
    tools.add_argument("head_sha")
    tools.add_argument("tools_run_id", type=_positive_integer)
    tools.add_argument("assessment_run_id", type=_positive_integer)
    tools.add_argument("assessment_run_attempt", type=_positive_integer)
    tools.add_argument("output", type=pathlib.Path)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        if args.command == "extract-resume":
            extract_resume(args.archive, args.destination)
        elif args.command == "validate-archive":
            validate_archive(args.archive)
        elif args.command == "validate-frame":
            validate_frame(args.frame_root)
        elif args.command == "initialize-manifest":
            initialize_manifest(args.path, args.collector_sha, args.frame_run_id)
        elif args.command == "validate-manifest":
            print(validate_manifest(args.path, args.frame_run_id))
        elif args.command == "migrate-manifest":
            print(
                migrate_manifest(
                    args.path,
                    args.frame_run_id,
                    args.target_collector_sha,
                    args.migration_name,
                    args.source_run_id,
                    args.source_head_sha,
                    args.source_artifact_id,
                    args.source_artifact_digest,
                    args.source_artifact_size,
                )
            )
        elif args.command == "migrate-source-required-go-semantic-progress":
            migrate_source_required_go_semantic_progress(
                args.manifest,
                args.state_root,
                args.work_root,
                args.frame_run_id,
                args.migration_name,
                args.source_run_id,
                args.source_head_sha,
                args.source_artifact_id,
                args.source_artifact_digest,
                args.source_artifact_size,
            )
        elif args.command == "migrate-inferred-scip-kind-replay":
            migrate_inferred_scip_kind_replay(
                args.manifest,
                args.state_root,
                args.work_root,
                args.frame_run_id,
                args.migration_name,
                args.source_run_id,
                args.source_head_sha,
                args.source_artifact_id,
                args.source_artifact_digest,
                args.source_artifact_size,
            )
        elif (
            args.command
            == "migrate-bounded-qualification-project-model-v8-replay"
        ):
            migrate_qualification_project_model_replay(
                args.manifest,
                args.state_root,
                args.work_root,
                args.frame_run_id,
                args.migration_name,
                args.source_run_id,
                args.source_head_sha,
                args.source_artifact_id,
                args.source_artifact_digest,
                args.source_artifact_size,
            )
        elif (
            args.command
            == "migrate-bounded-qualification-project-model-v9-replay"
        ):
            migrate_qualification_project_model_v9_replay(
                args.manifest,
                args.state_root,
                args.work_root,
                args.frame_run_id,
                args.migration_name,
                args.source_run_id,
                args.source_head_sha,
                args.source_artifact_id,
                args.source_artifact_digest,
                args.source_artifact_size,
            )
        elif (
            args.command
            == "migrate-bounded-qualification-project-model-v10-replay"
        ):
            migrate_qualification_project_model_v10_replay(
                args.manifest,
                args.state_root,
                args.work_root,
                args.frame_run_id,
                args.migration_name,
                args.source_run_id,
                args.source_head_sha,
                args.source_artifact_id,
                args.source_artifact_digest,
                args.source_artifact_size,
            )
        elif args.command == "validate-tools-provenance":
            provenance = validate_tools_provenance(
                args.run,
                args.artifacts,
                args.repository,
                args.head_sha,
                args.tools_run_id,
                args.assessment_run_id,
                args.assessment_run_attempt,
                args.output,
            )
            print(f"TOOLS_ARTIFACT_ID={provenance['artifact_id']}")
            print(f"TOOLS_ARTIFACT_DIGEST={provenance['artifact_digest']}")
            print(f"TOOLS_ARTIFACT_SIZE={provenance['artifact_size']}")
        else:
            raise AssertionError(f"unhandled command: {args.command}")
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
