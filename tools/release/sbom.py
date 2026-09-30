"""Describe Cargo's resolved source graph without claiming binary link coverage."""

import hashlib
import json
import tomllib
from datetime import datetime, timezone
from urllib.parse import quote


def source_sbom(metadata, lock_bytes, commit, target, epoch, binary_name, binary_sha):
    nodes = metadata["resolve"]["nodes"]
    root = metadata["resolve"]["root"]
    packages = {package["id"]: package for package in metadata["packages"]}
    if root not in packages or packages[root]["name"] != "sniff-cli":
        raise ValueError("Cargo metadata does not describe sniff-cli")
    identities = {
        node["id"]: "SPDXRef-Package-" + hashlib.sha256(node["id"].encode()).hexdigest()
        for node in nodes
    }
    lock = tomllib.loads(lock_bytes.decode())
    checksums = {
        (item["name"], item["version"], item.get("source")): item.get("checksum")
        for item in lock["package"]
    }
    inventory = []
    for node in sorted(nodes, key=lambda item: item["id"]):
        package = packages[node["id"]]
        source = package["source"]
        item = {
            "SPDXID": identities[node["id"]],
            "name": package["name"],
            "versionInfo": package["version"],
            "downloadLocation": source or "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": package.get("license") or "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        if source and source.startswith("registry+"):
            checksum = checksums.get((package["name"], package["version"], source))
            if not checksum:
                raise ValueError("Registry dependency lacks a lockfile checksum")
            item["checksums"] = [{"algorithm": "SHA256", "checksumValue": checksum}]
            item["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": (
                        f"pkg:cargo/{quote(package['name'])}@{quote(package['version'])}"
                    ),
                }
            ]
        inventory.append(item)
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": identities[root],
        },
        {
            "spdxElementId": identities[root],
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": "SPDXRef-Binary",
        },
    ]
    for node in nodes:
        for dependency in node["deps"]:
            for kind in dependency["dep_kinds"]:
                relationship = {
                    None: "DEPENDS_ON",
                    "dev": "DEV_DEPENDENCY_OF",
                    "build": "BUILD_DEPENDENCY_OF",
                }[kind["kind"]]
                left, right = identities[node["id"]], identities[dependency["pkg"]]
                if kind["kind"] is not None:
                    left, right = right, left
                relationships.append(
                    {
                        "spdxElementId": left,
                        "relationshipType": relationship,
                        "relatedSpdxElement": right,
                    }
                )
    relationships = sorted({json.dumps(item, sort_keys=True) for item in relationships})
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"sniff-{commit}-{target}",
        "creationInfo": {
            "creators": ["Tool: sniff-candidate-bundler-v1"],
            "created": datetime.fromtimestamp(epoch, timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        },
        "comment": (
            "Target-filtered Cargo source dependency graph, including build and "
            "development dependencies. This is not a complete binary link "
            "inventory or a vulnerability assessment."
        ),
        "packages": inventory,
        "files": [
            {
                "SPDXID": "SPDXRef-Binary",
                "fileName": "./" + binary_name,
                "fileTypes": ["BINARY"],
                "checksums": [{"algorithm": "SHA256", "checksumValue": binary_sha}],
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        ],
        "relationships": [json.loads(item) for item in relationships],
    }
    fingerprint = hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    document["documentNamespace"] = (
        f"https://github.com/trysniff/sniff/sbom/{commit}/{target}/{fingerprint}"
    )
    return document
