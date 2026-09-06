import hashlib
import json
from email.parser import BytesParser
from email.policy import default
from pathlib import Path
import re
import stat
import sys
import zipfile


CONTRACT = "sniff-python-wheelhouse-v1"
MAX_WHEELS = 4096
MAX_WHEEL_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
MAX_METADATA_BYTES = 1024 * 1024


def fail(message):
    raise SystemExit(message)


def sandbox_child(root, relative, label, must_exist):
    relative = Path(relative)
    if relative.is_absolute() or not relative.parts or any(
        part in ("", ".", "..") for part in relative.parts
    ):
        fail(f"{label} escaped the sandbox")
    candidate = root
    for part in relative.parts:
        candidate = candidate / part
        if candidate.exists() and candidate.is_symlink():
            fail(f"{label} contains a symbolic link")
    if must_exist and not candidate.exists():
        fail(f"{label} is unavailable")
    return candidate


def safe_archive_name(name):
    if not name or "\\" in name or name.startswith("/"):
        return False
    return all(component not in ("", ".", "..") for component in name.split("/"))


def wheel_metadata(path):
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as error:
        fail(f"invalid wheel archive {path.name}: {error}")
    with archive:
        members = archive.infolist()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            fail(f"wheel archive has too many members: {path.name}")
        metadata_members = []
        total_uncompressed = 0
        for member in members:
            if not safe_archive_name(member.filename):
                fail(f"wheel archive has an unsafe member: {path.name}")
            mode = member.external_attr >> 16
            if stat.S_IFMT(mode) == stat.S_IFLNK:
                fail(f"wheel archive contains a symbolic link: {path.name}")
            total_uncompressed += member.file_size
            if total_uncompressed > MAX_TOTAL_BYTES:
                fail(f"wheel archive expands beyond the size limit: {path.name}")
            parts = member.filename.split("/")
            if len(parts) == 2 and parts[0].endswith(".dist-info") and parts[1] == "METADATA":
                metadata_members.append(member)
        if len(metadata_members) != 1:
            fail(f"wheel archive must contain exactly one dist-info/METADATA: {path.name}")
        member = metadata_members[0]
        if member.file_size > MAX_METADATA_BYTES:
            fail(f"wheel metadata exceeds the size limit: {path.name}")
        with archive.open(member) as source:
            metadata_bytes = source.read(MAX_METADATA_BYTES + 1)
        if len(metadata_bytes) > MAX_METADATA_BYTES:
            fail(f"wheel metadata exceeds the size limit: {path.name}")
    metadata = BytesParser(policy=default).parsebytes(metadata_bytes)
    names = metadata.get_all("Name", [])
    versions = metadata.get_all("Version", [])
    if len(names) != 1 or len(versions) != 1:
        fail(f"wheel metadata must contain one Name and Version: {path.name}")
    name = re.sub(r"[-_.]+", "-", str(names[0])).lower()
    version = str(versions[0])
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
        fail(f"wheel metadata has an unsafe project name: {path.name}")
    if not re.fullmatch(r"[A-Za-z0-9.!+_-]+", version):
        fail(f"wheel metadata has an unsafe version: {path.name}")
    return name, version


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_wheelhouse(wheelhouse):
    entries = sorted(wheelhouse.iterdir(), key=lambda path: path.name)
    if len(entries) > MAX_WHEELS:
        fail("wheelhouse exceeds its artifact limit")
    artifacts = []
    total_bytes = 0
    for path in entries:
        if path.is_symlink() or not path.is_file() or path.suffix.lower() != ".whl":
            fail(f"wheelhouse contains a non-wheel artifact: {path.name}")
        if not path.name.isascii() or Path(path.name).name != path.name:
            fail("wheelhouse contains an unsafe filename")
        size = path.stat().st_size
        total_bytes += size
        if size == 0 or size > MAX_WHEEL_BYTES or total_bytes > MAX_TOTAL_BYTES:
            fail(f"wheel artifact exceeds its size limit: {path.name}")
        name, version = wheel_metadata(path)
        artifacts.append(
            {
                "name": name,
                "version": version,
                "filename": path.name,
                "sha256": sha256(path),
                "size": size,
            }
        )
    artifacts.sort(key=lambda artifact: artifact["name"])
    names = [artifact["name"] for artifact in artifacts]
    if len(names) != len(set(names)):
        fail("wheelhouse contains multiple artifacts for one project")
    return artifacts


def write_outputs(lock_path, provenance_path, artifacts):
    lock = "".join(
        f'{artifact["name"]}=={artifact["version"]} '
        f'--hash=sha256:{artifact["sha256"]}\n'
        for artifact in artifacts
    )
    with lock_path.open("x", encoding="ascii", newline="\n") as output:
        output.write(lock)
    provenance = {"version": 1, "contract": CONTRACT, "artifacts": artifacts}
    with provenance_path.open("x", encoding="ascii", newline="\n") as output:
        json.dump(provenance, output, ensure_ascii=True, separators=(",", ":"))


def main():
    if sys.version_info < (3, 11):
        fail("Python 3.11 or newer is required for wheelhouse inspection")
    if len(sys.argv) != 4:
        fail("expected wheelhouse, lock, and provenance paths")
    root = Path.cwd()
    wheelhouse = sandbox_child(root, sys.argv[1], "wheelhouse", True)
    lock_path = sandbox_child(root, sys.argv[2], "requirements lock", False)
    provenance_path = sandbox_child(root, sys.argv[3], "wheelhouse provenance", False)
    if not wheelhouse.is_dir() or not lock_path.parent.is_dir() or not provenance_path.parent.is_dir():
        fail("wheelhouse outputs are unavailable")
    if lock_path.exists() or provenance_path.exists():
        fail("wheelhouse outputs already exist")
    write_outputs(lock_path, provenance_path, inspect_wheelhouse(wheelhouse))


if __name__ == "__main__":
    main()
