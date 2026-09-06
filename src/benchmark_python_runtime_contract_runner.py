import hashlib
import json
from pathlib import Path
import platform
import sys


PIP_WHEEL_FILENAME = "pip-26.2.1-py3-none-any.whl"
PIP_WHEEL_SHA256 = "71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e"
PIP_WHEEL_BYTES = 1_816_632


def fail(message):
    raise SystemExit(message)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def pip_runtime():
    wheel = Path(__file__).with_name(PIP_WHEEL_FILENAME)
    if wheel.is_symlink() or not wheel.is_file():
        fail("Sniff's pinned pip wheel is not a regular file")
    size = wheel.stat().st_size
    if size != PIP_WHEEL_BYTES:
        fail("Sniff's pinned pip wheel has an unexpected size")
    wheel_sha256 = sha256(wheel)
    if wheel_sha256 != PIP_WHEEL_SHA256:
        fail("Sniff's pinned pip wheel failed SHA-256 verification")
    sys.path.insert(0, str(wheel))
    import pip

    return str(pip.__version__), 1, size, wheel_sha256


def main():
    if sys.version_info < (3, 11):
        fail("Python 3.11 or newer is required for build-toolchain preparation")
    pip_version, file_count, total_bytes, files_sha256 = pip_runtime()
    contract = {
        "version": 2,
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "cache_tag": sys.implementation.cache_tag,
        "platform": sys.platform,
        "pip_version": pip_version,
        "pip_file_count": file_count,
        "pip_total_bytes": total_bytes,
        "pip_files_sha256": files_sha256,
    }
    print(json.dumps(contract, ensure_ascii=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
