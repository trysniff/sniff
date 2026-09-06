import ensurepip
import hashlib
import json
from pathlib import Path
import platform
import sys


MAX_FILE_BYTES = 128 * 1024 * 1024


def fail(message):
    raise SystemExit(message)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def pip_runtime():
    bundled = Path(ensurepip.__file__).parent / "_bundled"
    wheels = sorted(bundled.glob("pip-*.whl"))
    if len(wheels) != 1:
        fail("Python runtime must provide exactly one bundled pip wheel")
    wheel = wheels[0]
    if wheel.is_symlink() or not wheel.is_file():
        fail("bundled pip wheel is not a regular file")
    size = wheel.stat().st_size
    if size == 0 or size > MAX_FILE_BYTES:
        fail("bundled pip wheel exceeds its size limit")
    sys.path.insert(0, str(wheel))
    import pip

    return str(pip.__version__), 1, size, sha256(wheel)


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
