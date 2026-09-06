import hashlib
import os
from pathlib import Path
import runpy
import sys


PIP_WHEEL_FILENAME = "pip-26.2.1-py3-none-any.whl"
PIP_WHEEL_SHA256 = "71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e"
PIP_WHEEL_BYTES = 1_816_632


def inherit_appcontainer_acl_for_private_temp():
    if os.name != "nt":
        return
    original_mkdir = os.mkdir

    def mkdir(path, mode=0o777, *, dir_fd=None):
        if mode == 0o700:
            mode = 0o777
        if dir_fd is None:
            return original_mkdir(path, mode)
        return original_mkdir(path, mode, dir_fd=dir_fd)

    os.mkdir = mkdir


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def sniff_pip_wheel():
    wheel = Path(__file__).with_name(PIP_WHEEL_FILENAME)
    if wheel.is_symlink() or not wheel.is_file():
        raise SystemExit("Sniff's pinned pip wheel is not a regular file")
    if wheel.stat().st_size != PIP_WHEEL_BYTES:
        raise SystemExit("Sniff's pinned pip wheel has an unexpected size")
    if sha256(wheel) != PIP_WHEEL_SHA256:
        raise SystemExit("Sniff's pinned pip wheel failed SHA-256 verification")
    return wheel


def main():
    if sys.version_info < (3, 11):
        raise SystemExit("Python 3.11 or newer is required for pip isolation")
    inherit_appcontainer_acl_for_private_temp()
    sys.path.insert(0, str(sniff_pip_wheel()))
    runpy.run_module("pip", run_name="__main__")


if __name__ == "__main__":
    main()
