import ensurepip
import os
from pathlib import Path
import runpy
import sys


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


def bundled_pip_wheel():
    bundled = Path(ensurepip.__file__).parent / "_bundled"
    wheels = sorted(bundled.glob("pip-*.whl"))
    if len(wheels) != 1:
        raise SystemExit("Python runtime must provide exactly one bundled pip wheel")
    wheel = wheels[0]
    if wheel.is_symlink() or not wheel.is_file():
        raise SystemExit("bundled pip wheel is not a regular file")
    return wheel


def main():
    if sys.version_info < (3, 11):
        raise SystemExit("Python 3.11 or newer is required for pip isolation")
    inherit_appcontainer_acl_for_private_temp()
    sys.path.insert(0, str(bundled_pip_wheel()))
    runpy.run_module("pip", run_name="__main__")


if __name__ == "__main__":
    main()
