"""Extract the hash-pinned blind source seal on Windows and Unix alike."""

import pathlib
import sys
import zipfile


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: extract_blind_source_seal.py ARCHIVE DESTINATION")
    destination = pathlib.Path(sys.argv[2])
    with zipfile.ZipFile(sys.argv[1]) as archive:
        names = set()
        for member in archive.infolist():
            # The release ZIP was made on Windows and stores backslash separators.
            name = member.filename.replace("\\", "/")
            relative = pathlib.PurePosixPath(name)
            if (
                not relative.parts
                or relative.is_absolute()
                or ".." in relative.parts
                or pathlib.PureWindowsPath(name).drive
                or name in names
            ):
                raise ValueError(f"unsafe or repeated source-seal ZIP path: {name!r}")
            names.add(name)
            member.filename = name
        archive.extractall(destination)
    audit = destination / "blind-source-seal.sources/selection/source-selection-audit.json"
    if not audit.is_file():
        raise FileNotFoundError(f"selection audit missing after extraction: {audit}")


if __name__ == "__main__":
    main()
