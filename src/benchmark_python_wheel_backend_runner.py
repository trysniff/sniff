import importlib
import os
from pathlib import Path
import sys
import tomllib


def fail(message):
    raise SystemExit(message)


def canonical_child(root, relative):
    path = Path(relative)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        fail(f"backend-path is not canonical: {relative}")
    candidate = root / path
    if not candidate.is_dir():
        fail(f"backend-path is not a directory: {relative}")
    return candidate


def main():
    if len(sys.argv) != 3:
        fail("expected project and wheel-output directories")
    sandbox_root = Path.cwd()
    project = sandbox_root / sys.argv[1]
    output = sandbox_root / sys.argv[2]
    if not project.is_dir() or not output.is_dir():
        fail("project or wheel-output directory is unavailable")
    manifest = tomllib.loads((project / "pyproject.toml").read_text(encoding="utf-8"))
    build_system = manifest.get("build-system")
    if not isinstance(build_system, dict):
        fail("build-system is not a table")
    requires = build_system.get("requires")
    if requires != []:
        fail("external Python build requirements need a prepared deterministic toolchain")
    backend_name = build_system.get("build-backend")
    if not isinstance(backend_name, str) or not backend_name:
        fail("build-backend is not an explicit string")
    backend_paths = build_system.get("backend-path", [])
    if not isinstance(backend_paths, list) or not all(
        isinstance(path, str) for path in backend_paths
    ):
        fail("backend-path is not an array of strings")
    sys.path[0:0] = [str(canonical_child(project, path)) for path in backend_paths]
    module_name, separator, object_path = backend_name.partition(":")
    backend = importlib.import_module(module_name)
    if separator:
        for component in object_path.split("."):
            if not component:
                fail("build-backend object path is empty")
            backend = getattr(backend, component)
    os.chdir(project)
    dynamic_requirements = getattr(backend, "get_requires_for_build_wheel", lambda _: [])({})
    if dynamic_requirements != []:
        fail("dynamic Python build requirements need a prepared deterministic toolchain")
    wheel_filename = backend.build_wheel(str(output), {}, None)
    if not isinstance(wheel_filename, str) or Path(wheel_filename).name != wheel_filename:
        fail("build_wheel returned an unsafe wheel filename")
    print(wheel_filename)


if __name__ == "__main__":
    main()
