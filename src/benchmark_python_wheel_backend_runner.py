import importlib
import json
import os
from pathlib import Path
import sys
import tomllib


def fail(message):
    raise SystemExit(message)


def canonical_child(root, relative):
    path = Path(relative)
    if relative != "." and (
        path.is_absolute()
        or not path.parts
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        fail(f"backend-path is not canonical: {relative}")
    candidate = root
    for component in path.parts:
        candidate /= component
        if candidate.is_symlink():
            fail(f"backend-path contains an unsupported symbolic link: {relative}")
    if not candidate.is_dir():
        fail(f"backend-path is not a directory: {relative}")
    return candidate


def module_is_symlink_free_child(module_file, declared_root):
    if module_file != declared_root and not module_file.is_relative_to(declared_root):
        return False
    current = declared_root
    for component in module_file.relative_to(declared_root).parts:
        current /= component
        if current.is_symlink():
            fail("in-tree build backend module path contains a symbolic link")
    return True


def sandbox_child(sandbox_root, relative, label):
    candidate = (sandbox_root / relative).resolve()
    if candidate != sandbox_root and not candidate.is_relative_to(sandbox_root):
        fail(f"{label} escaped the sandbox")
    return candidate


def load_backend(project):
    manifest = tomllib.loads((project / "pyproject.toml").read_text(encoding="utf-8"))
    build_system = manifest.get("build-system")
    if not isinstance(build_system, dict):
        fail("build-system is not a table")
    requires = build_system.get("requires")
    if not isinstance(requires, list) or not all(
        isinstance(requirement, str) and requirement for requirement in requires
    ):
        fail("build-system.requires is not an array of requirement strings")
    backend_name = build_system.get("build-backend")
    if not isinstance(backend_name, str) or not backend_name:
        fail("build-backend is not an explicit string")
    backend_paths = build_system.get("backend-path", [])
    if not isinstance(backend_paths, list) or not all(
        isinstance(path, str) for path in backend_paths
    ):
        fail("backend-path is not an array of strings")
    resolved_backend_paths = [canonical_child(project, path) for path in backend_paths]
    sys.path[0:0] = [str(path) for path in resolved_backend_paths]
    module_name, separator, object_path = backend_name.partition(":")
    os.chdir(project)
    backend_module = importlib.import_module(module_name)
    if resolved_backend_paths:
        module_file = getattr(backend_module, "__file__", None)
        if not isinstance(module_file, str):
            fail("in-tree build backend has no concrete module file")
        module_file = Path(module_file)
        if not module_file.is_absolute() or not module_file.is_file():
            fail("in-tree build backend module file is unavailable")
        if not any(
            module_is_symlink_free_child(module_file, path)
            for path in resolved_backend_paths
        ):
            fail("build backend was not loaded from a declared backend-path")
    backend = backend_module
    if separator:
        for component in object_path.split("."):
            if not component:
                fail("build-backend object path is empty")
            backend = getattr(backend, component)
    return backend, requires


def dynamic_requirements(backend):
    dynamic_requirements = getattr(backend, "get_requires_for_build_wheel", lambda _: [])({})
    if not isinstance(dynamic_requirements, list) or not all(
        isinstance(requirement, str)
        and requirement
        and not any(character in requirement for character in "\r\n\0")
        for requirement in dynamic_requirements
    ):
        fail("get_requires_for_build_wheel returned invalid requirements")
    return dynamic_requirements


def write_dynamic_requirements(project, result_path):
    backend, _ = load_backend(project)
    requirements = dynamic_requirements(backend)
    result_path.write_text(
        json.dumps(requirements, ensure_ascii=True, separators=(",", ":")),
        encoding="utf-8",
    )


def build_wheel(project, output, contract_path):
    backend, static_requirements = load_backend(project)
    dynamic = dynamic_requirements(backend)
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    if not isinstance(contract, dict) or set(contract) != {
        "static_requirements",
        "dynamic_requirements",
    }:
        fail("build requirements contract has an invalid shape")
    if contract["static_requirements"] != static_requirements:
        fail("static build requirements changed after toolchain preparation")
    if contract["dynamic_requirements"] != dynamic:
        fail("dynamic build requirements changed after toolchain preparation")
    wheel_filename = backend.build_wheel(str(output), {}, None)
    if not isinstance(wheel_filename, str) or Path(wheel_filename).name != wheel_filename:
        fail("build_wheel returned an unsafe wheel filename")
    print(wheel_filename)


def main():
    if sys.version_info < (3, 11):
        fail("Python 3.11 or newer is required for the isolated wheel runner")
    if len(sys.argv) not in (4, 5):
        fail("expected mode, project, and output arguments")
    sandbox_root = Path.cwd().resolve()
    mode = sys.argv[1]
    project = sandbox_child(sandbox_root, sys.argv[2], "project")
    if not project.is_dir():
        fail("project directory is unavailable")
    target = sandbox_child(sandbox_root, sys.argv[3], "output")
    if mode == "requirements" and len(sys.argv) == 4:
        if not target.parent.is_dir() or target.exists():
            fail("dynamic-requirements output is unavailable")
        os.chdir(project)
        write_dynamic_requirements(project, target)
        return
    if mode == "build" and len(sys.argv) == 5:
        contract = sandbox_child(sandbox_root, sys.argv[4], "requirements contract")
        if not target.is_dir() or not contract.is_file():
            fail("wheel output or requirements contract is unavailable")
        os.chdir(project)
        build_wheel(project, target, contract)
        return
    fail("wheel runner mode and arguments disagree")


if __name__ == "__main__":
    main()
