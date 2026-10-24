#!/usr/bin/env python3
"""Prepare verified local TLS dependency patches without changing go.mod/go.sum.

Run from any directory; pass --go when the pinned toolchain is not on PATH.
The default is offline. Use the returned audit.mod with Go commands run from
the V2bX repository, for example: go test -modfile=<audit.mod> ./core/sing.
Existing prepared trees are verified in full and are never repaired or deleted.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any


SCHEMA = 1
METADATA = ("xray-tls-lifecycle.json", "sing-box-tls-lifecycle.json")


class PreparationError(Exception):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def is_link(path: Path) -> bool:
    # pathlib added Windows junction detection in Python 3.12.
    return path.is_symlink() or getattr(path, "is_junction", lambda: False)()


def relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or ":" in value
        or "\n" in value
        or "\r" in value
        or path.is_absolute()
        or any(part in (".", "..", ".git") for part in path.parts)
        or str(path) != value
    ):
        raise PreparationError(f"Unsafe relative path: {value!r}")
    return value


def tree_hashes(root: Path) -> dict[str, str]:
    if is_link(root) or not root.is_dir():
        raise PreparationError(f"Source must be a real directory: {root}")
    hashes: dict[str, str] = {}
    for current, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(current) / name
            if is_link(path):
                raise PreparationError(f"Links are not allowed in prepared sources: {path}")
        for name in files:
            path = Path(current) / name
            if not path.is_file():
                raise PreparationError(f"Nonregular source file: {path}")
            rel = relative_path(path.relative_to(root).as_posix())
            hashes[rel] = digest(path.read_bytes())
    return dict(sorted(hashes.items()))


def go_h1(hashes: dict[str, str], prefix: str = "") -> str:
    """Go's x/mod/sumdb/dirhash.Hash1, including the original module prefix."""
    summary = "".join(f"{value}  {prefix}{name}\n" for name, value in sorted(hashes.items()))
    return "h1:" + base64.b64encode(hashlib.sha256(summary.encode()).digest()).decode()


def run(command: list[str], cwd: Path, env: dict[str, str]) -> str:
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8")
    if result.returncode:
        raise PreparationError(
            f"Command failed ({result.returncode}): {command!r}\n"
            f"{result.stdout.strip()}\n{result.stderr.strip()}"
        )
    return result.stdout


def git_apply(git: str, source: Path, patch: Path, env: dict[str, str], *flags: str) -> None:
    isolated = env.copy()
    # Prevent discovery of V2bX's index when staging below .dart_tool.
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
        isolated.pop(key, None)
    isolated["GIT_CEILING_DIRECTORIES"] = str(source.parent.resolve())
    isolated["GIT_ATTR_NOSYSTEM"] = "1"
    # Cache hashes describe exact LF bytes; user-level Windows autocrlf must
    # not rewrite patched files as CRLF.
    run([git, "-c", "core.autocrlf=false", "-c", "core.eol=lf", "-c", f"core.attributesFile={os.devnull}", "apply", "--whitespace=nowarn", *flags, str(patch)], source, isolated)


def verify_files(metadata: dict[str, Any], hashes: dict[str, str], field: str) -> None:
    for item in metadata["files"]:
        actual = hashes.get(item["path"])
        if actual != item[field]:
            raise PreparationError(
                f"{metadata['module']}: {field} mismatch for {item['path']}: "
                f"expected {item[field]}, got {actual}"
            )


def read_metadata(path: Path, sums: dict[tuple[str, str], str]) -> tuple[dict[str, Any], Path]:
    data = load_json(path)
    for field in ("module", "module_path", "version", "module_sum", "go_mod_sum", "patch", "patch_sha256", "files"):
        if field not in data:
            raise PreparationError(f"Missing {field} in {path}")
    patch = path.parent / relative_path(data["patch"])
    if digest(patch.read_bytes()) != data["patch_sha256"]:
        raise PreparationError(f"Patch SHA-256 mismatch: {patch}")
    for version, expected in ((data["version"], data["module_sum"]), (data["version"] + "/go.mod", data["go_mod_sum"])):
        if sums.get((data["module"], version)) != expected:
            raise PreparationError(f"Metadata does not match tracked go.sum: {data['module']} {version}")
    seen: set[str] = set()
    if not data["files"]:
        raise PreparationError(f"Empty patched-files metadata: {path}")
    for item in data["files"]:
        name = relative_path(item["path"])
        if name in seen:
            raise PreparationError(f"Duplicate patched file in {path}: {name}")
        seen.add(name)
        for field in ("base_sha256", "patched_sha256"):
            value = item[field]
            if value is not None and not re.fullmatch(r"[0-9a-f]{64}", value):
                raise PreparationError(f"Invalid {field} for {name}")
        if item["base_sha256"] == item["patched_sha256"]:
            raise PreparationError(f"Metadata lists an unchanged file: {name}")
    return data, patch


def verify_prepared(target: Path, identity: dict[str, Any], metadata: dict[str, Any], patch: Path, git: str, env: dict[str, str]) -> dict[str, Any]:
    if is_link(target):
        raise PreparationError(f"Prepared output cannot be a link: {target}")
    if {item.name for item in target.iterdir()} != {"source", "manifest.json"}:
        raise PreparationError(f"Unexpected files in existing prepared output: {target}")
    manifest = load_json(target / "manifest.json")
    if manifest.get("identity") != identity:
        raise PreparationError(f"Existing output identity mismatch: {target}")
    actual = tree_hashes(target / "source")
    if manifest.get("source_files") != actual:
        raise PreparationError(f"Existing prepared source was altered; preserved for inspection: {target}")
    expected_manifest = {"identity": identity, "module": metadata["module"], "module_path": metadata["module_path"], "version": metadata["version"], "source_files": actual}
    if manifest != expected_manifest:
        raise PreparationError(f"Existing prepared manifest was altered; preserved for inspection: {target}")
    verify_files(metadata, actual, "patched_sha256")
    # Reconstruct the pristine full-tree hash from the fixed patch metadata.
    # This prevents a modified manifest from concealing changes to other files.
    pristine = actual.copy()
    for item in metadata["files"]:
        if item["base_sha256"] is None:
            pristine.pop(item["path"], None)
        else:
            pristine[item["path"]] = item["base_sha256"]
    if go_h1(pristine, f"{metadata['module']}@{metadata['version']}/") != metadata["module_sum"]:
        raise PreparationError(f"Prepared tree fails pinned full-module checksum: {target}")
    git_apply(git, target / "source", patch, env, "--reverse", "--check")
    return manifest


def prepare_module(metadata_path: Path, metadata: dict[str, Any], patch: Path, output: Path, work: Path, download_mod: Path, go: str, git: str, env: dict[str, str], check: bool) -> tuple[Path, dict[str, Any]]:
    identity = {"schema": SCHEMA, "metadata_sha256": digest(metadata_path.read_bytes()), "module_sum": metadata["module_sum"], "patch_sha256": metadata["patch_sha256"]}
    label = metadata["module"].rsplit("/", 1)[-1].lower()
    target = output / f"{label}-{digest(canonical(identity))[:24]}"
    if target.exists():
        manifest = verify_prepared(target, identity, metadata, patch, git, env)
        return target / "source", manifest
    if check:
        raise PreparationError(f"Prepared output missing; run without --check first: {target}")
    downloaded = json.loads(run([go, "mod", "download", f"-modfile={download_mod}", "-json", f"{metadata['module']}@{metadata['version']}"], metadata_path.parent.parent, env))
    for field, expected in (("Path", metadata["module"]), ("Version", metadata["version"]), ("Sum", metadata["module_sum"]), ("GoModSum", metadata["go_mod_sum"])):
        if downloaded.get(field) != expected:
            raise PreparationError(f"Downloaded {metadata['module']} {field} mismatch")
    cache = Path(downloaded["Dir"])
    original = tree_hashes(cache)
    if go_h1(original, f"{metadata['module']}@{metadata['version']}/") != metadata["module_sum"]:
        raise PreparationError(f"Extracted Go module cache fails pinned full-module checksum: {cache}")
    if go_h1({"go.mod": digest(Path(downloaded["GoMod"]).read_bytes())}) != metadata["go_mod_sum"]:
        raise PreparationError(f"Cached go.mod fails pinned checksum: {metadata['module']}")
    verify_files(metadata, original, "base_sha256")
    stage = work / target.name
    stage.mkdir()
    source = stage / "source"
    shutil.copytree(cache, source)
    copied = tree_hashes(source)
    if copied != original:
        raise PreparationError(f"Module cache changed while copying: {cache}")
    for relative in copied:
        path = source / relative
        path.chmod(path.stat().st_mode | stat.S_IWUSR)
    git_apply(git, source, patch, env, "--check")
    git_apply(git, source, patch, env)
    patched = tree_hashes(source)
    verify_files(metadata, patched, "patched_sha256")
    changed = {name for name in original.keys() | patched.keys() if original.get(name) != patched.get(name)}
    if changed != {item["path"] for item in metadata["files"]}:
        raise PreparationError(f"Patch changed files absent from metadata: {sorted(changed)}")
    git_apply(git, source, patch, env, "--reverse", "--check")
    manifest = {"identity": identity, "module": metadata["module"], "module_path": metadata["module_path"], "version": metadata["version"], "source_files": patched}
    (stage / "manifest.json").write_bytes(canonical(manifest))
    # Rename only a newly created staging directory. Existing targets are never removed.
    stage.rename(target)
    verify_prepared(target, identity, metadata, patch, git, env)
    return target / "source", manifest


def graph_replacements(graph: dict[str, Any], repo: Path, prepared: dict[str, Path]) -> list[str]:
    flags: list[str] = []
    for item in graph.get("Replace") or []:
        old, new = item["Old"], item["New"]
        old_spec = old["Path"] + ("@" + old["Version"] if old.get("Version") else "")
        if old["Path"] in prepared:
            # Drop version-specific replacements as well as the unversioned form.
            flags.append(f"-dropreplace={old_spec}")
        elif not new.get("Version"):
            destination = Path(new["Path"])
            if not destination.is_absolute():
                destination = repo / destination
            destination = destination.resolve(strict=True)
            if not (destination / "go.mod").is_file():
                raise PreparationError(f"Local replacement has no go.mod: {destination}")
            flags.append(f"-replace={old_spec}={destination.as_posix()}")
    flags.extend(f"-replace={module}={path.as_posix()}" for module, path in sorted(prepared.items()))
    return flags


def verify_pin(graph: dict[str, Any], metadata: dict[str, Any]) -> None:
    required = {item["Path"]: item["Version"] for item in graph.get("Require") or []}
    module_path = metadata["module_path"]
    matching = [item for item in graph.get("Replace") or [] if item["Old"]["Path"] == module_path and item["Old"].get("Version") in (None, "", required.get(module_path))]
    matching.sort(key=lambda item: bool(item["Old"].get("Version")))
    if not matching or matching[-1]["New"] != {"Path": metadata["module"], "Version": metadata["version"]}:
        raise PreparationError(f"Patch metadata does not match the normal go.mod pin: {module_path}")


def verify_graph(go: str, modfile: Path, repo: Path, prepared: dict[str, Path], env: dict[str, str]) -> list[dict[str, str]]:
    graph = json.loads(run([go, "mod", "edit", "-json", str(modfile)], repo, env))
    expected: dict[str, Path] = dict(prepared)
    for item in graph.get("Replace") or []:
        old, new = item["Old"], item["New"]
        if old["Path"] in prepared and old.get("Version"):
            raise PreparationError(f"Version-specific replacement takes precedence: {old}")
        if not new.get("Version"):
            destination = Path(new["Path"])
            if not destination.is_absolute():
                raise PreparationError(f"Audit replacement must be absolute: {new}")
            expected[old["Path"]] = destination.resolve(strict=True)
    checks = []
    for module, destination in sorted(expected.items()):
        selected = json.loads(run([go, "list", f"-modfile={modfile}", "-mod=readonly", "-m", "-json", module], repo, env))
        actual = selected.get("Replace", {}).get("Dir")
        if not actual or Path(actual).resolve() != destination.resolve():
            raise PreparationError(f"Go selected the wrong source for {module}: {actual}, wanted {destination}")
        checks.append({"module": module, "directory": str(destination)})
    return checks


def prepare(args: argparse.Namespace, repo: Path) -> dict[str, Any]:
    originals = {name: (repo / name).read_bytes() for name in ("go.mod", "go.sum")}
    output = Path(args.output).resolve() if args.output else repo / ".dart_tool" / "tls-dependencies"
    if output == repo or (output.is_relative_to(repo) and output.relative_to(repo).parts[0] != ".dart_tool"):
        raise PreparationError("Outputs inside the repository must be below .dart_tool; use an external directory otherwise")
    if is_link(output):
        raise PreparationError(f"Output must not be a link: {output}")
    output.mkdir(parents=True, exist_ok=True)
    found_go = shutil.which(args.go)
    found_git = shutil.which("git")
    if not found_go or not found_git:
        raise PreparationError("Both the requested Go compiler and git must be available")
    go = str(Path(found_go).resolve())
    env = os.environ.copy()
    inferred_root = Path(go).parent.parent
    if (inferred_root / "src" / "cmd").is_dir():
        env["GOROOT"] = str(inferred_root)
    else:
        env.pop("GOROOT", None)
    env.update({"GOFLAGS": "", "GOWORK": "off", "GOTOOLCHAIN": "local", "GOEXPERIMENT": "jsonv2"})
    if not args.allow_download:
        env.update({"GOPROXY": "off", "GOSUMDB": "off"})
    version = run([go, "version"], repo, env).strip()
    work = Path(tempfile.mkdtemp(prefix=".prepare-", dir=output))
    try:
        download_mod = work / "download.mod"
        download_mod.write_bytes(originals["go.mod"])
        download_mod.with_suffix(".sum").write_bytes(originals["go.sum"])
        original_graph = json.loads(run([go, "mod", "edit", "-json", str(download_mod)], repo, env))
        sums = {}
        for line in originals["go.sum"].decode().splitlines():
            module, version_name, checksum = line.split()
            key = (module, version_name)
            if key in sums and sums[key] != checksum:
                raise PreparationError(f"Conflicting tracked go.sum entry: {key}")
            sums[key] = checksum
        prepared: dict[str, Path] = {}
        modules = []
        for filename in METADATA:
            metadata_path = repo / "patches" / filename
            metadata, patch = read_metadata(metadata_path, sums)
            verify_pin(original_graph, metadata)
            source, manifest = prepare_module(metadata_path, metadata, patch, output, work, download_mod, go, found_git, env, args.check)
            prepared[metadata["module_path"]] = source
            modules.append({"module": metadata["module"], "module_path": metadata["module_path"], "version": metadata["version"], "source": str(source), "manifest": str(source.parent / "manifest.json"), "file_count": len(manifest["source_files"]), "identity": manifest["identity"]})
        graph_identity = {"schema": SCHEMA, "go_mod_sha256": digest(originals["go.mod"]), "go_sum_sha256": digest(originals["go.sum"]), "go_version": version, "offline": not args.allow_download, "modules": modules}
        graph_target = output / ("graph-" + digest(canonical(graph_identity))[:24])
        graph_stage = work / "graph"
        graph_stage.mkdir()
        audit_mod = graph_stage / "audit.mod"
        audit_mod.write_bytes(originals["go.mod"])
        audit_mod.with_suffix(".sum").write_bytes(originals["go.sum"])
        run([go, "mod", "edit", *graph_replacements(original_graph, repo, prepared), str(audit_mod)], repo, env)
        checks = verify_graph(go, audit_mod, repo, prepared, env)
        report = {"ok": True, "schema": SCHEMA, "identity": graph_identity, "go_version": version, "offline": not args.allow_download, "audit_mod": str(graph_target / "audit.mod"), "audit_sum": str(graph_target / "audit.sum"), "result_json": str(graph_target / "preparation.json"), "modules": modules, "replacement_checks": checks, "checks": {"normal_modfiles_unchanged": True, "metadata_and_patch_hashes": True, "pinned_module_checksums": True, "full_prepared_tree_hashes": True, "reverse_patch_checks": True, "go_selected_local_replacements": True}, "audit_mod_sha256": digest(audit_mod.read_bytes()), "audit_sum_sha256": digest(audit_mod.with_suffix(".sum").read_bytes())}
        (graph_stage / "preparation.json").write_bytes(canonical(report))
        if graph_target.exists():
            if is_link(graph_target) or tree_hashes(graph_target) != tree_hashes(graph_stage):
                raise PreparationError(f"Existing audit graph differs; preserved for inspection: {graph_target}")
            for item in graph_stage.iterdir():
                item.unlink()
            graph_stage.rmdir()
        elif args.check:
            raise PreparationError(f"Audit graph missing; run without --check first: {graph_target}")
        else:
            graph_stage.rename(graph_target)
        # Check the final modfile too; Go resolves relative replacements from
        # the repository root even when -modfile points elsewhere.
        verify_graph(go, graph_target / "audit.mod", repo, prepared, env)
        for item in work.iterdir():
            if not item.is_file() or item.is_symlink():
                raise PreparationError(f"Unexpected staging entry, retained: {item}")
            item.unlink()
        work.rmdir()
        return report
    except Exception as error:
        raise PreparationError(f"{error}\nStaging retained for inspection: {work}") from error
    finally:
        for name, original in originals.items():
            if (repo / name).read_bytes() != original:
                raise PreparationError(f"Normal {name} changed during preparation; investigate before using output")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--go", default="go", help="Go executable (must support the pinned Go/toolchain directives)")
    parser.add_argument("--output", help="Own output directory (default: .dart_tool/tls-dependencies)")
    parser.add_argument("--check", action="store_true", help="Verify existing outputs; do not prepare missing dependency trees")
    parser.add_argument("--allow-download", action="store_true", help="Allow Go's configured proxy/network; default is offline")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    try:
        print(json.dumps(prepare(args, repo), indent=2))
        return 0
    except (PreparationError, OSError, ValueError, KeyError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
