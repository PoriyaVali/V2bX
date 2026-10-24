#!/usr/bin/env python3
"""Offline safety regressions for dependency preparation; no Go downloads."""

import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
import prepare_tls_dependencies as prep


class PreparationSafetyTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="v2bx-tls-preparation-test-")
        self.root = Path(self.temporary.name).resolve()
        # All cleanup remains within this exact newly allocated temporary tree.
        self.assertTrue(self.root.is_relative_to(Path(tempfile.gettempdir()).resolve()))
        self.git = shutil.which("git")
        self.env = os.environ.copy()

    def tearDown(self):
        self.assertEqual(Path(self.temporary.name).resolve(), self.root)
        self.temporary.cleanup()

    def fixture(self):
        target = self.root / "prepared"
        source = target / "source"
        source.mkdir(parents=True)
        (source / "go.mod").write_bytes(b"module example.com/core\n")
        (source / "serve.go").write_bytes(b"old\n")
        (source / "keep.txt").write_bytes(b"unmodified dependency source\n")
        base = prep.tree_hashes(source)
        patch = self.root / "lifecycle.patch"
        patch.write_bytes(b"diff --git a/serve.go b/serve.go\n--- a/serve.go\n+++ b/serve.go\n@@ -1 +1 @@\n-old\n+new\n")
        metadata = {"module": "example.com/fork", "module_path": "example.com/core", "version": "v1.0.0", "module_sum": prep.go_h1(base, "example.com/fork@v1.0.0/"), "files": [{"path": "serve.go", "base_sha256": base["serve.go"], "patched_sha256": prep.digest(b"new\n")}]}
        prep.git_apply(self.git, source, patch, self.env, "--check")
        prep.git_apply(self.git, source, patch, self.env)
        identity = {"fixture": True}
        manifest = {"identity": identity, "module": metadata["module"], "module_path": metadata["module_path"], "version": metadata["version"], "source_files": prep.tree_hashes(source)}
        (target / "manifest.json").write_bytes(prep.canonical(manifest))
        return target, metadata, patch, identity

    def test_paths_reject_traversal_windows_paths_and_git(self):
        for name in ("", "../outside", "/outside", "a/../b", "a//b", "a/./b", "C:/outside", "a\\b", ".git/config", "a\nb"):
            with self.subTest(name=name), self.assertRaises(prep.PreparationError):
                prep.relative_path(name)
        self.assertEqual(prep.relative_path("transport/internet/tls/config.go"), "transport/internet/tls/config.go")

    def test_hash1_sorts_paths_and_binds_prefix(self):
        hashes = {"z": prep.digest(b"z"), "a": prep.digest(b"a")}
        self.assertEqual(prep.go_h1(hashes), prep.go_h1(dict(reversed(list(hashes.items())))))
        self.assertNotEqual(prep.go_h1(hashes), prep.go_h1(hashes, "example.com/core@v1/"))

    @unittest.skipUnless(shutil.which("git"), "git is required for patch verification")
    def test_readonly_module_directories_are_patchable_without_touching_cache(self):
        cache = self.root / "module-cache"
        nested = cache / "transport" / "tls"
        nested.mkdir(parents=True)
        (cache / "empty").mkdir()
        original = nested / "config.go"
        original.write_bytes(b"old\n")
        cache_paths = [cache, *cache.rglob("*")]
        try:
            for path in reversed(cache_paths):
                path.chmod(0o555 if path.is_dir() else 0o444)
            original_modes = {path: stat.S_IMODE(path.stat().st_mode) for path in cache_paths}
            source = self.root / "staging"
            shutil.copytree(cache, source)
            prep.make_staging_writable(source)
            for path in [source, *source.rglob("*")]:
                self.assertTrue(path.stat().st_mode & stat.S_IWUSR, str(path))
                if path.is_dir():
                    self.assertTrue(path.stat().st_mode & stat.S_IXUSR, str(path))
            patch = self.root / "readonly.patch"
            patch.write_bytes(b"diff --git a/transport/tls/config.go b/transport/tls/config.go\n--- a/transport/tls/config.go\n+++ b/transport/tls/config.go\n@@ -1 +1 @@\n-old\n+new\n")
            prep.git_apply(self.git, source, patch, self.env, "--check")
            prep.git_apply(self.git, source, patch, self.env)
            self.assertEqual((source / "transport/tls/config.go").read_bytes(), b"new\n")
            self.assertEqual(original.read_bytes(), b"old\n")
            self.assertEqual({path: stat.S_IMODE(path.stat().st_mode) for path in cache_paths}, original_modes)
        finally:
            # Restore only this test's own fixture for Windows temporary cleanup.
            for path in cache_paths:
                path.chmod(0o755 if path.is_dir() else 0o644)

    @unittest.skipUnless(shutil.which("git"), "git is required for patch verification")
    def test_valid_prepared_tree_reverse_patch_and_full_checksum(self):
        target, metadata, patch, identity = self.fixture()
        prep.verify_prepared(target, identity, metadata, patch, self.git, self.env)

    @unittest.skipUnless(shutil.which("git"), "git is required for patch verification")
    def test_modified_source_is_rejected_and_preserved(self):
        target, metadata, patch, identity = self.fixture()
        modified = target / "source" / "serve.go"
        modified.write_bytes(b"changed\n")
        with self.assertRaisesRegex(prep.PreparationError, "altered"):
            prep.verify_prepared(target, identity, metadata, patch, self.git, self.env)
        self.assertEqual(modified.read_bytes(), b"changed\n")

    @unittest.skipUnless(shutil.which("git"), "git is required for patch verification")
    def test_modified_manifest_cannot_hide_unpatched_file_tampering(self):
        target, metadata, patch, identity = self.fixture()
        (target / "source" / "keep.txt").write_bytes(b"unexpected code\n")
        manifest = prep.load_json(target / "manifest.json")
        manifest["source_files"] = prep.tree_hashes(target / "source")
        (target / "manifest.json").write_bytes(prep.canonical(manifest))
        with self.assertRaisesRegex(prep.PreparationError, "full-module checksum"):
            prep.verify_prepared(target, identity, metadata, patch, self.git, self.env)

    @unittest.skipUnless(shutil.which("git"), "git is required for patch verification")
    def test_inserted_source_file_and_rewritten_manifest_fail_module_checksum(self):
        target, metadata, patch, identity = self.fixture()
        (target / "source" / "unexpected.go").write_bytes(b"package unwanted\n")
        manifest = prep.load_json(target / "manifest.json")
        manifest["source_files"] = prep.tree_hashes(target / "source")
        (target / "manifest.json").write_bytes(prep.canonical(manifest))
        with self.assertRaisesRegex(prep.PreparationError, "full-module checksum"):
            prep.verify_prepared(target, identity, metadata, patch, self.git, self.env)

    @unittest.skipUnless(shutil.which("git"), "git is required for patch verification")
    def test_extra_output_file_is_rejected(self):
        target, metadata, patch, identity = self.fixture()
        (target / "unexpected.txt").write_bytes(b"keep me\n")
        with self.assertRaisesRegex(prep.PreparationError, "Unexpected files"):
            prep.verify_prepared(target, identity, metadata, patch, self.git, self.env)

    def test_all_target_version_replacements_dropped_and_third_party_absolutized(self):
        third_party = self.root / "third_party" / "protocol"
        third_party.mkdir(parents=True)
        (third_party / "go.mod").write_bytes(b"module example.com/protocol\n")
        graph = {"Replace": [{"Old": {"Path": "example.com/core", "Version": "v1.0.0"}, "New": {"Path": "example.com/fork", "Version": "v2.0.0"}}, {"Old": {"Path": "example.com/core"}, "New": {"Path": "example.com/other", "Version": "v3.0.0"}}, {"Old": {"Path": "example.com/protocol"}, "New": {"Path": "./third_party/protocol"}}]}
        prepared = self.root / "prepared-source"
        flags = prep.graph_replacements(graph, self.root, {"example.com/core": prepared})
        self.assertIn("-dropreplace=example.com/core@v1.0.0", flags)
        self.assertIn("-dropreplace=example.com/core", flags)
        self.assertIn(f"-replace=example.com/protocol={third_party.as_posix()}", flags)
        self.assertIn(f"-replace=example.com/core={prepared.as_posix()}", flags)

    def test_metadata_must_match_effective_normal_graph_pin(self):
        graph = {"Require": [{"Path": "example.com/core", "Version": "v1.0.0"}], "Replace": [{"Old": {"Path": "example.com/core"}, "New": {"Path": "example.com/fork", "Version": "v2.0.0"}}, {"Old": {"Path": "example.com/core", "Version": "v1.0.0"}, "New": {"Path": "example.com/fork", "Version": "v3.0.0"}}]}
        metadata = {"module_path": "example.com/core", "module": "example.com/fork", "version": "v3.0.0"}
        prep.verify_pin(graph, metadata)
        metadata["version"] = "v2.0.0"
        with self.assertRaisesRegex(prep.PreparationError, "normal go.mod pin"):
            prep.verify_pin(graph, metadata)


if __name__ == "__main__":
    unittest.main()
