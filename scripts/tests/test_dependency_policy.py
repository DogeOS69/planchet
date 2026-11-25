"""Contract checks for the dependency screen; no network or Cargo invocation."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "dependency_policy", Path(__file__).resolve().parents[1] / "check-dependency-policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class DependencyPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def graph(self, dependency="sha2", alias="sha2", kind=None, source=None, links=None):
        own = self.root / "crates" / "planchet"
        external = self.root / "registry" / dependency
        own.mkdir(parents=True)
        external.mkdir(parents=True)
        packages = [
            {"id": "root", "name": "planchet", "version": "0.1.0", "source": None,
             "manifest_path": str(own / "Cargo.toml"), "targets": []},
            {"id": "dependency", "name": dependency, "version": "1.0.0",
             "source": source or "registry+https://github.com/rust-lang/crates.io-index",
             "manifest_path": str(external / "Cargo.toml"), "links": links, "targets": []},
        ]
        return {"packages": packages, "workspace_members": ["root"], "resolve": {"nodes": [
            {"id": "root", "deps": [{"name": alias, "pkg": "dependency", "dep_kinds": [{"kind": kind}]}]},
            {"id": "dependency", "deps": []},
        ]}}

    def test_renaming_does_not_hide_forbidden_normal_dev_or_build_dependencies(self):
        for kind in [None, "dev", "build"]:
            with self.subTest(kind=kind):
                metadata = self.graph("ring", "innocent_crypto", kind)
                errors = policy.screen(metadata, self.root)[3]
                self.assertTrue(any("ring 1.0.0: forbidden package identity" in error for error in errors))
                # Allow repeated cases to use the same fixture directories.
                (self.root / "crates" / "planchet").rmdir()
                (self.root / "registry" / "ring").rmdir()

    def test_forbidden_alias_cannot_obscure_approved_package(self):
        metadata = self.graph(alias="nintondo_dogecoin")
        errors = policy.screen(metadata, self.root)[3]
        self.assertTrue(any("forbidden dependency alias nintondo_dogecoin" in error for error in errors))

    def test_unapproved_source_native_links_and_bundled_c_are_rejected(self):
        metadata = self.graph(source="git+https://example.org/renamed-crypto", links="crypto")
        (self.root / "registry" / "sha2" / "backend.c").write_text("/* fixture */")
        errors = policy.screen(metadata, self.root)[3]
        self.assertTrue(any("non-allowlisted source" in error for error in errors))
        self.assertTrue(any("native links declaration crypto" in error for error in errors))
        self.assertTrue(any("bundled native source/object: backend.c" in error for error in errors))

    def test_rust_build_script_and_build_dependency_are_allowed_and_reported(self):
        metadata = self.graph(kind="build")
        script = self.root / "crates" / "planchet" / "build.rs"
        script.write_text('fn main() {}')
        metadata["packages"][0]["targets"] = [{"kind": ["custom-build"], "src_path": str(script)}]
        packages, scripts, edges, errors = policy.screen(metadata, self.root)
        self.assertEqual(len(packages), 2)
        self.assertEqual(scripts, [str(script)])
        self.assertEqual(edges, ["planchet -> sha2"])
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
