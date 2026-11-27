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
        own.mkdir(parents=True, exist_ok=True)
        external.mkdir(parents=True, exist_ok=True)
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


    def test_git_sources_are_rejected_even_for_registry_package_names(self):
        metadata = self.graph("k256", "backend", source="git+https://example.org/crypto?rev=abc#abc")
        self.assertIn("k256 1.0.0: non-allowlisted source: git+https://example.org/crypto?rev=abc#abc",
                      policy.screen(metadata, self.root)[3])

    def test_every_native_source_and_object_suffix_is_rejected(self):
        metadata = self.graph()
        source = self.root / "registry" / "sha2" / "src"
        source.mkdir()
        for suffix in [".c", ".cpp", ".s", ".asm", ".o", ".a", ".cu", ".so"]:
            with self.subTest(suffix=suffix):
                path = source / ("backend" + suffix)
                path.write_bytes(b"native fixture")
                self.assertIn(f"sha2 1.0.0: bundled native source/object: src/backend{suffix}",
                              policy.screen(metadata, self.root)[3])
                path.unlink()

    def test_lock_rejects_git_sources_even_when_selected_graph_omits_them(self):
        lock = self.root / "Cargo.lock"
        lock.write_text('source = "registry+https://github.com/rust-lang/crates.io-index"\n')
        self.assertEqual(policy.check_lock_sources(self.root), [])
        lock.write_text('source = "git+https://example.org/crypto?tag=v1#abc"\n')
        self.assertEqual(policy.check_lock_sources(self.root),
                         ["Cargo.lock: non-allowlisted source: git+https://example.org/crypto?tag=v1#abc"])

    def test_consumer_tree_distinguishes_registry_git_and_macro_identities(self):
        metadata = self.graph("k256", "backend")
        software = metadata["packages"][1]
        alternate = dict(software, id="alternate", source="git+https://example.org/crypto?rev=12345678#12345678abcdef")
        macro = dict(software, id="macro", name="derive-key", targets=[{"kind": ["proc-macro"]}])
        metadata["packages"].extend([alternate, macro])
        tree = ("k256 v1.0.0|ecdsa\n"
                "k256 v1.0.0 (https://example.org/crypto?rev=12345678#12345678)|arithmetic,ecdsa\n"
                "derive-key v1.0.0 (proc-macro)|\n"
                "k256 v1.0.0|ecdsa (*)\n")
        selected, features = policy.selected_tree(metadata, tree)
        self.assertEqual(selected, {"dependency", "alternate", "macro"})
        self.assertEqual(features["alternate"], {"arithmetic", "ecdsa"})
        self.assertEqual(features["dependency"], {"ecdsa"})
        for invalid in ["", "unknown v0.1.0|\n"]:
            with self.subTest(tree=invalid), self.assertRaises(ValueError):
                policy.selected_tree(metadata, invalid)

    def test_selected_graph_retains_build_checks_but_omits_inactive_packages(self):
        metadata = self.graph("ring", "renamed", kind="build")
        selected, _ = policy.selected_tree(metadata, f'{policy.tree_label(metadata["packages"][0])}|\n')
        self.assertEqual(policy.screen(metadata, self.root, selected)[3], [])
        selected.add("dependency")
        self.assertIn("ring 1.0.0: forbidden package identity", policy.screen(metadata, self.root, selected)[3])

    def test_sha_only_provider_profile_permits_crypto_owner_but_rejects_optional_algorithms(self):
        packages = [{"id": "crypto", "name": "planchet-crypto"}]
        denied = policy.PRIVATE_KEY_PACKAGES | policy.NETWORK_PACKAGES | {"sha3"}
        self.assertEqual(policy.profile_violations(packages, {}, denied), [])
        for name in ["k256", "p256", "sha3", "getrandom", "planchet-signer"]:
            with self.subTest(package=name):
                self.assertIn(f"unexpected package {name}",
                              policy.profile_violations(packages + [{"id": name, "name": name}], {}, denied))

    def test_verification_profile_rejects_network_entropy_and_local_signing(self):
        packages = [{"id": "signer", "name": "planchet-signer"},
                    {"id": "entropy", "name": "getrandom"}]
        self.assertEqual(policy.profile_violations(packages[:1], {"signer": {"verify"}}, policy.NETWORK_PACKAGES), [])
        self.assertEqual(policy.profile_violations(packages, {"signer": {"local", "verify"}}, policy.NETWORK_PACKAGES),
                         ["unexpected package getrandom", "local signing must remain disabled"])


if __name__ == "__main__":
    unittest.main()
