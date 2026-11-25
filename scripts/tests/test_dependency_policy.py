"""Contract checks for the dependency screen; no network or Cargo invocation."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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


    def pinned(self, name="openvm", version="1.7.0"):
        metadata = self.graph(name, "backend", source=policy.OPENVM_SOURCE)
        metadata["packages"][1]["version"] = version
        return metadata

    def test_only_reviewed_guest_package_versions_at_exact_tag_and_sha_are_allowed(self):
        metadata = self.pinned("k256", "0.13.4")
        dependency = metadata["packages"][1]
        self.assertEqual(policy.screen(metadata, self.root)[3], [])
        # Same commit under a rev selector has a different Cargo package ID.
        invalid = [
            policy.OPENVM_SOURCE.replace("tag=v1.7.0", "rev=" + policy.OPENVM_SHA),
            policy.OPENVM_SOURCE.replace(policy.OPENVM_SHA, "0" * 40),
            policy.OPENVM_SOURCE.replace("openvm-org", "lookalike-org"),
            policy.OPENVM_SOURCE.replace("v1.7.0", "v1.7.1"),
        ]
        for source in invalid:
            with self.subTest(source=source):
                dependency["source"] = source
                self.assertTrue(any("non-allowlisted source" in error
                                    for error in policy.screen(metadata, self.root)[3]))
        dependency["source"] = policy.OPENVM_SOURCE
        dependency["version"] = "0.13.5"
        self.assertTrue(any("non-allowlisted source" in error
                            for error in policy.screen(metadata, self.root)[3]))

    def test_pinned_repository_does_not_allow_unreviewed_sdk_packages_or_native_links(self):
        metadata = self.pinned("openvm-circuit")
        self.assertTrue(any("non-allowlisted source" in error
                            for error in policy.screen(metadata, self.root)[3]))
        metadata = self.pinned()
        metadata["packages"][1]["links"] = "crypto"
        self.assertIn("openvm 1.7.0: native links declaration crypto", policy.screen(metadata, self.root)[3])

    def test_openvm_registry_lookalike_is_rejected(self):
        metadata = self.graph("openvm")
        metadata["packages"][1]["version"] = "1.7.0"
        self.assertTrue(any("not an approved pinned guest library" in error
                            for error in policy.screen(metadata, self.root)[3]))

    def test_runtime_assembly_exception_requires_identity_path_source_and_exact_bytes(self):
        metadata = self.pinned()
        package = metadata["packages"][1]
        directory = Path(package["manifest_path"]).parent
        source = directory / "src"
        source.mkdir()
        runtime = source / "memcpy.s"
        runtime.write_bytes(b"known runtime assembly fixture\n")
        # A tiny reviewed fixture substitutes for the much larger upstream file.
        # This fixed digest was computed independently with shasum -a 256.
        digest = "0e4eb0a9928beb1f643fd734c33e0b6c036b1ebde787ac4f93bba5f452abe83b"
        with patch.dict(policy.OPENVM_RUNTIME_ASM, {"src/memcpy.s": digest}):
            self.assertEqual(policy.screen(metadata, self.root)[3], [])
            for suffix in [".c", ".s", ".o", ".cu"]:
                path = source / ("crypto" + suffix)
                path.write_bytes(runtime.read_bytes())
                errors = policy.screen(metadata, self.root)[3]
                self.assertIn(f"openvm 1.7.0: bundled native source/object: src/crypto{suffix}", errors)
                path.unlink()
            runtime.write_bytes(b"changed assembly\n")
            self.assertIn("openvm 1.7.0: bundled native source/object: src/memcpy.s",
                          policy.screen(metadata, self.root)[3])
            runtime.write_bytes(b"known runtime assembly fixture\n")
            package["source"] = policy.OPENVM_SOURCE.replace(policy.OPENVM_SHA, "0" * 40)
            self.assertTrue(any("bundled native source/object" in error
                                for error in policy.screen(metadata, self.root)[3]))
            package["source"] = policy.OPENVM_SOURCE
            package["name"] = "openvm-platform"
            self.assertTrue(any("bundled native source/object" in error
                                for error in policy.screen(metadata, self.root)[3]))

    def test_frozen_lock_rejects_moved_tag_even_when_host_graph_omits_openvm(self):
        lock = self.root / "Cargo.lock"
        lock.write_text(f'source = "{policy.OPENVM_SOURCE}"\n')
        self.assertEqual(policy.check_openvm_lock(self.root), [])
        lock.write_text(f'source = "{policy.OPENVM_SOURCE.replace(policy.OPENVM_SHA, "0" * 40)}"\n')
        self.assertTrue(any("OpenVM source must be exactly" in error
                            for error in policy.check_openvm_lock(self.root)))

    def test_consumer_tree_distinguishes_software_and_accelerated_curve_identity(self):
        metadata = self.pinned("k256", "0.13.4")
        accelerated = metadata["packages"][1]
        software = dict(accelerated, id="software", source="registry+https://github.com/rust-lang/crates.io-index")
        metadata["packages"].append(software)
        macro = dict(accelerated, id="macro", name="openvm-custom-insn", version="0.1.0",
                     targets=[{"kind": ["proc-macro"]}])
        metadata["packages"].append(macro)
        tree = ("k256 v0.13.4|ecdsa\n"
                "k256 v0.13.4 (https://github.com/openvm-org/openvm.git?tag=v1.7.0#425913bd)|arithmetic,ecdsa\n"
                "openvm-custom-insn v0.1.0 (proc-macro) (https://github.com/openvm-org/openvm.git?tag=v1.7.0#425913bd)|\n"
                "k256 v0.13.4|ecdsa (*)\n")
        selected, features = policy.selected_tree(metadata, tree)
        self.assertEqual(selected, {"software", "dependency", "macro"})
        self.assertEqual(features["dependency"], {"arithmetic", "ecdsa"})
        self.assertEqual(features["software"], {"ecdsa"})
        for invalid in ["", "unknown v0.1.0|\n"]:
            with self.subTest(tree=invalid), self.assertRaises(ValueError):
                policy.selected_tree(metadata, invalid)

    def test_selected_graph_retains_build_checks_but_omits_inactive_packages(self):
        metadata = self.graph("ring", "renamed", kind="build")
        selected, _ = policy.selected_tree(metadata, f'{policy.tree_label(metadata["packages"][0])}|\n')
        self.assertEqual(policy.screen(metadata, self.root, selected)[3], [])
        selected.add("dependency")
        self.assertIn("ring 1.0.0: forbidden package identity", policy.screen(metadata, self.root, selected)[3])

    def profile(self):
        packages = [
            {"id": name, "name": name, "version": version, "source": policy.OPENVM_SOURCE}
            for name, version in [("openvm-sha2", "1.7.0"), ("openvm-keccak256", "1.7.0"),
                                  ("k256", "0.13.4"), ("p256", "0.13.2")]
        ]
        packages.extend([
            {"id": "signer", "name": "planchet-signer", "source": None},
            {"id": "entropy", "name": "getrandom", "source": "registry+https://github.com/rust-lang/crates.io-index"},
        ])
        return packages

    def test_host_proc_macro_entropy_is_screened_but_guest_runtime_entropy_is_rejected(self):
        packages = self.profile()
        runtime = {"signer", "k256", "p256", "openvm-sha2", "openvm-keccak256"}
        self.assertEqual(policy.openvm_profile_violations(packages, {"signer": {"verify"}}, runtime), [])
        runtime.add("entropy")
        self.assertIn("openvm-policy: unexpected guest runtime entropy package getrandom",
                      policy.openvm_profile_violations(packages, {"signer": {"verify"}}, runtime))
        # Host placement never excuses prohibited crypto sources.
        metadata = self.graph("ring", "host_macro_dependency", kind="build")
        self.assertIn("ring 1.0.0: forbidden package identity", policy.screen(metadata, self.root)[3])

    def test_openvm_profile_requires_accelerators_and_keeps_local_signing_separate(self):
        packages = self.profile()
        self.assertIn("openvm-policy: local signing must remain disabled",
                      policy.openvm_profile_violations(packages, {"signer": {"local", "verify"}}, set()))
        packages = [package for package in packages if package["name"] != "p256"]
        self.assertIn("openvm-policy: missing pinned accelerated package p256",
                      policy.openvm_profile_violations(packages, {}, set()))


if __name__ == "__main__":
    unittest.main()
