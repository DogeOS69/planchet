#!/usr/bin/env python3
"""Static dependency-policy screening. Requires Python 3.9+ and a locked Cargo graph.

This is not a Rust build, a sandbox, or proof that arbitrary Rust/build scripts
cannot invoke native tools. See README.md for compilation and artifact checks.
"""

import argparse
import json
import re
from pathlib import Path
import subprocess
import sys


FORBIDDEN = {
    "cc", "cmake", "bindgen", "clang-sys", "pkg-config", "vcpkg",
    "ring", "aws-lc-rs", "aws-lc-sys", "aws-lc-fips-sys",
    "openssl", "openssl-sys", "openssl-src", "native-tls", "libdogecoin",
    "secp256k1", "secp256k1-sys", "sha2-asm",
}
NATIVE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".m", ".mm",
                   ".s", ".asm", ".cu", ".cuh", ".o", ".obj", ".a", ".lib", ".so", ".dylib", ".dll"}
REGISTRY_SOURCES = {"registry+https://github.com/rust-lang/crates.io-index",
                    "sparse+https://index.crates.io/"}
PRIVATE_KEY_PACKAGES = {"planchet-signer", "planchet-psbt", "k256", "p256", "ecdsa", "elliptic-curve"}
NETWORK_PACKAGES = {"planchet-provider", "planchet-transport", "planchet-rpc-types",
                    "reqwest", "hyper", "hyper-util", "h2", "tokio", "mio", "socket2",
                    "native-tls", "rustls", "getrandom"}


def check_lock_sources(workspace):
    """Reject stale non-registry sources even when a selected graph omits them."""
    sources = re.findall(r'^source = "([^"\n]+)"$',
                         (workspace / "Cargo.lock").read_text(), re.MULTILINE)
    return [f"Cargo.lock: non-allowlisted source: {source}"
            for source in sorted(set(sources)) if source not in REGISTRY_SOURCES]


def forbidden(identity):
    name = identity.lower().replace("_", "-")
    return (name in FORBIDDEN or name.endswith("-sys")
            or "nintondo" in name or "nintendo" in name
            or "libdogecoin" in name)


def resolved_packages(metadata, selected_ids=None):
    """Follow actual resolved edges, including dev/build; ignore inactive targets."""
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    packages = {package["id"]: package for package in metadata["packages"]}
    pending = list(metadata["workspace_members"] if selected_ids is None else selected_ids)
    selected = set()
    aliases = []
    while pending:
        identity = pending.pop()
        if identity in selected:
            continue
        selected.add(identity)
        for dep in nodes[identity]["deps"]:
            if selected_ids is not None and dep["pkg"] not in selected_ids:
                continue
            aliases.append((packages[identity]["name"], dep["name"]))
            pending.append(dep["pkg"])
    return [packages[key] for key in sorted(selected)], aliases


def screen(metadata, workspace, selected_ids=None):
    packages, aliases = resolved_packages(metadata, selected_ids)
    violations = []
    build_scripts = []
    build_edges = []
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    by_id = {package["id"]: package for package in packages}
    for owner, alias in aliases:
        if forbidden(alias):
            violations.append(f"{owner}: forbidden dependency alias {alias}")
    for package in packages:
        label = f'{package["name"]} {package["version"]}'
        directory = Path(package["manifest_path"]).resolve().parent
        source = package["source"]
        if forbidden(package["name"]):
            violations.append(f"{label}: forbidden package identity")
        if source is None:
            if not directory.is_relative_to(workspace / "crates"):
                violations.append(f"{label}: path source outside workspace crates/: {directory}")
        elif source not in REGISTRY_SOURCES:
            violations.append(f"{label}: non-allowlisted source: {source}")
        if package.get("links"):
            violations.append(f'{label}: native links declaration {package["links"]}')
        # A rename cannot hide the underlying resolved package or its source.
        # Inspect every normal/dev/build edge, not only the library's normal tree.
        for dep in nodes[package["id"]]["deps"]:
            if dep["pkg"] not in by_id:
                continue
            if any(kind["kind"] == "build" for kind in dep["dep_kinds"]):
                build_edges.append(f'{package["name"]} -> {by_id[dep["pkg"]]["name"]}')
        for target in package["targets"]:
            if "custom-build" in target["kind"]:
                build_scripts.append(str(Path(target["src_path"]).resolve()))
        # Scan the package source directory, not only targets known to Cargo:
        # vendored C, assembly and precompiled libraries are also disallowed.
        for path in directory.rglob("*"):
            relative = path.relative_to(directory)
            if any(part in {".git", "target", "__pycache__"} for part in relative.parts):
                continue
            if path.is_file() and path.suffix.lower() in NATIVE_SUFFIXES:
                violations.append(f"{label}: bundled native source/object: {relative}")
    return packages, build_scripts, build_edges, sorted(set(violations))


def tree_label(package):
    """Cargo tree's {p} display, including source to distinguish forks."""
    label = f'{package["name"]} v{package["version"]}'
    if any("proc-macro" in target["kind"] for target in package["targets"]):
        label += " (proc-macro)"
    source = package["source"]
    if source is None:
        return f'{label} ({Path(package["manifest_path"]).resolve().parent})'
    if source.startswith("git+"):
        url, revision = source[4:].rsplit("#", 1)
        return f"{label} ({url}#{revision[:8]})"
    if source in REGISTRY_SOURCES:
        return label
    raise ValueError(f"unrecognized tree source: {source}")


def selected_tree(metadata, tree):
    """Match exact package identities, never aliases or just name/version.

    A package-selected Cargo tree supplies actual features/normal/dev/build
    packages. Workspace metadata alone unifies unrelated member features.
    Fail closed if Cargo's display changes or a package cannot be matched.
    """
    by_label = {}
    for package in metadata["packages"]:
        label = tree_label(package)
        if label in by_label and by_label[label] != package["id"]:
            raise ValueError(f"ambiguous Cargo tree package identity: {label}")
        by_label[label] = package["id"]
    selected = set()
    features = {}
    for line in tree.splitlines():
        if not line.strip():
            continue
        label, enabled = line.removesuffix(" (*)").split("|", 1)
        if label not in by_label:
            raise ValueError(f"Cargo tree package absent from metadata: {label}")
        identity = by_label[label]
        selected.add(identity)
        features.setdefault(identity, set()).update(filter(None, enabled.split(",")))
    if not selected:
        raise ValueError("Cargo returned an empty consumer tree")
    return selected, features


def profile_violations(packages, features, denied):
    errors = [f"unexpected package {name}"
              for name in sorted({package["name"] for package in packages} & denied)]
    for package in packages:
        if package["name"] == "planchet-signer" and "local" in features.get(package["id"], set()):
            errors.append("local signing must remain disabled")
    return errors


def screen_profiles(workspace, toolchain, host_target):
    """Screen independently selected consumer trees without workspace unification.

    Dev dependencies are covered by the workspace screen. These consumer graphs
    include normal/build edges and inspect resolved features as well as names.
    """
    metadata = json.loads(subprocess.check_output([
        "cargo", f"+{toolchain}", "metadata", "--locked", "--format-version", "1", "--all-features",
    ], cwd=workspace, text=True))
    profiles = [
        ("default", ["-p", "planchet", "--target", host_target], PRIVATE_KEY_PACKAGES),
        ("rpc-http", ["-p", "planchet", "--features", "rpc,http", "--target", host_target], PRIVATE_KEY_PACKAGES),
        ("provider-sha256", ["-p", "planchet", "--no-default-features", "--features", "crypto-backend",
                             "--target", host_target], PRIVATE_KEY_PACKAGES | NETWORK_PACKAGES | {"sha3"}),
        ("provider-curves", ["-p", "planchet", "--no-default-features", "--features", "crypto-backend,keccak,k256,p256",
                             "--target", host_target], NETWORK_PACKAGES | {"planchet-signer", "planchet-psbt"}),
        ("verification", ["-p", "planchet", "--no-default-features", "--features", "crypto-backend,psbt,signer",
                           "--target", host_target], NETWORK_PACKAGES),
        ("wasm-policy", ["-p", "planchet-signer", "--no-default-features", "--features", "verify,psbt,crypto-backend",
                          "--target", "wasm32-unknown-unknown"], NETWORK_PACKAGES),
    ]
    violations = []
    for label, arguments, denied in profiles:
        tree = subprocess.check_output([
            "cargo", f"+{toolchain}", "tree", "--locked", "-e", "normal,build",
            "--prefix", "none", "--format", "{p}|{f}", *arguments,
        ], cwd=workspace, text=True)
        selected, features = selected_tree(metadata, tree)
        packages, _, _, errors = screen(metadata, workspace, selected)
        errors.extend(profile_violations(packages, features, denied))
        violations.extend(f"{label}: {error}" for error in errors)
        print(f'{label}: {len(packages)} packages; ' + ("FAIL" if errors else "PASS separation"))
    return violations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", default="1.91.0")
    parser.add_argument("--target", help="target triple; defaults to the selected rustc host")
    parser.add_argument("--no-default-features", action="store_true",
                        help="screen the minimal workspace graph instead of all features")
    parser.add_argument("--check-profiles", action="store_true",
                        help="also screen default/RPC, SHA-only provider, curve and verification profiles")
    args = parser.parse_args()
    workspace = Path(__file__).resolve().parents[1]
    version = subprocess.check_output(["rustc", f"+{args.toolchain}", "-vV"], text=True)
    host_target = next(line.split(": ", 1)[1] for line in version.splitlines() if line.startswith("host: "))
    args.target = args.target or host_target
    command = ["cargo", f"+{args.toolchain}", "metadata", "--locked", "--format-version", "1",
               "--filter-platform", args.target,
               "--no-default-features" if args.no_default_features else "--all-features"]
    print("Running:", " ".join(command), flush=True)
    metadata = json.loads(subprocess.check_output(command, cwd=workspace, text=True))
    if metadata.get("resolve") is None:
        raise ValueError("cargo metadata returned no resolved graph")
    packages, scripts, edges, violations = screen(metadata, workspace)
    violations.extend(check_lock_sources(workspace))
    if args.check_profiles:
        violations.extend(screen_profiles(workspace, args.toolchain, host_target))
    print(f"Screened {len(packages)} resolved packages on {args.target} (normal/dev/build).")
    print("Build dependencies: " + (", ".join(sorted(edges)) or "none"))
    print("Rust build scripts requiring source review:")
    for path in scripts:
        print(" ", path)
    if not scripts:
        print("  none")
    for violation in violations:
        print("FAIL:", violation, file=sys.stderr)
    if violations:
        return 1
    print("PASS: static screening only; compilation and native-link proof are separate checks.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"Dependency screening failed: {error}", file=sys.stderr)
        sys.exit(2)
