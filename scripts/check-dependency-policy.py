#!/usr/bin/env python3
"""Static dependency-policy screening. Requires Python 3.9+ and a locked Cargo graph.

This is not a Rust build, a sandbox, or proof that arbitrary Rust/build scripts
cannot invoke native tools. See README.md for compilation and artifact checks.
"""

import argparse
import json
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
                   ".s", ".asm", ".o", ".obj", ".a", ".lib", ".so", ".dylib", ".dll"}
REGISTRY_SOURCES = {"registry+https://github.com/rust-lang/crates.io-index",
                    "sparse+https://index.crates.io/"}
PRIVATE_KEY_PACKAGES = {"planchet-signer", "planchet-psbt", "k256", "ecdsa", "elliptic-curve"}
NETWORK_PACKAGES = {"planchet-provider", "planchet-transport", "planchet-rpc-types",
                    "reqwest", "hyper", "hyper-util", "h2", "tokio", "mio", "socket2",
                    "native-tls", "rustls", "getrandom"}


def forbidden(identity):
    name = identity.lower().replace("_", "-")
    return (name in FORBIDDEN or name.endswith("-sys")
            or "nintondo" in name or "nintendo" in name
            or "libdogecoin" in name)


def resolved_packages(metadata):
    """Follow actual resolved edges, including dev/build; ignore inactive targets."""
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    packages = {package["id"]: package for package in metadata["packages"]}
    pending = list(metadata["workspace_members"])
    selected = set()
    aliases = []
    while pending:
        identity = pending.pop()
        if identity in selected:
            continue
        selected.add(identity)
        for dep in nodes[identity]["deps"]:
            aliases.append((packages[identity]["name"], dep["name"]))
            pending.append(dep["pkg"])
    return [packages[key] for key in sorted(selected)], aliases


def screen(metadata, workspace):
    packages, aliases = resolved_packages(metadata)
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


def screen_profiles(workspace, toolchain, host_target):
    """Use Cargo's package-selected trees to avoid workspace feature unification.

    Metadata selects the entire workspace. These independent invocations instead
    check consumer-specific normal/build graphs. Dev dependencies stay covered by
    the workspace metadata screen, but are not shipped in a consumer library.
    """
    profiles = [
        ("default", ["-p", "planchet", "--target", host_target], PRIVATE_KEY_PACKAGES),
        ("rpc-http", ["-p", "planchet", "--features", "rpc,http", "--target", host_target], PRIVATE_KEY_PACKAGES),
        ("wasm-policy", ["-p", "planchet-signer", "--no-default-features", "--features", "verify,psbt",
                         "--target", "wasm32-unknown-unknown"], NETWORK_PACKAGES),
    ]
    violations = []
    for label, arguments, denied in profiles:
        command = ["cargo", f"+{toolchain}", "tree", "--locked", "-e", "normal,build",
                   "--prefix", "none", "--format", "{p}", *arguments]
        tree = subprocess.check_output(command, cwd=workspace, text=True)
        names = {line.split()[0] for line in tree.splitlines() if line.strip()}
        rejected = names & denied
        if rejected:
            violations.append(f'{label}: unexpected packages {", ".join(sorted(rejected))}')
        print(f'{label}: {len(names)} packages; ' + ("FAIL" if rejected else "PASS separation"))
    return violations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", default="1.91.0")
    parser.add_argument("--target", help="target triple; defaults to the selected rustc host")
    parser.add_argument("--no-default-features", action="store_true",
                        help="screen the minimal workspace graph instead of all features")
    parser.add_argument("--check-profiles", action="store_true",
                        help="also screen default/RPC private-key separation and WASM policy networking/entropy")
    args = parser.parse_args()
    workspace = Path(__file__).resolve().parents[1]
    if args.target is None:
        version = subprocess.check_output(["rustc", f"+{args.toolchain}", "-vV"], text=True)
        args.target = next(line.split(": ", 1)[1] for line in version.splitlines() if line.startswith("host: "))
    command = ["cargo", f"+{args.toolchain}", "metadata", "--locked", "--format-version", "1",
               "--filter-platform", args.target,
               "--no-default-features" if args.no_default_features else "--all-features"]
    print("Running:", " ".join(command), flush=True)
    metadata = json.loads(subprocess.check_output(command, cwd=workspace, text=True))
    if metadata.get("resolve") is None:
        raise ValueError("cargo metadata returned no resolved graph")
    packages, scripts, edges, violations = screen(metadata, workspace)
    if args.check_profiles:
        violations.extend(screen_profiles(workspace, args.toolchain, args.target))
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
