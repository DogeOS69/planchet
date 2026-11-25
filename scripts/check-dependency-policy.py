#!/usr/bin/env python3
"""Static dependency-policy screening. Requires Python 3.9+ and a locked Cargo graph.

This is not a Rust build, a sandbox, or proof that arbitrary Rust/build scripts
cannot invoke native tools. See README.md for compilation and artifact checks.
"""

import argparse
import hashlib
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
PRIVATE_KEY_PACKAGES = {"planchet-signer", "planchet-psbt", "planchet-crypto", "k256", "p256", "ecdsa", "elliptic-curve"}
NETWORK_PACKAGES = {"planchet-provider", "planchet-transport", "planchet-rpc-types",
                    "reqwest", "hyper", "hyper-util", "h2", "tokio", "mio", "socket2",
                    "native-tls", "rustls", "getrandom"}


OPENVM_TARGET = "riscv32im-risc0-zkvm-elf"
OPENVM_SHA = "425913bdc743ef44236daf472ec53c2c05b75fa1"
OPENVM_SOURCE = f"git+https://github.com/openvm-org/openvm.git?tag=v1.7.0#{OPENVM_SHA}"
# Only guest libraries and the proc macros they actually need. Circuit/prover,
# pairing, other revisions, registry lookalikes and repository-wide exceptions
# are deliberately absent. RustCrypto k256/p256 from crates.io remain allowed.
OPENVM_PACKAGES = dict.fromkeys({
    "openvm", "openvm-platform", "openvm-custom-insn", "openvm-rv32im-guest",
    "openvm-sha2", "openvm-sha256-guest", "openvm-keccak256", "openvm-keccak256-guest",
    "openvm-algebra-guest", "openvm-algebra-moduli-macros", "openvm-algebra-complex-macros",
    "openvm-ecc-guest", "openvm-ecc-sw-macros", "openvm-macros-common",
}, "1.7.0")
OPENVM_PACKAGES.update({"openvm-custom-insn": "0.1.0", "k256": "0.13.4", "p256": "0.13.2"})
# These two pinned VM-runtime files provide memory operations, not cryptography.
# They were generated upstream from musl C; no C compiler runs in the guest build.
# Match identity, source, path AND bytes; never exempt all assembly or an SDK tree.
OPENVM_RUNTIME_ASM = {
    "src/memcpy.s": "14912407df84e63f2e3a83e80f97bf685dac47c5c6bca6d4de38763a3a7bdc19",
    "src/memset.s": "381b51e8030234748fb76052af49b3fd8c611e5807fd09ab884ff88a0eba03e2",
}
OPENVM_FEATURES = "planchet/openvm,planchet/psbt,planchet/signer"


def approved_openvm(package):
    return (package["source"] == OPENVM_SOURCE
            and OPENVM_PACKAGES.get(package["name"]) == package["version"])


def runtime_assembly(package, relative, path):
    expected = OPENVM_RUNTIME_ASM.get(relative.as_posix())
    return (package["name"] == "openvm" and approved_openvm(package)
            and expected is not None and hashlib.sha256(path.read_bytes()).hexdigest() == expected)


def check_openvm_lock(workspace):
    """Even a host-only screen must notice a moved tag in the frozen lockfile."""
    text = (workspace / "Cargo.lock").read_text()
    sources = re.findall(r'^source = "(git\+https://github\.com/openvm-org/openvm(?:\.git)?[^"\n]*)"$',
                         text, re.MULTILINE)
    return [f"Cargo.lock: OpenVM source must be exactly {OPENVM_SOURCE}: {source}"
            for source in sorted(set(sources)) if source != OPENVM_SOURCE]


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
        elif source not in REGISTRY_SOURCES and not approved_openvm(package):
            violations.append(f"{label}: non-allowlisted source: {source}")
        if (package["name"] == "openvm" or package["name"].startswith("openvm-")) and not approved_openvm(package):
            violations.append(f"{label}: OpenVM package is not an approved pinned guest library")
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
            if (path.is_file() and path.suffix.lower() in NATIVE_SUFFIXES
                    and not runtime_assembly(package, relative, path)):
                violations.append(f"{label}: bundled native source/object: {relative}")
    return packages, build_scripts, build_edges, sorted(set(violations))


def tree_label(package):
    """Cargo tree's {p} display, including source to distinguish curve forks."""
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


def openvm_profile_violations(packages, features, runtime_ids):
    errors = []
    names = {package["name"] for package in packages}
    for name in sorted(names & (NETWORK_PACKAGES - {"getrandom"})):
        errors.append(f"openvm-policy: unexpected networking package {name}")
    if any(package["name"] == "getrandom" and package["id"] in runtime_ids for package in packages):
        errors.append("openvm-policy: unexpected guest runtime entropy package getrandom")
    required = {"openvm-sha2", "openvm-keccak256", "k256", "p256"}
    accelerated = {package["name"] for package in packages if approved_openvm(package)}
    for name in sorted(required - accelerated):
        errors.append(f"openvm-policy: missing pinned accelerated package {name}")
    for package in packages:
        enabled = features.get(package["id"], set())
        if package["name"] == "planchet-signer" and "local" in enabled:
            errors.append("openvm-policy: local signing must remain disabled")
    return errors


def load_openvm_graph(workspace, toolchain):
    common = ["--locked", "--no-default-features", "--features", OPENVM_FEATURES]
    # Keep host-side proc-macro/build dependencies in metadata too; the target
    # tree below selects actual packages for both execution platforms. Filtering
    # metadata to zkVM alone drops host-only dependencies such as libc.
    metadata = json.loads(subprocess.check_output([
        "cargo", f"+{toolchain}", "metadata", "--format-version", "1",
        *common,
    ], cwd=workspace, text=True))
    tree = subprocess.check_output([
        "cargo", f"+{toolchain}", "tree", "-p", "planchet", "--target", OPENVM_TARGET,
        "-e", "normal,build,dev", "--prefix", "none", "--format", "{p}|{f}", *common,
    ], cwd=workspace, text=True)
    selected, features = selected_tree(metadata, tree)
    # Proc macros/build scripts execute on the host. Their dependencies are
    # still source-screened above; a separate normal tree establishes what is
    # shipped into the guest, without allowing host-only entropy into runtime.
    runtime_tree = subprocess.check_output([
        "cargo", f"+{toolchain}", "tree", "-p", "planchet", "--target", OPENVM_TARGET,
        "-e", "normal,no-proc-macro", "--prefix", "none", "--format", "{p}|{f}", *common,
    ], cwd=workspace, text=True)
    runtime, _ = selected_tree(metadata, runtime_tree)
    return metadata, selected, features, runtime


def screen_openvm(workspace, toolchain):
    metadata, selected, features, runtime = load_openvm_graph(workspace, toolchain)
    packages, scripts, edges, errors = screen(metadata, workspace, selected)
    errors.extend(openvm_profile_violations(packages, features, runtime))
    host_entropy = [package for package in packages
                    if package["name"] == "getrandom" and package["id"] not in runtime]
    if host_entropy:
        print("openvm-policy: getrandom is host proc-macro/build-time only; sources screened, absent from guest runtime")
    print(f"openvm-policy: {len(packages)} packages on {OPENVM_TARGET}; "
          + ("FAIL" if errors else "PASS pinned sources and verification-only graph"))
    return packages, scripts, edges, errors


def screen_profiles(workspace, toolchain, host_target):
    """Use Cargo's package-selected trees to avoid workspace feature unification.

    Metadata selects the entire workspace. These independent invocations instead
    check consumer-specific normal/build graphs. Dev dependencies stay covered by
    the workspace metadata screen, but are not shipped in a consumer library.
    """
    profiles = [
        ("default", ["-p", "planchet", "--target", host_target], PRIVATE_KEY_PACKAGES),
        ("rpc-http", ["-p", "planchet", "--features", "rpc,http", "--target", host_target], PRIVATE_KEY_PACKAGES),
        ("host-backends", ["-p", "planchet", "--no-default-features", "--features", "openvm",
                           "--target", host_target], {"planchet-signer", "planchet-psbt", "getrandom"}),
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
    violations.extend(screen_openvm(workspace, toolchain)[3])
    return violations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", default="1.91.0")
    parser.add_argument("--target", help="target triple; defaults to the selected rustc host")
    parser.add_argument("--no-default-features", action="store_true",
                        help="screen the minimal workspace graph instead of all features")
    parser.add_argument("--openvm", action="store_true",
                        help="screen the actual zkVM facade openvm,psbt,signer consumer graph")
    parser.add_argument("--check-profiles", action="store_true",
                        help="also screen default/RPC separation, WASM policy, and actual pinned OpenVM graph")
    args = parser.parse_args()
    workspace = Path(__file__).resolve().parents[1]
    version = subprocess.check_output(["rustc", f"+{args.toolchain}", "-vV"], text=True)
    host_target = next(line.split(": ", 1)[1] for line in version.splitlines() if line.startswith("host: "))
    if args.openvm:
        if args.target is not None and args.target != OPENVM_TARGET:
            parser.error(f"--openvm requires --target {OPENVM_TARGET} (or omit --target)")
        if args.no_default_features:
            parser.error("--openvm already selects no defaults and its supported feature set")
        args.target = OPENVM_TARGET
        packages, scripts, edges, violations = screen_openvm(workspace, args.toolchain)
    else:
        args.target = args.target or host_target
        command = ["cargo", f"+{args.toolchain}", "metadata", "--locked", "--format-version", "1",
                   "--filter-platform", args.target,
                   "--no-default-features" if args.no_default_features else "--all-features"]
        print("Running:", " ".join(command), flush=True)
        metadata = json.loads(subprocess.check_output(command, cwd=workspace, text=True))
        if metadata.get("resolve") is None:
            raise ValueError("cargo metadata returned no resolved graph")
        packages, scripts, edges, violations = screen(metadata, workspace)
    violations.extend(check_openvm_lock(workspace))
    if args.check_profiles:
        violations.extend(screen_profiles(workspace, args.toolchain, host_target))
    print(f"Screened {len(packages)} resolved packages on {args.target} (normal/dev/build).")
    print("Build dependencies: " + (", ".join(sorted(edges)) or "none"))
    runtime = [package for package in packages if package["name"] == "openvm" and approved_openvm(package)]
    if runtime:
        print("VM runtime exception: pinned, byte-checked RISC-V memcpy/memset assembly; no C/native crypto exception.")
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
