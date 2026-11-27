#!/usr/bin/env python3
"""Run the opt-in wallet contract against a disposable Linux x86_64 Core 1.14.9."""

import hashlib
import os
from pathlib import Path
import platform
import re
import secrets
import signal
import socket
import subprocess
import tempfile


ARCHIVE = "dogecoin-1.14.9-x86_64-linux-gnu.tar.gz"
URL = f"https://github.com/dogecoin/dogecoin/releases/download/v1.14.9/{ARCHIVE}"
# Official v1.14.9 SHA256SUMS.asc; never execute an unverified download.
SHA256 = "4f227117b411a7c98622c970986e27bcfc3f547a72bef65e7d9e82989175d4f8"
TEST = "isolated_regtest_watch_import_read_and_rescan"
WORKSPACE = Path(__file__).resolve().parent.parent


def interrupted(signum, _frame):
    raise SystemExit(128 + signum)


def run(root):
    archive = root / ARCHIVE
    subprocess.run([
        "curl", "--fail", "--location", "--silent", "--show-error",
        "--proto", "=https", "--proto-redir", "=https",
        "--connect-timeout", "15", "--max-time", "120",
        "--output", str(archive), URL,
    ], check=True, timeout=130)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise RuntimeError("Core archive SHA-256 mismatch")
    subprocess.run([
        "tar", "-xzf", str(archive), "-C", str(root),
        "--strip-components=1", "dogecoin-1.14.9/bin/dogecoind",
        "dogecoin-1.14.9/bin/dogecoin-cli",
    ], check=True, timeout=30)

    datadir = root / "data"
    datadir.mkdir()
    user, password = "planchet-ci", secrets.token_hex(32)
    config = root / "dogecoin.conf"
    config.write_text(f"rpcuser={user}\nrpcpassword={password}\n")
    # Explicit absolute config/datadir bypass all user/system node settings.
    config.chmod(0o600)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    endpoint = f"http://127.0.0.1:{port}"
    node_args = [f"-datadir={datadir}", f"-conf={config}", "-regtest", f"-rpcport={port}"]
    log = root / "node.log"
    with log.open("w") as output:
        node = subprocess.Popen([
            str(root / "bin/dogecoind"), *node_args,
            "-server", "-daemon=0", "-printtoconsole", "-disablewallet=0",
            "-listen=0", "-connect=0", "-dnsseed=0", "-discover=0", "-upnp=0",
            "-listenonion=0", "-maxconnections=0", "-prune=0",
            "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
        ], stdout=output, stderr=subprocess.STDOUT)
        try:
            if node.poll() is not None:
                raise RuntimeError("Core exited before readiness (possible port conflict)")
            ready = subprocess.run([
                str(root / "bin/dogecoin-cli"), *node_args,
                "-rpcconnect=127.0.0.1", "-rpcwait", "getblockcount",
            ], check=True, text=True, stdout=subprocess.PIPE, timeout=60)
            # A raced port cannot select another node: only our random auth works,
            # and RPC has exactly one bind address, so a conflict kills our child.
            if node.poll() is not None or ready.stdout.strip() != "0":
                raise RuntimeError("Expected our fresh regtest node at genesis")
            env = os.environ.copy()
            env.update(PLANCHET_WALLET_RPC_URL=endpoint, PLANCHET_WALLET_RPC_USER=user,
                       PLANCHET_WALLET_RPC_PASSWORD=password)
            result = subprocess.run([
                "cargo", "+1.91.0", "test", "--locked", "-p", "planchet-provider",
                "--features", "http", "--test", "wallet", TEST,
                "--", "--exact", "--ignored", "--color", "never",
            ], cwd=WORKSPACE, env=env, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, timeout=600)
            print(result.stdout, end="", flush=True)
            result.check_returncode()
            if (not re.search(rf"^test {TEST} \.\.\. ok$", result.stdout, re.MULTILINE)
                    or not re.search(
                        r"^test result: ok\. 1 passed; 0 failed; 0 ignored; "
                        r"0 measured; \d+ filtered out;", result.stdout, re.MULTILINE)):
                raise RuntimeError("Expected exactly one executed, passing wallet test")
            if node.poll() is not None:
                raise RuntimeError("Core exited during the wallet test")
        except BaseException:
            print(log.read_text(), flush=True)
            raise
        finally:
            # Only the child PID, never RPC stop, process names or existing nodes.
            if node.poll() is None:
                node.terminate()
                try:
                    node.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    node.kill()
            node.wait()


def main():
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("This CI harness requires Linux x86_64")
    os.umask(0o077)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    with tempfile.TemporaryDirectory(prefix="planchet-wallet-", dir=os.getenv("RUNNER_TEMP")) as temp:
        run(Path(temp))


if __name__ == "__main__":
    main()
