#!/usr/bin/env python3
"""
scripts/secret_rotation.py

Automatically rotates any secret that was "touched" by a deployment diff —
i.e. a config file, env-var reference, or Vault path mentioned in the changed
files — so that a compromised or reviewed secret doesn't sit unrotated.

Usage:
    python scripts/secret_rotation.py --diff-base origin/main --vault-addr http://localhost:8200
    python scripts/secret_rotation.py --demo     # runs against a mocked Vault client, no network needed
"""
import argparse
import json
import os
import re
import secrets
import string
import subprocess
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

SECRET_PATH_HINT_RE = re.compile(
    r"(secret/data/[\w/\-]+)|(vault:.*path=([\w/\-]+))", re.IGNORECASE
)
ENV_SECRET_NAME_RE = re.compile(
    r"\b([A-Z0-9_]*(SECRET|TOKEN|PASSWORD|API_KEY|CREDENTIAL|PRIVATE_KEY)[A-Z0-9_]*)\b"
)


@dataclass
class RotationEvent:
    secret_path: str
    rotated_at: str
    triggered_by_file: str
    rotation_id: str
    status: str


def get_changed_files(diff_base: str) -> list[str]:
    try:
        out = subprocess.run(
            ["git", "diff", "--name-only", diff_base, "HEAD"],
            capture_output=True, text=True, check=True,
        )
        return [f for f in out.stdout.splitlines() if f.strip()]
    except subprocess.CalledProcessError:
        return []


def find_touched_secret_paths(changed_files: list[str]) -> dict[str, str]:
    """Return {secret_path: triggering_file} for every secret reference found
    in the changed files (manifests, config, workflow files)."""
    touched = {}
    for f in changed_files:
        if not os.path.exists(f):
            continue
        if os.path.getsize(f) > 2_000_000:  # skip huge files
            continue
        try:
            with open(f, "r", errors="ignore") as fh:
                content = fh.read()
        except OSError:
            continue

        for m in SECRET_PATH_HINT_RE.finditer(content):
            path = m.group(1) or m.group(3)
            if path:
                touched[path] = f

        for m in ENV_SECRET_NAME_RE.finditer(content):
            # Map bare env-var secret names to a conventional Vault path
            inferred_path = f"secret/data/app/{m.group(1).lower()}"
            touched.setdefault(inferred_path, f)

    return touched


def generate_strong_secret(length: int = 40) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))


class VaultClient:
    """Thin wrapper around the Vault HTTP API (KV v2)."""

    def __init__(self, addr: str, token: str):
        self.addr = addr.rstrip("/")
        self.token = token

    def rotate(self, secret_path: str) -> str:
        import urllib.request

        new_value = generate_strong_secret()
        # KV v2 write path convention: secret/data/<path> -> API path v1/secret/data/<path>
        url = f"{self.addr}/v1/{secret_path}"
        payload = json.dumps({"data": {"value": new_value, "rotated_at": now_iso()}}).encode()
        req = urllib.request.Request(
            url, data=payload, method="POST",
            headers={"X-Vault-Token": self.token, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status not in (200, 204):
                raise RuntimeError(f"Vault rotation failed for {secret_path}: HTTP {resp.status}")
        return new_value


class MockVaultClient:
    """No-network mock used for --demo mode / local testing without a Vault server."""

    def rotate(self, secret_path: str) -> str:
        return generate_strong_secret()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def rotate_all(client, touched: dict[str, str]) -> list[RotationEvent]:
    events = []
    for path, trigger_file in touched.items():
        rotation_id = secrets.token_hex(6)
        try:
            client.rotate(path)
            status = "success"
        except Exception as e:  # noqa: BLE001
            status = f"failed: {e}"
        events.append(RotationEvent(
            secret_path=path,
            rotated_at=now_iso(),
            triggered_by_file=trigger_file,
            rotation_id=rotation_id,
            status=status,
        ))
    return events


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--diff-base", default="origin/main")
    ap.add_argument("--vault-addr", default=os.environ.get("VAULT_ADDR", "http://localhost:8200"))
    ap.add_argument("--vault-token", default=os.environ.get("VAULT_TOKEN", ""))
    ap.add_argument("--demo", action="store_true", help="Run with a mocked Vault client")
    ap.add_argument("--out", default="/tmp/rotation_events.json")
    args = ap.parse_args()

    if args.demo:
        changed_files = ["k8s/deployment.yaml", "dashboard/app.py"]
        touched = {
            "secret/data/prod/db": "k8s/deployment.yaml",
            "secret/data/app/api_token": "dashboard/app.py",
        }
        client = MockVaultClient()
    else:
        changed_files = get_changed_files(args.diff_base)
        touched = find_touched_secret_paths(changed_files)
        if not touched:
            print("No secret references touched by this diff. Nothing to rotate.")
            return
        client = VaultClient(args.vault_addr, args.vault_token)

    events = rotate_all(client, touched)

    with open(args.out, "w") as f:
        json.dump([asdict(e) for e in events], f, indent=2)

    print(f"Rotated {len(events)} secret(s):")
    for e in events:
        print(f"  - {e.secret_path}  [{e.status}]  (triggered by {e.triggered_by_file})")

    if any("failed" in e.status for e in events):
        sys.exit(1)


if __name__ == "__main__":
    main()
