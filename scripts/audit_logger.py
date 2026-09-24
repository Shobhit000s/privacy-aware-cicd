#!/usr/bin/env python3
"""
scripts/audit_logger.py

Writes a structured, tamper-evident audit event for every pipeline run and
(optionally) pushes a summary metric to a Prometheus Pushgateway so Grafana's
compliance dashboard stays current in near real-time.

Each event is hash-chained to the previous one (like a mini append-only
ledger) so the audit log can't be silently edited after the fact.

Usage:
    python scripts/audit_logger.py --demo
    python scripts/audit_logger.py --run-id 12345 --commit abc123 --actor jdoe \
        --risk-score 42 --status success --push-metrics http://pushgateway:9091
"""
import argparse
import hashlib
import json
import os
import urllib.request
from datetime import datetime, timezone

AUDIT_LOG_PATH = os.environ.get("AUDIT_LOG_PATH", "audit_log.jsonl")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def last_event_hash(log_path: str) -> str:
    if not os.path.exists(log_path):
        return "0" * 64  # genesis
    last_line = None
    with open(log_path, "r") as f:
        for line in f:
            if line.strip():
                last_line = line
    if last_line is None:
        return "0" * 64
    return json.loads(last_line)["event_hash"]


def build_event(run_id, commit, actor, risk_score, status, prev_hash) -> dict:
    body = {
        "run_id": run_id,
        "commit": commit,
        "actor": actor,
        "risk_score": risk_score,
        "status": status,
        "timestamp": now_iso(),
        "prev_hash": prev_hash,
    }
    digest_input = json.dumps(body, sort_keys=True).encode()
    body["event_hash"] = hashlib.sha256(digest_input).hexdigest()
    return body


def append_event(event: dict, log_path: str = AUDIT_LOG_PATH):
    with open(log_path, "a") as f:
        f.write(json.dumps(event) + "\n")


def verify_chain(log_path: str = AUDIT_LOG_PATH) -> bool:
    """Re-walk the chain and confirm no event has been tampered with."""
    prev = "0" * 64
    if not os.path.exists(log_path):
        return True
    with open(log_path, "r") as f:
        for line in f:
            if not line.strip():
                continue
            event = json.loads(line)
            claimed_hash = event.pop("event_hash")
            recomputed = hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()
            if recomputed != claimed_hash or event["prev_hash"] != prev:
                return False
            prev = claimed_hash
    return True


def compute_security_score(risk_score: float | None, status: str) -> int:
    """Simple 0-100 'security score' for the dashboard: inverse of risk,
    penalized further if the run failed outright."""
    base = 100 - (risk_score if risk_score is not None else 0)
    if status not in ("success", "completed"):
        base -= 20
    return max(0, min(100, round(base)))


def push_to_prometheus(pushgateway_url: str, job: str, metrics: dict):
    body_lines = []
    for name, value in metrics.items():
        body_lines.append(f"{name} {value}")
    payload = ("\n".join(body_lines) + "\n").encode()
    url = f"{pushgateway_url.rstrip('/')}/metrics/job/{job}"
    req = urllib.request.Request(url, data=payload, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status in (200, 202)
    except Exception as e:  # noqa: BLE001
        print(f"[warn] could not push metrics to pushgateway: {e}")
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", default="demo-run")
    ap.add_argument("--commit", default="0000000")
    ap.add_argument("--actor", default="local-user")
    ap.add_argument("--risk-score", type=float, default=None)
    ap.add_argument("--status", default="success")
    ap.add_argument("--push-metrics", default="")
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--verify", action="store_true", help="Verify audit log integrity and exit")
    args = ap.parse_args()

    if args.verify:
        ok = verify_chain()
        print("Audit log integrity: OK" if ok else "Audit log integrity: TAMPERED / BROKEN CHAIN")
        return

    if args.demo:
        args.run_id, args.commit, args.actor = "demo-run-001", "a1b2c3d", "demo-user"
        args.risk_score, args.status = 34.5, "success"

    prev_hash = last_event_hash(AUDIT_LOG_PATH)
    event = build_event(args.run_id, args.commit, args.actor, args.risk_score, args.status, prev_hash)
    append_event(event)

    security_score = compute_security_score(args.risk_score, args.status)
    event["security_score"] = security_score

    print(json.dumps(event, indent=2))
    print(f"\nChain integrity check: {'OK' if verify_chain() else 'BROKEN'}")

    if args.push_metrics:
        push_to_prometheus(
            args.push_metrics,
            job="privacy_cicd_audit",
            metrics={
                "pipeline_risk_score": args.risk_score or 0,
                "pipeline_security_score": security_score,
                "pipeline_run_status": 1 if args.status == "success" else 0,
            },
        )


if __name__ == "__main__":
    main()
