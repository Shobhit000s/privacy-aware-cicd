#!/usr/bin/env python3
"""
ml/risk_predictor/features.py

Extracts a structured feature vector describing a deployment/diff, used as
input to the risk-prediction model. In CI this inspects the actual git diff;
standalone it can generate a synthetic feature vector for demoing.

Feature set (documented rationale in docs/ARCHITECTURE.md):
  - lines_changed            : size of the diff (larger diffs -> harder to review -> more risk)
  - files_changed            : breadth of the diff
  - new_env_vars             : number of new environment variables introduced
  - secret_like_env_vars     : how many of those look secret-shaped
  - config_files_touched     : files under config/ or k8s/ touched
  - new_public_endpoints     : new ingress/route definitions marked public
  - pii_field_count          : fields in touched schemas that look like PII
  - pii_fields_unencrypted   : of those, how many lack an encrypted flag
  - has_audit_logging        : 1 if the touched service enables audit logging
  - service_incident_history : historical incident count for this service (last 90d)
  - base_image_age_days      : age of the base image (older -> more unpatched CVEs)
  - reviewer_count           : number of distinct reviewers/approvers on the PR
  - is_friday_or_weekend     : deploys near/after cutover windows carry more risk
  - touches_auth_module      : 1 if diff touches authn/authz code paths
"""
import argparse
import json
import os
import random
import re
import subprocess
from datetime import datetime

FEATURE_NAMES = [
    "lines_changed",
    "files_changed",
    "new_env_vars",
    "secret_like_env_vars",
    "config_files_touched",
    "new_public_endpoints",
    "pii_field_count",
    "pii_fields_unencrypted",
    "has_audit_logging",
    "service_incident_history",
    "base_image_age_days",
    "reviewer_count",
    "is_friday_or_weekend",
    "touches_auth_module",
]

SECRET_ENV_RE = re.compile(r"(SECRET|TOKEN|PASSWORD|API_KEY|CREDENTIAL|PRIVATE_KEY)", re.IGNORECASE)
PII_FIELD_RE = re.compile(r"(email|ssn|phone|address|dob|passport|credit_card|national_id)", re.IGNORECASE)
AUTH_PATH_RE = re.compile(r"(auth|login|session|token|permission|rbac)", re.IGNORECASE)


def run_git_diff(diff_base: str) -> tuple[list[str], str]:
    try:
        files = subprocess.run(
            ["git", "diff", "--name-only", diff_base, "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.splitlines()
        stat = subprocess.run(
            ["git", "diff", "--shortstat", diff_base, "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout
        full_diff = subprocess.run(
            ["git", "diff", diff_base, "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout
        return [f for f in files if f.strip()], full_diff
    except subprocess.CalledProcessError:
        return [], ""


def extract_from_repo(diff_base: str) -> dict:
    files, full_diff = run_git_diff(diff_base)

    lines_changed = full_diff.count("\n+") + full_diff.count("\n-")
    files_changed = len(files)
    config_files_touched = sum(1 for f in files if f.startswith(("k8s/", "config/", "docker/")))
    new_env_vars = len(re.findall(r"^\+\s*.*name:\s*[\"']?[A-Z0-9_]+[\"']?", full_diff, re.MULTILINE))
    secret_like_env_vars = len(SECRET_ENV_RE.findall(full_diff))
    new_public_endpoints = full_diff.count("public: true") + full_diff.count('"public": true')
    pii_field_count = len(set(PII_FIELD_RE.findall(full_diff)))
    pii_fields_unencrypted = full_diff.count("encrypted: false") + full_diff.count('"encrypted": false')
    has_audit_logging = 1 if "audit_logging_enabled: true" in full_diff or "audit_logging_enabled\": true" in full_diff else 0
    touches_auth_module = 1 if any(AUTH_PATH_RE.search(f) for f in files) else 0

    weekday = datetime.now().weekday()
    is_friday_or_weekend = 1 if weekday >= 4 else 0

    return {
        "lines_changed": lines_changed,
        "files_changed": files_changed,
        "new_env_vars": new_env_vars,
        "secret_like_env_vars": secret_like_env_vars,
        "config_files_touched": config_files_touched,
        "new_public_endpoints": new_public_endpoints,
        "pii_field_count": pii_field_count,
        "pii_fields_unencrypted": pii_fields_unencrypted,
        "has_audit_logging": has_audit_logging,
        # These two would come from a service registry / incident tracker in production;
        # default to conservative middle-of-road values when unavailable.
        "service_incident_history": int(os.environ.get("SERVICE_INCIDENT_HISTORY", 1)),
        "base_image_age_days": int(os.environ.get("BASE_IMAGE_AGE_DAYS", 30)),
        "reviewer_count": int(os.environ.get("PR_REVIEWER_COUNT", 1)),
        "is_friday_or_weekend": is_friday_or_weekend,
        "touches_auth_module": touches_auth_module,
    }


def generate_demo_features(seed: int | None = None) -> dict:
    rng = random.Random(seed)
    return {
        "lines_changed": rng.randint(5, 800),
        "files_changed": rng.randint(1, 40),
        "new_env_vars": rng.randint(0, 6),
        "secret_like_env_vars": rng.randint(0, 3),
        "config_files_touched": rng.randint(0, 8),
        "new_public_endpoints": rng.randint(0, 2),
        "pii_field_count": rng.randint(0, 5),
        "pii_fields_unencrypted": rng.randint(0, 3),
        "has_audit_logging": rng.choice([0, 1]),
        "service_incident_history": rng.randint(0, 5),
        "base_image_age_days": rng.randint(0, 400),
        "reviewer_count": rng.randint(0, 3),
        "is_friday_or_weekend": rng.choice([0, 1]),
        "touches_auth_module": rng.choice([0, 1]),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--diff-base", default="origin/main")
    ap.add_argument("--out", default="/tmp/features.json")
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    if args.demo:
        features = generate_demo_features(args.seed)
    else:
        features = extract_from_repo(args.diff_base)

    with open(args.out, "w") as f:
        json.dump(features, f, indent=2)
    print(f"Wrote feature vector to {args.out}")
    print(json.dumps(features, indent=2))


if __name__ == "__main__":
    main()
