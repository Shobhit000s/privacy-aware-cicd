#!/usr/bin/env python3
"""
scripts/build_opa_input.py

Assembles the JSON input document fed to `opa eval` in the pipeline. In a real
deployment this would pull data from the rendered K8s manifest, the Trivy/
Gitleaks JSON reports, and the schema registry. Here it demonstrates the
expected shape and provides sane demo defaults so the policy can be evaluated
standalone.
"""
import argparse
import json
import time


def build_demo_input() -> dict:
    return {
        "environment": "production",
        "ml_risk_score": 42,
        "risk_threshold": 70,
        "approved_registries": ["ghcr.io/myorg/", "myorg.azurecr.io/"],
        "deployment": {
            "image": "ghcr.io/myorg/privacy-aware-app:abc123",
            "env": [
                {"name": "LOG_LEVEL", "value": "info"},
                {"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "db-creds"}}},
            ],
            "securityContext": {"runAsNonRoot": True},
            "containerSecurityContext": {
                "allowPrivilegeEscalation": False,
                "readOnlyRootFilesystem": True,
            },
            "resources": {"limits": {"cpu": "500m", "memory": "256Mi"}},
            "ingress": {"public": True, "waf_enabled": True},
            "data_residency": {
                "source_region": "eu-west-1",
                "destination_region": "eu-west-1",
                "compliance_approved": True,
            },
        },
        "data_schema": {
            "fields": [
                {"name": "user_email", "encrypted": True},
                {"name": "session_id", "encrypted": False},
            ]
        },
        "service": {
            "audit_logging_enabled": True,
            "logs_raw_request_body": False,
        },
        "scan_results": {
            "trivy": {"scanned_at_unix": int(time.time()), "critical_count": 0},
            "gitleaks": {"findings_count": 0},
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/tmp/input.json")
    args = ap.parse_args()

    doc = build_demo_input()
    with open(args.out, "w") as f:
        json.dump(doc, f, indent=2)
    print(f"Wrote OPA input document to {args.out}")


if __name__ == "__main__":
    main()
