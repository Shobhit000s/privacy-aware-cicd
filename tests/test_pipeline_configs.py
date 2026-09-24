"""
tests/test_pipeline_configs.py

Validates the pipeline's own configuration artifacts — not application code,
but the policy/scanner/workflow definitions themselves. These catch the
"the pipeline is broken, not the app" class of failure: a typo in Rego that
makes a policy silently never fire, invalid YAML that fails at the very
first `actions/checkout`, malformed TOML that makes gitleaks fall back to
defaults silently.

Requires the `opa` CLI on PATH (download via the standard install script);
skips OPA-dependent tests gracefully if it isn't available so this file
still runs the config-validity checks on any machine.

Run with: pytest tests/test_pipeline_configs.py -v
"""
import json
import os
import shutil
import subprocess

import pytest
import yaml

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")
OPA_BIN = shutil.which("opa") or "/tmp/opa"
HAS_OPA = os.path.exists(OPA_BIN) and os.access(OPA_BIN, os.X_OK)


def opa_eval(input_doc: dict) -> list:
    proc = subprocess.run(
        [OPA_BIN, "eval",
         "--data", os.path.join(REPO_ROOT, "policies/opa/privacy_policy.rego"),
         "--data", os.path.join(REPO_ROOT, "policies/opa/deployment_policy.rego"),
         "--input", "/dev/stdin",
         "data.privacy.deny", "--format", "json"],
        input=json.dumps(input_doc), capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    return result["result"][0]["expressions"][0]["value"]


def base_compliant_input() -> dict:
    import time
    return {
        "environment": "production",
        "ml_risk_score": 10,
        "risk_threshold": 70,
        "approved_registries": ["ghcr.io/myorg/"],
        "deployment": {
            "image": "ghcr.io/myorg/app:abc123",
            "env": [],
            "securityContext": {"runAsNonRoot": True},
            "containerSecurityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True},
            "resources": {"limits": {"cpu": "500m", "memory": "256Mi"}},
            "ingress": {"public": False, "waf_enabled": False},
            "data_residency": {"source_region": "eu", "destination_region": "eu", "compliance_approved": True},
        },
        "data_schema": {"fields": []},
        "service": {"audit_logging_enabled": True, "logs_raw_request_body": False},
        "scan_results": {
            "trivy": {"scanned_at_unix": int(time.time()), "critical_count": 0},
            "gitleaks": {"findings_count": 0},
        },
    }


@pytest.mark.skipif(not HAS_OPA, reason="opa CLI not found on PATH or /tmp/opa")
class TestOpaPolicySanity:
    def test_compliant_input_has_no_denials(self):
        assert opa_eval(base_compliant_input()) == []

    def test_plaintext_secret_env_var_is_denied(self):
        doc = base_compliant_input()
        doc["deployment"]["env"].append({"name": "DB_PASSWORD", "value": "hunter2"})
        denials = opa_eval(doc)
        assert any("plaintext" in d for d in denials)

    def test_unapproved_registry_is_denied(self):
        doc = base_compliant_input()
        doc["deployment"]["image"] = "docker.io/randomuser/app:latest"
        denials = opa_eval(doc)
        assert any("not from an approved registry" in d for d in denials)

    def test_high_ml_risk_score_is_denied_in_production(self):
        doc = base_compliant_input()
        doc["ml_risk_score"] = 95
        denials = opa_eval(doc)
        assert any("exceeds threshold" in d for d in denials)

    def test_stale_trivy_scan_is_denied(self):
        doc = base_compliant_input()
        doc["scan_results"]["trivy"]["scanned_at_unix"] -= 100000  # >24h old
        denials = opa_eval(doc)
        assert any("stale" in d for d in denials)

    def test_unencrypted_pii_field_is_denied(self):
        doc = base_compliant_input()
        doc["data_schema"]["fields"].append({"name": "user_email", "encrypted": False})
        denials = opa_eval(doc)
        assert any("PII" in d for d in denials)

    def test_missing_resource_limits_denied(self):
        doc = base_compliant_input()
        del doc["deployment"]["resources"]["limits"]["memory"]
        denials = opa_eval(doc)
        assert any("memory limit" in d for d in denials)


class TestGitleaksConfigValidity:
    def test_toml_parses(self):
        path = os.path.join(REPO_ROOT, "gitleaks/.gitleaks.toml")
        with open(path, "rb") as f:
            config = tomllib.load(f)
        assert "rules" in config
        assert len(config["rules"]) >= 5

    def test_every_rule_has_id_and_regex(self):
        path = os.path.join(REPO_ROOT, "gitleaks/.gitleaks.toml")
        with open(path, "rb") as f:
            config = tomllib.load(f)
        for rule in config["rules"]:
            assert "id" in rule and "regex" in rule, f"malformed rule: {rule}"

    def test_regexes_compile(self):
        import re
        path = os.path.join(REPO_ROOT, "gitleaks/.gitleaks.toml")
        with open(path, "rb") as f:
            config = tomllib.load(f)
        for rule in config["rules"]:
            re.compile(rule["regex"])  # raises re.error if malformed


class TestWorkflowYamlValidity:
    def test_github_actions_workflow_is_valid_yaml(self):
        path = os.path.join(REPO_ROOT, ".github/workflows/pipeline.yml")
        with open(path) as f:
            doc = yaml.safe_load(f)
        assert "jobs" in doc
        expected_jobs = {"secret-scan", "vuln-scan", "policy-check", "risk-prediction",
                          "secret-rotation", "deploy", "audit"}
        assert expected_jobs.issubset(doc["jobs"].keys())

    def test_every_job_after_secret_scan_has_a_needs_chain(self):
        path = os.path.join(REPO_ROOT, ".github/workflows/pipeline.yml")
        with open(path) as f:
            doc = yaml.safe_load(f)
        # every job except secret-scan itself should declare `needs`, so a
        # future edit can't accidentally let a stage run in parallel with
        # (and thus not actually gate) an earlier one
        for name, job in doc["jobs"].items():
            if name == "secret-scan":
                continue
            assert "needs" in job, f"job '{name}' has no 'needs' — pipeline ordering may be unenforced"


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
