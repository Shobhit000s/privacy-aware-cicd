"""
tests/test_pipeline.py

Run with: pytest tests/test_pipeline.py -v
(requires model.joblib to exist — run ml/risk_predictor/train_model.py first)
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ml", "risk_predictor"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import pytest  # noqa: E402


MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "ml", "risk_predictor", "model.joblib")


@pytest.fixture(scope="module")
def trained_model():
    if not os.path.exists(MODEL_PATH):
        from train_model import train
        train(n_samples=500, out_path=MODEL_PATH,
              data_path=os.path.join(os.path.dirname(MODEL_PATH), "data", "synthetic_training_data.csv"))
    return MODEL_PATH


def test_low_risk_scores_lower_than_high_risk(trained_model):
    from predict_risk import predict

    low = {
        "lines_changed": 10, "files_changed": 1, "new_env_vars": 0,
        "secret_like_env_vars": 0, "config_files_touched": 0, "new_public_endpoints": 0,
        "pii_field_count": 0, "pii_fields_unencrypted": 0, "has_audit_logging": 1,
        "service_incident_history": 0, "base_image_age_days": 1, "reviewer_count": 3,
        "is_friday_or_weekend": 0, "touches_auth_module": 0,
    }
    high = dict(low)
    high.update({
        "secret_like_env_vars": 3, "pii_fields_unencrypted": 4, "has_audit_logging": 0,
        "reviewer_count": 0, "base_image_age_days": 300, "touches_auth_module": 1,
        "new_public_endpoints": 2, "pii_field_count": 5, "service_incident_history": 5,
    })

    low_result = predict(low, trained_model)
    high_result = predict(high, trained_model)

    assert low_result["risk_score"] < high_result["risk_score"]
    assert low_result["risk_level"] in ("LOW", "MEDIUM")
    assert high_result["risk_level"] in ("HIGH", "CRITICAL")


def test_risk_score_bounded(trained_model):
    from predict_risk import predict
    extreme = {name: 9999 for name in [
        "lines_changed", "files_changed", "new_env_vars", "secret_like_env_vars",
        "config_files_touched", "new_public_endpoints", "pii_field_count",
        "pii_fields_unencrypted", "has_audit_logging", "service_incident_history",
        "base_image_age_days", "reviewer_count", "is_friday_or_weekend", "touches_auth_module",
    ]}
    result = predict(extreme, trained_model)
    assert 0 <= result["risk_score"] <= 100


def test_audit_log_chain_integrity():
    from audit_logger import build_event, append_event, verify_chain, last_event_hash

    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "audit_log.jsonl")

        prev = last_event_hash(log_path)
        e1 = build_event("run1", "abc123", "alice", 20.0, "success", prev)
        append_event(e1, log_path)

        prev = last_event_hash(log_path)
        e2 = build_event("run2", "def456", "bob", 85.0, "success", prev)
        append_event(e2, log_path)

        assert verify_chain(log_path) is True

        # Tamper with the log and confirm detection
        with open(log_path) as f:
            lines = f.readlines()
        tampered = json.loads(lines[0])
        tampered["risk_score"] = 0.0  # attacker tries to hide a high-risk run
        lines[0] = json.dumps(tampered) + "\n"
        with open(log_path, "w") as f:
            f.writelines(lines)

        assert verify_chain(log_path) is False


def test_secret_rotation_detects_touched_paths():
    from secret_rotation import find_touched_secret_paths

    touched = find_touched_secret_paths(["tests/fixtures/sample_manifest.txt"])
    assert any("secret/data" in p for p in touched)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
