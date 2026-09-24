"""
tests/test_additional_ml_components.py

Smoke tests for the three ML components added to make the project's AI/ML
content genuine rather than nominal: NER-based PII detection, real SHAP
explainability, and the commit-message risk classifier. These are basic
functional tests (does it run, does it produce well-formed output, does it
satisfy its own mathematical invariants) — NOT claims of real-world
accuracy. See docs/ARCHITECTURE.md for the honest limitations of each,
especially the commit-message classifier's documented generalization
failure on paraphrased input.

Run with: pytest tests/test_additional_ml_components.py -v
"""
import os
import sys

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "ml", "risk_predictor"))
sys.path.insert(0, os.path.join(ROOT, "scanner"))


class TestNERPIIDetector:
    def test_detects_person_name_in_code_fixture(self):
        spacy = pytest.importorskip("spacy")
        from ner_pii_detector import scan_file, get_model
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("test_customer_name = 'Rohan Malhotra'\nMAX_RETRIES = 3\n")
            path = f.name

        try:
            nlp = get_model()
            findings = scan_file(path, nlp)
            assert any(fnd.entity_type == "PERSON" for fnd in findings), \
                "expected at least one PERSON entity to be detected"
        finally:
            os.unlink(path)

    def test_redaction_never_leaks_full_value(self):
        from ner_pii_detector import redact
        original = "Rohan Malhotra"
        red = redact(original)
        assert red != original
        assert len(red) == len(original)


class TestSHAPExplainability:
    def test_shap_additivity_holds(self):
        pytest.importorskip("shap")
        from explain_shap import explain
        model_path = os.path.join(ROOT, "ml", "risk_predictor", "model.joblib")
        if not os.path.exists(model_path):
            pytest.skip("model.joblib not trained in this environment")

        features = {
            "lines_changed": 200, "files_changed": 10, "new_env_vars": 1,
            "secret_like_env_vars": 1, "config_files_touched": 2, "new_public_endpoints": 0,
            "pii_field_count": 2, "pii_fields_unencrypted": 1, "has_audit_logging": 1,
            "service_incident_history": 1, "base_image_age_days": 60, "reviewer_count": 1,
            "is_friday_or_weekend": 0, "touches_auth_module": 0,
        }
        result = explain(features, model_path)
        # explain() itself asserts additivity internally; a successful return
        # without an AssertionError IS the test. Also sanity-check the shape.
        assert result["additivity_check_passed"] is True
        assert 0 <= result["risk_score"] <= 100
        assert len(result["top_factors"]) > 0
        assert all("shap_value" in f for f in result["top_factors"])

    def test_shap_values_are_signed_not_just_magnitudes(self):
        """A real SHAP explanation must be able to say a feature DECREASED
        risk, not just rank importance — this distinguishes it from the
        earlier importance-weighted approximation, which was magnitude-only."""
        pytest.importorskip("shap")
        from explain_shap import explain
        model_path = os.path.join(ROOT, "ml", "risk_predictor", "model.joblib")
        if not os.path.exists(model_path):
            pytest.skip("model.joblib not trained in this environment")

        low_risk_features = {
            "lines_changed": 5, "files_changed": 1, "new_env_vars": 0,
            "secret_like_env_vars": 0, "config_files_touched": 0, "new_public_endpoints": 0,
            "pii_field_count": 0, "pii_fields_unencrypted": 0, "has_audit_logging": 1,
            "service_incident_history": 0, "base_image_age_days": 1, "reviewer_count": 5,
            "is_friday_or_weekend": 0, "touches_auth_module": 0,
        }
        result = explain(low_risk_features, model_path)
        signs = [f["shap_value"] for f in result["top_factors"]]
        assert any(s < 0 for s in signs), "expected at least one risk-decreasing (negative) SHAP value for a low-risk case"


class TestCommitMessageClassifier:
    def test_trains_and_predicts_without_error(self, tmp_path):
        from commit_message_classifier import train, predict
        model_path = str(tmp_path / "test_commit_clf.joblib")
        metrics = train(n_per_class=100, out_path=model_path)
        assert 0 <= metrics["accuracy"] <= 1
        assert os.path.exists(model_path)

        result = predict("quick fix bypassing validation for now", model_path)
        assert result["predicted_label"] in ("safe", "risky")
        assert 0 <= result["risky_probability"] <= 1

    def test_documented_generalization_limitation_is_real(self, tmp_path):
        """This test intentionally asserts the KNOWN FAILURE MODE, not a
        success — it exists so that if a future retrain accidentally fixes
        this (e.g., by enlarging the synthetic phrase bank), the test
        breaks and forces the docs/ARCHITECTURE.md disclosure to be
        revisited rather than silently going stale."""
        from commit_message_classifier import train, predict
        model_path = str(tmp_path / "test_commit_clf2.joblib")
        train(n_per_class=400, out_path=model_path)

        # A message describing REVERTING a risky hack — bag-of-words with
        # no negation handling is expected to misfire on "temporary".
        result = predict(
            "reverting the temporary hack from last week now that proper fix is tested",
            model_path,
        )
        assert result["predicted_label"] == "risky", (
            "If this now correctly predicts 'safe', the documented "
            "generalization limitation in docs/ARCHITECTURE.md is stale "
            "and should be updated to reflect the improvement."
        )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
