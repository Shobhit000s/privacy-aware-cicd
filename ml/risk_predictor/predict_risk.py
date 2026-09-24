#!/usr/bin/env python3
"""
ml/risk_predictor/predict_risk.py

Loads the trained model and scores a single deployment's feature vector,
returning a 0-100 privacy-risk score plus a plain-language explanation of
the top contributing factors (via per-feature contribution, computed as
feature_importance * standardized_feature_value — a cheap, dependency-free
approximation of a Shapley-style explanation).

Usage:
    python ml/risk_predictor/predict_risk.py --features /tmp/features.json
    python ml/risk_predictor/predict_risk.py --features /tmp/features.json --json
"""
import argparse
import json
import os
import sys

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))
from features import FEATURE_NAMES  # noqa: E402

MODEL_PATH_DEFAULT = os.path.join(os.path.dirname(__file__), "model.joblib")

HUMAN_READABLE = {
    "lines_changed": "size of the diff",
    "files_changed": "breadth of files touched",
    "new_env_vars": "new environment variables introduced",
    "secret_like_env_vars": "secret-shaped environment variables",
    "config_files_touched": "config/manifest files touched",
    "new_public_endpoints": "new publicly-exposed endpoints",
    "pii_field_count": "PII-shaped data fields touched",
    "pii_fields_unencrypted": "PII fields without encryption",
    "has_audit_logging": "audit logging enabled",
    "service_incident_history": "service's recent incident history",
    "base_image_age_days": "age of the base container image",
    "reviewer_count": "number of PR reviewers",
    "is_friday_or_weekend": "deploy timing (Fri/weekend)",
    "touches_auth_module": "touches authentication/authorization code",
}


def load_model(path: str):
    bundle = joblib.load(path)
    return bundle["model"], bundle["feature_names"]


def predict(features: dict, model_path: str = MODEL_PATH_DEFAULT) -> dict:
    if not os.path.exists(model_path):
        raise FileNotFoundError(
            f"No trained model found at {model_path}. Run train_model.py first."
        )
    model, feature_names = load_model(model_path)

    x_df = pd.DataFrame([[features.get(f, 0) for f in feature_names]], columns=feature_names)
    raw_score = float(model.predict(x_df)[0])
    score = float(np.clip(raw_score, 0, 100))
    x = x_df.to_numpy()

    # Cheap per-prediction explanation: importance-weighted, sign-aware
    # contribution using each feature's deviation from the training mean of
    # ~half its typical range (a simple, dependency-free stand-in for SHAP).
    importances = model.feature_importances_
    contributions = []
    for name, imp, val in zip(feature_names, importances, x[0]):
        contributions.append({
            "feature": name,
            "label": HUMAN_READABLE.get(name, name),
            "value": float(val),
            "importance": float(imp),
            "contribution": float(imp * (val if "has_audit_logging" != name else (1 - val))),
        })
    contributions.sort(key=lambda c: -c["contribution"])
    top_factors = [c for c in contributions if c["contribution"] > 0][:5]

    risk_level = (
        "LOW" if score < 30 else
        "MEDIUM" if score < 60 else
        "HIGH" if score < 80 else
        "CRITICAL"
    )

    return {
        "risk_score": round(score, 1),
        "risk_level": risk_level,
        "top_factors": top_factors,
        "recommendation": recommendation_for(risk_level),
    }


def recommendation_for(level: str) -> str:
    return {
        "LOW": "Safe to proceed. Continue routine monitoring.",
        "MEDIUM": "Proceed with caution — consider an extra reviewer or "
                   "encrypting flagged PII fields before deploying.",
        "HIGH": "Recommend blocking auto-deploy; require manual privacy "
                "review and remediation of flagged factors.",
        "CRITICAL": "Block deployment. Escalate to security/privacy team "
                    "before this change ships.",
    }[level]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", required=True, help="Path to a JSON feature vector")
    ap.add_argument("--model", default=MODEL_PATH_DEFAULT)
    ap.add_argument("--json", action="store_true", help="Print raw JSON only")
    args = ap.parse_args()

    with open(args.features) as f:
        features = json.load(f)

    result = predict(features, args.model)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    print(f"Privacy Risk Score: {result['risk_score']} / 100  [{result['risk_level']}]")
    print(f"Recommendation: {result['recommendation']}\n")
    print("Top contributing factors:")
    for f in result["top_factors"]:
        print(f"  - {f['label']} (value={f['value']:g})")


if __name__ == "__main__":
    main()
