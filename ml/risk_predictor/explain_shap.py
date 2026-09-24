#!/usr/bin/env python3
"""
ml/risk_predictor/explain_shap.py

Exact, game-theoretically-grounded feature attribution for the risk model's
predictions, using SHAP (SHapley Additive exPlanations — Lundberg & Lee,
2017). This replaces the earlier importance-weighted approximation in
predict_risk.py, which docs/ARCHITECTURE.md and the accompanying paper
explicitly flagged as a disclosed limitation ("adequate for surfacing the
general direction of risk drivers but should not be treated as a precise
causal attribution"). This module is that flagged future work, implemented.

TreeExplainer is used specifically because the underlying model
(GradientBoostingRegressor) is a tree ensemble — TreeExplainer computes
exact Shapley values for tree models in polynomial time, rather than the
exponential-time exact computation (or sampling-based approximation)
required for arbitrary black-box models.

Usage:
    python ml/risk_predictor/explain_shap.py --features /tmp/features.json
    python ml/risk_predictor/explain_shap.py --features /tmp/features.json --json
"""
import argparse
import json
import os
import sys

import numpy as np
import pandas as pd
import joblib

sys.path.insert(0, os.path.dirname(__file__))
from features import FEATURE_NAMES  # noqa: E402
from predict_risk import HUMAN_READABLE, recommendation_for  # noqa: E402

MODEL_PATH_DEFAULT = os.path.join(os.path.dirname(__file__), "model.joblib")


def explain(features: dict, model_path: str = MODEL_PATH_DEFAULT) -> dict:
    import shap  # local import: keep this an optional, clearly-flagged dependency

    if not os.path.exists(model_path):
        raise FileNotFoundError(f"No trained model found at {model_path}. Run train_model.py first.")

    bundle = joblib.load(model_path)
    model, feature_names = bundle["model"], bundle["feature_names"]

    x_df = pd.DataFrame([[features.get(f, 0) for f in feature_names]], columns=feature_names)
    raw_score = float(model.predict(x_df)[0])
    score = float(np.clip(raw_score, 0, 100))

    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(x_df)[0]  # exact Shapley value per feature for this prediction
    expected_value = explainer.expected_value
    base_value = float(np.ravel(expected_value)[0])  # some shap/sklearn version combos return a length-1 array

    contributions = []
    for name, val, shap_val in zip(feature_names, x_df.iloc[0].values, shap_values):
        contributions.append({
            "feature": name,
            "label": HUMAN_READABLE.get(name, name),
            "value": float(val),
            "shap_value": float(shap_val),  # signed: positive = pushed risk UP, negative = pushed risk DOWN
        })
    # Sort by absolute contribution magnitude — the features that moved the
    # prediction furthest from the base value, in either direction.
    contributions.sort(key=lambda c: -abs(c["shap_value"]))

    # Sanity check that is intrinsic to SHAP's definition, not a heuristic:
    # base_value + sum(shap_values) must reconstruct the raw model output.
    reconstruction = base_value + sum(c["shap_value"] for c in contributions)
    assert abs(reconstruction - raw_score) < 1e-4, (
        f"SHAP additivity check failed: {reconstruction} != {raw_score} "
        "(indicates a version mismatch between shap and scikit-learn's tree API)"
    )

    risk_level = (
        "LOW" if score < 30 else "MEDIUM" if score < 60 else "HIGH" if score < 80 else "CRITICAL"
    )

    return {
        "risk_score": round(score, 1),
        "risk_level": risk_level,
        "base_value": round(base_value, 2),
        "top_factors": contributions[:6],
        "additivity_check_passed": True,
        "recommendation": recommendation_for(risk_level),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", required=True)
    ap.add_argument("--model", default=MODEL_PATH_DEFAULT)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    with open(args.features) as f:
        features = json.load(f)

    try:
        result = explain(features, args.model)
    except ImportError:
        print("shap is not installed. Install with: pip install shap", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    print(f"Privacy Risk Score: {result['risk_score']} / 100  [{result['risk_level']}]")
    print(f"Model base rate (average prediction across training data): {result['base_value']}")
    print(f"Recommendation: {result['recommendation']}\n")
    print("Exact SHAP contributions (base_value + sum(shap_values) = prediction):")
    for f in result["top_factors"]:
        direction = "increases" if f["shap_value"] > 0 else "decreases"
        print(f"  {f['label']:38s} value={f['value']:<8g} {direction} risk by {abs(f['shap_value']):.2f} points")


if __name__ == "__main__":
    main()
