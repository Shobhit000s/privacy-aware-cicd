#!/usr/bin/env python3
"""
ml/risk_predictor/train_model.py

Trains a gradient-boosted regressor that maps deployment features -> a 0-100
privacy-risk score. Ships with a synthetic dataset generator so the model is
trainable and demoable without any real (and therefore sensitive) deployment
history. The generator encodes domain knowledge about what actually drives
privacy risk (see docstring of `synthetic_risk_score` below) plus noise, so
the model has real signal to learn rather than being pure random-label mush.

In production: replace `generate_synthetic_dataset()` with a loader that
pulls labeled historical deployments (features + an outcome label such as
"caused a privacy incident within 30 days: yes/no", or a manually-assigned
audit risk score) from your audit log / incident tracker.

Usage:
    python ml/risk_predictor/train_model.py
    python ml/risk_predictor/train_model.py --n-samples 5000 --out ml/risk_predictor/model.joblib
"""
import argparse
import os
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_absolute_error, r2_score
import joblib

sys.path.insert(0, os.path.dirname(__file__))
from features import FEATURE_NAMES  # noqa: E402

MODEL_PATH_DEFAULT = os.path.join(os.path.dirname(__file__), "model.joblib")
DATA_PATH_DEFAULT = os.path.join(os.path.dirname(__file__), "data", "synthetic_training_data.csv")


def synthetic_risk_score(row: dict, rng: np.random.Generator) -> float:
    """
    Domain-informed ground-truth risk function used only to LABEL synthetic
    training examples. Encodes: bigger/broader diffs, more secret-shaped env
    vars, more unencrypted PII, missing audit logging, stale base images,
    fewer reviewers, deploys touching auth, and Friday/weekend deploys all
    push risk up. Score is clipped to [0, 100] with Gaussian noise added so
    the learned model has to generalize rather than memorize a formula.
    """
    score = 0.0
    score += min(row["lines_changed"] / 20, 15)
    score += min(row["files_changed"] / 3, 8)
    score += row["new_env_vars"] * 2
    score += row["secret_like_env_vars"] * 9
    score += row["config_files_touched"] * 1.5
    score += row["new_public_endpoints"] * 8
    score += row["pii_field_count"] * 4
    score += row["pii_fields_unencrypted"] * 10
    score -= row["has_audit_logging"] * 8
    score += row["service_incident_history"] * 5
    score += min(row["base_image_age_days"] / 15, 12)
    score -= row["reviewer_count"] * 4
    score += row["is_friday_or_weekend"] * 5
    score += row["touches_auth_module"] * 7

    score += rng.normal(0, 6)  # measurement/label noise
    return float(np.clip(score, 0, 100))


def generate_synthetic_dataset(n_samples: int, seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    for _ in range(n_samples):
        row = {
            "lines_changed": int(rng.exponential(80)),
            "files_changed": int(rng.exponential(6)) + 1,
            "new_env_vars": int(rng.poisson(0.8)),
            "secret_like_env_vars": int(rng.poisson(0.3)),
            "config_files_touched": int(rng.poisson(1.2)),
            "new_public_endpoints": int(rng.poisson(0.2)),
            "pii_field_count": int(rng.poisson(1.0)),
            "pii_fields_unencrypted": int(rng.poisson(0.4)),
            "has_audit_logging": int(rng.random() < 0.6),
            "service_incident_history": int(rng.poisson(0.8)),
            "base_image_age_days": int(rng.exponential(60)),
            "reviewer_count": int(rng.poisson(1.3)),
            "is_friday_or_weekend": int(rng.random() < 0.25),
            "touches_auth_module": int(rng.random() < 0.15),
        }
        row["risk_score"] = synthetic_risk_score(row, rng)
        rows.append(row)
    return pd.DataFrame(rows)[FEATURE_NAMES + ["risk_score"]]


def train(n_samples: int, out_path: str, data_path: str) -> dict:
    df = generate_synthetic_dataset(n_samples)
    os.makedirs(os.path.dirname(data_path), exist_ok=True)
    df.to_csv(data_path, index=False)

    X = df[FEATURE_NAMES]
    y = df["risk_score"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = GradientBoostingRegressor(
        n_estimators=200, max_depth=3, learning_rate=0.05, random_state=42
    )
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    mae = mean_absolute_error(y_test, preds)
    r2 = r2_score(y_test, preds)

    joblib.dump({"model": model, "feature_names": FEATURE_NAMES}, out_path)

    importances = dict(zip(FEATURE_NAMES, model.feature_importances_.round(4)))
    return {"mae": mae, "r2": r2, "n_samples": n_samples, "importances": importances}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-samples", type=int, default=3000)
    ap.add_argument("--out", default=MODEL_PATH_DEFAULT)
    ap.add_argument("--data-out", default=DATA_PATH_DEFAULT)
    args = ap.parse_args()

    metrics = train(args.n_samples, args.out, args.data_out)

    print(f"Trained on {metrics['n_samples']} synthetic samples")
    print(f"Test MAE:  {metrics['mae']:.2f} (risk points, 0-100 scale)")
    print(f"Test R^2:  {metrics['r2']:.3f}")
    print(f"\nModel saved to: {args.out}")
    print(f"Training data saved to: {args.data_out}")
    print("\nTop feature importances:")
    for name, imp in sorted(metrics["importances"].items(), key=lambda x: -x[1])[:8]:
        print(f"  {name:28s} {imp:.4f}")


if __name__ == "__main__":
    main()
