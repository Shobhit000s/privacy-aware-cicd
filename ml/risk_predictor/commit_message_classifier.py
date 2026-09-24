#!/usr/bin/env python3
"""
ml/risk_predictor/commit_message_classifier.py

A second, independent supervised ML model — distinct in both technique and
input modality from the Gradient Boosting regressor in train_model.py. That
model does tabular regression over 14 structural diff features; this one
does TEXT CLASSIFICATION over natural-language commit messages, using
TF-IDF vectorization + Logistic Regression.

Rationale: a deployment's structural features (diff size, reviewer count,
etc.) are one risk signal. The *language a developer used to describe their
own change* is a second, largely independent signal — commit messages
containing language like "quick fix", "temporary", "bypass", "TODO: remove
before prod", or "urgent hotfix" correlate with rushed, under-reviewed
changes in the software engineering literature on commit-message mining,
independent of the diff's structural size. This module tests that signal
in isolation as a second vote alongside the structural risk model, not a
replacement for it.

Training data: like train_model.py, this ships with a synthetic-but-
documented generator (templated risky vs. safe commit message phrases with
randomized surrounding text) — the same transparency disclosure applies:
this demonstrates the technique works, it does not demonstrate real-world
accuracy against actual historical commit messages.

Usage:
    python ml/risk_predictor/commit_message_classifier.py --train
    python ml/risk_predictor/commit_message_classifier.py --predict "quick fix, bypassing validation for now"
"""
import argparse
import os
import random

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, classification_report
from sklearn.pipeline import Pipeline

MODEL_PATH_DEFAULT = os.path.join(os.path.dirname(__file__), "commit_classifier.joblib")

# Phrase banks used only to LABEL synthetic training examples — same
# transparency principle as train_model.py's synthetic_risk_score().
RISKY_PHRASES = [
    "quick fix", "temporary workaround", "bypassing validation", "hotfix urgent",
    "disable check for now", "TODO remove before prod", "hardcoded for testing",
    "skip review needed asap", "emergency patch", "commented out the test",
    "will fix properly later", "just to unblock deploy", "quick and dirty",
    "removed the auth check temporarily", "disabled logging to save time",
    "bypass rate limit for demo", "force push to fix ci", "wip do not merge yet but deploying anyway",
]
SAFE_PHRASES = [
    "add unit tests for", "refactor module to improve readability", "update documentation for",
    "fix typo in", "bump dependency version", "add input validation for",
    "improve error handling in", "add integration test coverage for",
    "code review feedback addressed", "add logging for observability",
    "optimize query performance", "add type hints to", "clean up unused imports",
    "implement requested feature", "add docstrings to", "resolve merge conflict in",
    "update changelog", "add rate limiting to endpoint", "encrypt sensitive field before storage",
]
SUBJECTS = [
    "the login flow", "the payment endpoint", "user profile service", "the database migration",
    "the auth middleware", "the API gateway config", "the deployment script", "the notification service",
    "the export feature", "the admin dashboard", "session handling", "the webhook handler",
]


def generate_synthetic_commits(n_per_class: int = 400, seed: int = 42):
    rng = random.Random(seed)
    messages, labels = [], []
    for _ in range(n_per_class):
        phrase = rng.choice(RISKY_PHRASES)
        subject = rng.choice(SUBJECTS)
        messages.append(f"{phrase} {subject}" if rng.random() < 0.5 else f"{phrase} in {subject}")
        labels.append(1)
    for _ in range(n_per_class):
        phrase = rng.choice(SAFE_PHRASES)
        subject = rng.choice(SUBJECTS)
        messages.append(f"{phrase} {subject}" if rng.random() < 0.5 else f"{phrase} in {subject}")
        labels.append(0)
    combined = list(zip(messages, labels))
    rng.shuffle(combined)
    messages, labels = zip(*combined)
    return list(messages), list(labels)


def train(n_per_class: int = 400, out_path: str = MODEL_PATH_DEFAULT) -> dict:
    messages, labels = generate_synthetic_commits(n_per_class)
    X_train, X_test, y_train, y_test = train_test_split(
        messages, labels, test_size=0.2, random_state=42, stratify=labels
    )

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, max_features=2000)),
        ("clf", LogisticRegression(max_iter=1000, C=1.0)),
    ])
    pipeline.fit(X_train, y_train)

    preds = pipeline.predict(X_test)
    acc = accuracy_score(y_test, preds)
    f1 = f1_score(y_test, preds)
    report = classification_report(y_test, preds, target_names=["safe", "risky"])

    joblib.dump(pipeline, out_path)
    return {"accuracy": acc, "f1": f1, "report": report, "n_train": len(X_train), "n_test": len(X_test)}


def predict(message: str, model_path: str = MODEL_PATH_DEFAULT) -> dict:
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"No trained classifier at {model_path}. Run with --train first.")
    pipeline = joblib.load(model_path)
    proba = pipeline.predict_proba([message])[0]
    risky_probability = float(proba[1])

    # Surface which n-grams the linear model weighted most heavily for
    # this specific message — logistic regression over TF-IDF is
    # inherently interpretable (unlike a black-box classifier), since the
    # decision is a weighted sum of per-token coefficients.
    tfidf = pipeline.named_steps["tfidf"]
    clf = pipeline.named_steps["clf"]
    feature_names = tfidf.get_feature_names_out()
    x_vec = tfidf.transform([message])
    nonzero = x_vec.nonzero()[1]
    contributions = sorted(
        [(feature_names[i], float(x_vec[0, i] * clf.coef_[0][i])) for i in nonzero],
        key=lambda t: -abs(t[1]),
    )[:5]

    return {
        "message": message,
        "risky_probability": round(risky_probability, 3),
        "predicted_label": "risky" if risky_probability >= 0.5 else "safe",
        "top_ngram_contributions": [{"ngram": n, "weight": round(w, 3)} for n, w in contributions],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", action="store_true")
    ap.add_argument("--predict", type=str, default=None)
    ap.add_argument("--model", default=MODEL_PATH_DEFAULT)
    args = ap.parse_args()

    if args.train:
        metrics = train(out_path=args.model)
        print(f"Trained on {metrics['n_train']} samples, tested on {metrics['n_test']}")
        print(f"Test accuracy: {metrics['accuracy']:.3f}")
        print(f"Test F1 (risky class): {metrics['f1']:.3f}\n")
        print(metrics["report"])
        print(f"Model saved to: {args.model}")
    elif args.predict:
        result = predict(args.predict, args.model)
        print(f"Message: \"{result['message']}\"")
        print(f"Risky probability: {result['risky_probability']} -> {result['predicted_label'].upper()}")
        print("Top contributing n-grams:")
        for c in result["top_ngram_contributions"]:
            direction = "toward risky" if c["weight"] > 0 else "toward safe"
            print(f"  '{c['ngram']}'  weight={c['weight']:+.3f}  ({direction})")
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
