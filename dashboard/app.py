#!/usr/bin/env python3
"""
dashboard/app.py

Privacy compliance dashboard: shows the current security score, recent audit
trail (from the hash-chained audit log), and lets a user paste/adjust a
feature vector to see the ML risk model's live prediction and explanation.

Run:
    python dashboard/app.py
    -> http://localhost:5000
"""
import json
import os
import sys
from datetime import datetime

from flask import Flask, jsonify, render_template, request, Response

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ml", "risk_predictor"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

app = Flask(__name__)

AUDIT_LOG_PATH = os.environ.get("AUDIT_LOG_PATH", os.path.join(os.path.dirname(__file__), "..", "audit_log.jsonl"))
MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "ml", "risk_predictor", "model.joblib")

# in-process metrics, exposed at /metrics in Prometheus text format
_metrics = {
    "pipeline_risk_score": 0,
    "pipeline_security_score": 100,
    "pipeline_run_status": 1,
}


def read_audit_log(limit: int = 50) -> list[dict]:
    if not os.path.exists(AUDIT_LOG_PATH):
        return []
    events = []
    with open(AUDIT_LOG_PATH) as f:
        for line in f:
            if line.strip():
                events.append(json.loads(line))
    return list(reversed(events))[:limit]


@app.route("/")
def index():
    events = read_audit_log()
    latest_score = events[0].get("security_score", 100) if events else 100
    avg_risk = (
        round(sum(e.get("risk_score") or 0 for e in events) / len(events), 1)
        if events else 0
    )
    return render_template(
        "index.html",
        events=events,
        latest_score=latest_score,
        avg_risk=avg_risk,
        total_runs=len(events),
    )


@app.route("/predict", methods=["GET", "POST"])
def predict_page():
    result = None
    features_used = None
    if request.method == "POST":
        from features import FEATURE_NAMES
        from predict_risk import predict

        features_used = {name: float(request.form.get(name, 0)) for name in FEATURE_NAMES}
        try:
            result = predict(features_used, MODEL_PATH)
            _metrics["pipeline_risk_score"] = result["risk_score"]
        except FileNotFoundError as e:
            result = {"error": str(e)}

    from features import FEATURE_NAMES
    return render_template("predict.html", feature_names=FEATURE_NAMES, result=result, features_used=features_used)


@app.route("/api/audit")
def api_audit():
    return jsonify(read_audit_log())


@app.route("/api/verify")
def api_verify():
    from audit_logger import verify_chain
    return jsonify({"integrity_ok": verify_chain(AUDIT_LOG_PATH)})


@app.route("/metrics")
def metrics():
    lines = [f"{k} {v}" for k, v in _metrics.items()]
    return Response("\n".join(lines) + "\n", mimetype="text/plain")


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
