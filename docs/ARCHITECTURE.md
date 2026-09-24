# Architecture & Design

## 1. Threat model

This pipeline defends against four failure modes that cause most real-world
CI/CD privacy incidents:

| # | Failure mode | Mitigation in this repo |
|---|---|---|
| 1 | A secret is committed and merged before anyone notices | Gitleaks pre-commit hook (local) + Gitleaks CI gate (`secret-scan` job) — two independent checkpoints |
| 2 | A vulnerable base image or dependency ships to prod | Trivy CI gate, fails on CRITICAL/HIGH CVEs, SARIF uploaded to code-scanning |
| 3 | A deployment is technically "clean" (no literal secret) but structurally risky — broad public exposure, unencrypted PII, no audit logging, touches auth code, deployed by one person on a Friday | **ML risk predictor** — this is the part static scanners cannot see |
| 4 | An incident happens and nobody can reconstruct what was deployed, by whom, with what risk score, and whether logs were tampered with afterward | Hash-chained audit log (`scripts/audit_logger.py`) + Grafana compliance dashboard |
| 5 | A secret that *was* reviewed/touched sits unrotated indefinitely, so a leaked review artifact stays valid | `scripts/secret_rotation.py` rotates any Vault path referenced by a diff automatically, no human step required |

## 2. Why an ML model, not just more static rules

Gitleaks/Trivy/OPA are all **rule-based**: they catch what someone already
wrote a rule for. The research novelty in this project is treating "will this
deployment cause a privacy problem" as a **regression problem over structural
features of the change**, so it can flag combinations of *individually
unremarkable* signals — e.g. no literal secret, but: new public endpoint +
unencrypted PII field + zero reviewers + stale base image + Friday deploy.
No single OPA rule captures that combination without becoming unmaintainable;
a model trained on historical outcomes can.

### Feature set (`ml/risk_predictor/features.py`)

14 features spanning diff size/breadth, secret-shaped env vars, PII field
exposure and encryption status, audit-logging posture, service incident
history, base image freshness, review coverage, deploy timing, and whether
auth code paths are touched. Each has a stated causal rationale in the module
docstring.

### Model choice

`GradientBoostingRegressor` (scikit-learn) over a 0–100 continuous risk score,
rather than a binary classifier, because:
- Risk is genuinely continuous — a "68" and a "94" both warrant different
  responses (manual review vs. hard block), which a binary label throws away.
- Feature importances are natively available for the explanation panel,
  without needing a separate SHAP dependency.
- Gradient boosting handles the mixed count/binary/continuous feature types
  here without manual scaling.

### Training data

Ships with a **synthetic dataset generator** (`train_model.py:
generate_synthetic_dataset`) rather than real historical data, because real
deployment/incident history is itself sensitive and organization-specific.
The generator encodes an explicit, documented domain-knowledge formula
(`synthetic_risk_score`) plus Gaussian noise, so the model has real signal to
learn rather than memorizing randomness — evidenced by Test R² ≈ 0.75 and
sensible feature importances (unencrypted PII fields and secret-shaped env
vars dominate, matching intuition).

**To productionize**: replace `generate_synthetic_dataset()` with a loader
that reads your own audit log (`audit_log.jsonl`) joined against your
incident tracker — label each historical deployment with whether it caused a
privacy incident within N days, or with a security team's manually assigned
risk score, and retrain periodically (`train_model.py --n-samples ...` becomes
`train_model.py --from-audit-log`).

### Explainability

`predict_risk.py` returns not just a score but the top contributing factors,
computed as `feature_importance × feature_value` (with `has_audit_logging`
inverted since its *absence* drives risk up). This is a lightweight,
dependency-free stand-in for a proper SHAP explanation — swap in the `shap`
library if you need exact Shapley values for compliance/audit purposes.

## 3. Audit log design: why hash-chained JSONL, not just a database table

`scripts/audit_logger.py` writes each pipeline-run event with a SHA-256 hash
of its own contents plus the *previous* event's hash (a simple blockchain-
style linked list). This means:
- Any single-event edit breaks the chain from that point forward — detectable
  by `--verify` / `/api/verify` without needing a separate integrity DB.
- Cheap to implement, no extra infrastructure, and portable — the log is a
  plain `.jsonl` file that can be shipped to any log store (S3, Loki,
  Splunk) while keeping the chain intact.
- This is a detective control, not a preventive one: it doesn't stop someone
  with write access to the log file from tampering with it, but any tampering
  is provably detectable, which is the property compliance audits need.

## 4. Jenkins portability

The primary pipeline is written as GitHub Actions (`.github/workflows/pipeline.yml`)
per the brief's "GitHub Actions or Jenkins" option. Porting to Jenkins is
mechanical because every stage's actual work lives in a plain script or CLI
tool (Gitleaks/Trivy binaries, `opa eval`, `python ml/risk_predictor/predict_risk.py`,
`python scripts/secret_rotation.py`, `python scripts/audit_logger.py`) rather
than GitHub-Actions-specific logic — a `Jenkinsfile` would call the same
scripts as `sh` steps inside a declarative pipeline with matching stage names.

## 5. Additional ML components: NER-based PII detection, exact SHAP, and a commit-message classifier

The original system had exactly one ML component (the Gradient Boosting
risk regressor). Three more were added to make the project's AI/ML content
substantive rather than singular, each addressing a specific, previously-
disclosed gap rather than being added for its own sake.

### 5.1 NER-based PII detection (`scanner/ner_pii_detector.py`)

The literature review (Mishra, Pagare & Sharma, 2025) identified that
regex-only PII detection fails on *unstructured* identifiers — a name or
address has no fixed format to match against. This module uses spaCy's
pretrained statistical NER model to detect `PERSON` and `GPE`/`LOC`
entities in source files, complementing (not replacing) the
checksum-validated regex scanner in `privacy_scanner.py`.

**Verified result**: correctly detected both planted names ("Rohan
Malhotra", "Priya Sharma") in a test fixture. **Honest limitation, observed
directly**: it mislabeled address components ("Bangalore", "Karnataka") as
`PERSON` rather than `GPE` when embedded in short, quoted, code-syntax
strings rather than natural prose — the small pretrained model wasn't
trained on code-embedded text. It still flagged them as PII *candidates*
(the entity-type label was wrong, but the "this needs human review" signal
was correct), which is why this stage is designed for human triage rather
than hard CI blocking, unlike the checksum-validated scanner.

### 5.2 Exact SHAP explainability (`ml/risk_predictor/explain_shap.py`)

`docs/ARCHITECTURE.md` (this file, prior version) and the accompanying
paper explicitly flagged the original importance-weighted explanation as
"a lightweight approximation, not an exact Shapley-value computation" and
listed exact SHAP as future work. This module is that future work,
implemented: `shap.TreeExplainer` computes exact Shapley values in
polynomial time for tree ensembles.

Two properties distinguish this from the earlier approximation, and both
are enforced by an assertion in the code, not just asserted in prose:
1. **Signed, not just ranked** — a feature can be shown to *decrease* risk
   (negative SHAP value), which the earlier magnitude-only approximation
   could not express.
2. **Additivity holds exactly** — `base_value + sum(shap_values) ==
   model_prediction`, verified to `1e-4` tolerance at runtime
   (`explain_shap.py`, the `assert reconstruction - raw_score` line). This
   is a mathematical property of Shapley values, not a heuristic — if it
   fails, it indicates a real library version mismatch, not just an
   imprecise explanation.

### 5.3 Commit-message risk classifier (`ml/risk_predictor/commit_message_classifier.py`)

A second, independent supervised model — TF-IDF + Logistic Regression text
classification, a different technique and input modality (natural
language) from the structural regressor. The hypothesis: the language a
developer uses to describe their own change ("quick fix", "bypass",
"temporary") is a signal independent of the diff's structural size.

**Result, reported without smoothing over the problem it reveals**: the
model achieves **100% test accuracy** on its own synthetic phrase-bank
data — which is a red flag, not a success, and is disclosed as one. The
synthetic generator uses a small, closed vocabulary of template phrases
with no lexical overlap between the "risky" and "safe" banks, so a linear
bag-of-n-grams model separates them trivially. Manual testing on genuinely
novel, unseen phrasing confirms this is memorization, not generalization:
- *"skipping tests because deadline is tomorrow morning"* (intuitively
  risky) was classified **SAFE** (0.404 probability).
- *"reverting the temporary hack from last week now that proper fix is
  tested"* (describes REMOVING a risk) was classified **RISKY** (0.843
  probability) — the model fired on the token "temporary" with no
  understanding that "reverting" negates it. This is the textbook failure
  mode of a bag-of-words model: no negation or context handling.

`tests/test_additional_ml_components.py::test_documented_generalization_limitation_is_real`
encodes this failure mode as an assertion, specifically so that if a
future retrain (e.g., with a larger, more realistic dataset) accidentally
fixes it, the test breaks loudly and forces this section to be revisited
rather than silently going stale. **This component should be read as a
demonstration that the technique is implemented and functional, not as a
production-ready risk signal** — it is not currently wired into the OPA
policy gate the way the structural risk model is (Section 2), specifically
because it has not earned that trust yet.

## 6. Why two audit trails exist (JSONL + Postgres)

`scripts/audit_logger.py` writes a hash-chained **JSONL file** per pipeline
run; `backend/routers/deployments.py` + `backend/routers/audit.py` write a
hash-chained **Postgres table** per API action. These are intentionally
separate, not duplicated by accident:

- The **JSONL log** is written by the CI runner itself (no network dependency
  on the backend being up), ships as a build artifact, and is the source of
  truth for "did this pipeline run happen and was it tampered with" —
  independent of whether the deployed application's database is even
  reachable.
- The **Postgres trail** is written by the *deployed application* in response
  to authenticated API calls (who created/updated/approved a deployment
  record), and is what the React frontend and `/api/audit` query — it has
  real foreign keys to `users`/`deployments`, RBAC-gated writes, and survives
  application restarts.

Both use the identical hash-chaining scheme (SHA-256 of the event body +
previous event's hash), so `verify_chain()` in `audit_logger.py` and
`GET /api/audit/verify` provide the same tamper-evidence guarantee for their
respective stores. A production deployment would typically ship the JSONL
log's contents into the same Postgres table (or into OpenSearch via Fluent
Bit — see `logging/fluent-bit/fluent-bit.conf`) for a single unified view;
that reconciliation step is not implemented here.

## 7. Two dashboards, deliberately

- **`dashboard/` (Flask)** is the *ops/compliance* dashboard: security score,
  ML risk predictor UI, audit trail viewer. It's infrastructure tooling, not
  part of the deployed business app, and talks to Vault/OPA/Prometheus directly.
- **`app/frontend/` (React) + `backend/` (FastAPI)** is the *actual business
  application* the pipeline builds, scans, and deploys — the thing a real
  team would ship to users, complete with its own auth and its own deployment
  records. This is what `k8s/base/backend-deployment.yaml` and
  `frontend-deployment.yaml` put behind the Ingress.

## 8. Data flow summary

```
git push
  │
  ▼
[Gitleaks: pre-commit local + CI gate] ──fail──▶ blocked, nothing else runs
  │ pass
  ▼
[Trivy: image/dependency scan]        ──fail──▶ blocked
  │ pass
  ▼
[OPA: policy-as-code evaluation]      ──fail──▶ blocked (privacy_policy.rego, deployment_policy.rego)
  │ pass
  ▼
[ML risk predictor: features.py → predict_risk.py] ──score≥threshold──▶ blocked
  │ pass
  ▼
[Vault: rotate any secret path touched by this diff]
  │
  ▼
[Kubernetes: deploy]
  │
  ▼
[Audit logger: hash-chained event] ──▶ [Prometheus Pushgateway] ──▶ [Grafana dashboard]
```

Every stage — including failures — writes an audit event, so the dashboard
reflects blocked deployments too, not just successful ones.
