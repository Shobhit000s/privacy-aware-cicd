# Privacy-Aware CI/CD Pipeline

An end-to-end DevSecOps pipeline that detects, protects, rotates, and audits sensitive
data (API keys, DB credentials, SSH keys, PII, sensitive logs) **before** it ever reaches
a deployment — with an ML model that predicts the *privacy-risk score* of a deployment
before it ships.

```
Commit ──▶ Secret Scan (Gitleaks) ──▶ Vuln Scan (Trivy) ──▶ Policy Check (OPA) ──▶
ML Risk Prediction ──▶ Secret Rotation (Vault) ──▶ Deploy (K8s) ──▶ Audit Log + Dashboard
```

## Why this exists

Most CI/CD pipelines fail privacy/security not because tools are missing, but because:
1. Secret scanners run *after* damage is done (post-merge, not pre-commit/pre-deploy gate).
2. Policy checks are manual code-review judgment calls, not enforced machine policy.
3. Nobody predicts risk *before* deploying — teams only find out via an incident.
4. Audit trails are scattered across tool-specific logs instead of one compliance view.

This project closes those four gaps.

## Repository layout

```
privacy-aware-cicd/
├── .github/workflows/pipeline.yml     # GitHub Actions orchestration (Jenkinsfile in jenkins/ mirrors it)
├── jenkins/Jenkinsfile                # Jenkins declarative pipeline, same stages/scripts as above
├── backend/                           # FastAPI business app: JWT auth, RBAC, deployments API, DB-backed audit trail
├── app/frontend/                      # React SPA: login/register, dashboard, deployments + manual-override UI
├── dashboard/                         # Separate Flask ops/compliance dashboard (security score, ML predictor UI)
├── scanner/privacy_scanner.py         # Custom PII scanner: email/phone/password/API key/Aadhaar/PAN/JWT/certs
├── scanner/ner_pii_detector.py        # ML: spaCy NER for unstructured PII (names, addresses) regex can't catch
├── docker/                            # Dockerfile + full docker-compose (Postgres, Vault, OPA, Prometheus,
│                                       # Grafana, Alertmanager, exporters, OpenSearch+Fluent Bit, backend, frontend)
├── k8s/base/                          # Namespace, ConfigMap, Secret templates, Ingress, Postgres StatefulSet+PVC,
│                                       # HPA, RBAC, backend/frontend/ops-dashboard Deployments+Services,
│                                       # per-service NetworkPolicies, tied together via kustomization.yaml
├── k8s/vault/                         # ExternalSecret + SecretStore manifests syncing Vault -> K8s Secrets
├── vault/                             # setup.sh (KV, K8s auth, JWT/OIDC auth, dynamic Postgres creds), policies/
├── policies/opa/                      # Rego policies: secret exposure, PII handling, deployment gates
├── gitleaks/                          # Gitleaks rule config (custom rules for PII + cloud credentials)
├── trivy/                             # trivy.yaml config + .trivyignore with documented-exception format
├── monitoring/                        # Prometheus + Alertmanager config, node/postgres exporters,
│                                       # Grafana dashboard JSON + datasource/dashboard provisioning
├── logging/fluent-bit/                # Fluent Bit config shipping container logs to OpenSearch
├── scripts/                           # secret_rotation.py, audit_logger.py, install_hooks.sh
├── ml/risk_predictor/                 # Feature extraction + trained ML risk-prediction model
│                                       # + exact SHAP explainability + commit-message NLP classifier
├── tests/                             # Unit, integration (FastAPI TestClient), K8s manifest validation,
│                                       # and pipeline-config (OPA/Gitleaks/workflow YAML) tests
└── docs/ARCHITECTURE.md               # Full design doc + threat model
```

## Quick start (local)

```bash
# 1. Bring up the full local stack: Postgres, Vault, OPA, backend, frontend,
#    Prometheus/Grafana/Alertmanager/exporters, OpenSearch/Fluent Bit, ops dashboard
cd docker && docker compose up -d --build

# 2. One-time Vault configuration (KV secrets, K8s/JWT auth, dynamic DB creds)
export VAULT_ADDR=http://localhost:8200 VAULT_TOKEN=dev-only-root-token
bash ../vault/setup.sh

# 3. Open the apps
#    Business app (React):       http://localhost:3000
#    Backend API docs:           http://localhost:8000/docs
#    Ops/compliance dashboard:   http://localhost:5000
#    Grafana:                    http://localhost:3001  (admin/admin)
#    OpenSearch Dashboards:      http://localhost:5601

# 4. Train the ML risk model and run the full test suite
pip install -r requirements.txt -r backend/requirements.txt
python ml/risk_predictor/train_model.py
pytest tests/ -v
```

### Running the backend/frontend without Docker

```bash
cd backend && pip install -r requirements.txt && uvicorn main:app --reload --port 8000
cd app/frontend && npm install && npm run dev   # http://localhost:5173
```

## Pipeline stages (see `.github/workflows/pipeline.yml`)

| Stage | Tool | Gate behavior |
|---|---|---|
| 1. Pre-commit / pre-push secret scan | Gitleaks | Blocks commit locally via git hook |
| 2. Container/dependency vuln scan | Trivy | Fails build on CRITICAL/HIGH CVEs |
| 3. Policy-as-code check | Open Policy Agent | Fails build if `deny` rule fires |
| 4. **ML privacy-risk prediction** | Custom scikit-learn model | Fails build if risk score ≥ threshold |
| 5. Secret rotation | HashiCorp Vault | Rotates any secret flagged as "touched" pre-deploy |
| 6. Deploy | Kubernetes | Only runs if stages 1–5 pass |
| 7. Audit + compliance dashboard | Prometheus/Grafana + Flask | Every stage emits a structured audit event |

## Research novelty: ML privacy-risk prediction

Rather than binary pass/fail secret detection, `ml/risk_predictor/` trains a classifier
over structural features of a deployment (diff size, number of new env vars, number of
files touching config/secrets paths, historical incident rate of the service, presence
of PII-shaped fields, network-policy exposure, image base freshness, etc.) to output a
**0–100 privacy-risk score** and a plain-language explanation of the top contributing
factors (via feature importances), rather than just "gitleaks found a match."

This lets the pipeline catch risk patterns Gitleaks/Trivy/OPA can't: e.g. "this
deployment doesn't contain a literal secret, but structurally resembles the last 3
deployments that leaked PII" (broad exposure, new public ingress, no audit log call,
touches a table with an email/SSN-shaped column).

See `docs/ARCHITECTURE.md` for the full feature list, model choice rationale, and
threat model.

## Status of components in this repo

See `docs/VERIFICATION_LOG.md` for the full, timestamped account of exactly
what was run, what broke, what got fixed, and why certain things remain
untested — this section is the short version.

**Fully functional, tested end-to-end against real tools/services:**
- FastAPI backend (JWT auth, RBAC, deployments API, DB-backed hash-chained audit trail) — 15 integration tests, plus a manual run against a **real PostgreSQL 16 instance** with data verified via direct `psql` query (the pytest suite itself still uses a SQLite fixture by design, for test isolation/speed)
- React frontend — builds cleanly via `npm run build`
- Custom privacy scanner (Aadhaar/PAN with real checksum validation, email/phone/JWT/password/cert/credit-card detection)
- ML risk model (train/predict, R²≈0.75 on synthetic data)
- OPA policies (15 Rego rules) — 12 pipeline-config tests including live `opa eval` runs
- **Gitleaks** — ran the real binary against this repo; it caught 6 false positives that exposed a real bug in a custom rule's capture group (was reporting the key *name*, not the value, so the allowlist could never match). Fixed and re-verified: **0 findings, clean scan**
- **Kubernetes manifests** — validated with `kubeconform` against real Kubernetes OpenAPI schemas (not just this project's own tests): **25/26 resources valid**, 1 expected non-error (Kustomize's own file has no K8s schema)
- **Prometheus** — real binary, config validated with `promtool`, then actually started and confirmed via its live API to be scraping all 3 configured targets correctly
- **Alertmanager** — real binary, config validated with `amtool`, actually started and confirmed healthy with the real receivers/routes loaded
- Audit logger, secret rotation script, Flask ops dashboard

**Attempted and genuinely blocked** (not skipped — each failed for a specific, documented reason; see the verification log):
- **Vault** — binary cannot be downloaded in this sandbox; `releases.hashicorp.com` is outside the network allowlist and Vault isn't on GitHub releases
- **Trivy vulnerability scanning** — the binary runs, but its vulnerability database is hosted on `mirror.gcr.io`/`ghcr.io`, both blocked by network policy
- **OpenSearch + Fluent Bit** — no reachable standalone-binary distribution for either
- **Full docker-compose stack** — no `docker` binary exists in this sandbox at all
- **Jenkins** — no server available to execute `jenkins/Jenkinsfile` against
- **A live Kubernetes deploy** — no `kubectl`/`minikube`/`kind`/`k3s` available; `kubeconform` (above) is the strongest validation achievable without one

**105 passed, 3 skipped, 0 failed** across the full `pytest tests/` run at last check.

