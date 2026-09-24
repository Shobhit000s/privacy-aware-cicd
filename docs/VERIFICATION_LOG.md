# Verification Log

This log records exactly what was **actually executed** against this project,
as distinct from configuration that is merely written-and-presumed-correct.
Every entry below reflects a real command run in a real sandboxed Linux
environment on 2026-07-30. Nothing in this file is inferred or assumed.

## Newly verified in this pass (previously "config only, never run")

### Gitleaks — real binary (v8.21.2), real bug found and fixed
Running the actual `gitleaks` binary against this repository initially
returned **6 findings** — all false positives, but genuine ones: two
documented placeholder strings (`dev-only-change-me`, `REPLACE_ME_INJECTED_BY_VAULT`),
two Vault KV path references misread as secret values, and a demo JWT
fixture inside `scanner/privacy_scanner.py`'s own `--demo` mode (used to
test the scanner's JWT detector).

Investigating why the allowlist didn't suppress these revealed a real bug:
the custom `generic-api-key-assignment` rule's capture group reported the
*key name* ("SECRET_KEY") as the leaked secret, not the actual value —
so allowlist regexes matching against real placeholder values could never
hit. Fixed by adding `secretGroup = 1` to correctly isolate the value.
**Final result: 0 findings, clean scan.** See `gitleaks/.gitleaks.toml`
for the corrected rule and the allowlist entries added in direct response
to this run (each is commented with why it exists).

### Kubernetes manifests — real schema validation (kubeconform v0.6.7)
No live cluster is available in this environment, but `kubeconform`
validates manifests against the actual Kubernetes OpenAPI schemas without
needing one. Result: **26 resources found in 12 files — 25 valid, 0
invalid, 1 error** (the 1 error is `kustomization.yaml`, which has no K8s
API schema because it's a Kustomize file, not a Kubernetes object —
expected, not a defect). This is materially stronger evidence than the
hand-written `tests/k8s_validation/` suite alone, since it checks against
schemas this project's own author didn't write. Repeatable via
`scripts/validate_k8s_schemas.sh`.

### Prometheus — real binary (v2.55.1), actually started and scraping
`promtool check config` passed on the real `monitoring/prometheus.yml` and
`alert_rules.yml`. The server was then actually started (not just
config-checked) and its live `/api/v1/targets` endpoint confirmed all
three configured scrape jobs (`opa`, `privacy-dashboard`, `pushgateway`)
registered correctly. The `pushgateway` target correctly showed `health:
down` with a DNS resolution failure for the hostname `pushgateway` — the
*expected* result outside the actual docker-compose network, confirming
the config resolves and behaves correctly rather than being silently wrong.

### Alertmanager — real binary (v0.27.0), actually started
`amtool check-config` passed on `monitoring/alertmanager/alertmanager.yml`.
The server was started with clustering disabled (`--cluster.listen-address=""`,
required in a sandbox with no private IP for gossip) and its `/-/healthy`
and `/api/v2/status` endpoints confirmed it loaded the real config (2
receivers, 1 inhibit rule) and reported healthy.

### PostgreSQL — real database (v16, via apt), backend run against it
Previously the backend was only ever tested against SQLite. PostgreSQL 16
was installed, a real `privacy_cicd` database and `app_user` role were
created matching `docker/docker-compose.yml`'s exact credentials, and the
FastAPI backend was started with `DATABASE_URL` pointed at it. A user
registration was submitted via `curl` and confirmed to have actually
persisted by querying Postgres directly with `psql` — all 4 expected
tables (`users`, `deployments`, `audit_events`, `secret_rotations`) were
auto-created by SQLAlchemy and the row was present with correct data.

**Caveat, stated precisely**: the automated integration test suite
(`tests/integration/test_backend_api.py`) still runs against a temporary
SQLite file by design (its fixture calls `monkeypatch.setenv("DATABASE_URL",
...)` to a sqlite path for test isolation/speed) — setting `DATABASE_URL`
externally before running pytest does **not** override this, and an
earlier draft of this log incorrectly claimed the pytest suite itself ran
against Postgres. It did not. The Postgres proof is the manual `curl` +
`psql` verification described above, not the pytest run.

## Attempted but genuinely blocked by this sandbox's network policy

These are not skipped out of laziness — each was actively attempted and
failed for a specific, verifiable reason:

- **HashiCorp Vault**: no binary could be obtained. `releases.hashicorp.com`
  returns `403 Forbidden: host_not_allowed` under this environment's
  network egress policy, and Vault is not distributed via GitHub releases
  (unlike Gitleaks, Trivy, Prometheus, etc.). `vault/setup.sh` remains
  correct HCL/CLI syntax, verified by inspection, but was never executed
  against a live server.
- **Trivy vulnerability scanning**: the `trivy` binary itself downloaded
  and runs (`trivy --version` succeeds), but every scan requires
  downloading its vulnerability database from an OCI registry, and both
  `mirror.gcr.io` and `ghcr.io` (the only two distribution points for
  `trivy-db`) return `403 Forbidden: host not in allowlist` under this
  environment's network policy. No vulnerability scan could be completed.
- **OpenSearch + Fluent Bit**: OpenSearch is JVM-based and distributed only
  as a multi-hundred-MB Docker image or tarball from opensearch.org, which
  is not reachable here; no standalone-binary path exists. Fluent Bit's
  GitHub releases page returned `404` for the expected `.deb` asset
  pattern at the version checked. Neither was run.
- **Full docker-compose stack**: this sandbox has no `docker` binary at
  all (`which docker` → not found), so the compose file's 15 services were
  never brought up together as one orchestrated stack. Each service's
  config was instead validated individually via its own native tooling
  where possible (Prometheus, Alertmanager, Postgres, above).
- **Jenkins**: no Jenkins server exists in this environment and none could
  be provisioned; `jenkins/Jenkinsfile` remains untested syntax, reviewed
  by inspection only.
- **A live Kubernetes cluster**: no `kubectl`, `minikube`, `kind`, or `k3s`
  available. `kubeconform` (above) is the strongest validation achievable
  without one.

## Net effect on the project's honesty claims

The README's "Status of components" section is updated to reflect all of
the above precisely. The short version: the application layer (FastAPI
backend, React frontend, ML risk model, custom privacy scanner, OPA
policies, Gitleaks) is now verified against *real* tools and a *real*
database, not just unit tests in isolation. The infrastructure layer
(Vault, live Kubernetes, Trivy's vulnerability database, OpenSearch/Fluent
Bit, Jenkins, full docker-compose orchestration) remains correct-per-spec
but genuinely unexecuted, for the specific network and tooling reasons
documented above — not because it was left untried.
