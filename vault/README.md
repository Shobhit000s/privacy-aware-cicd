# Vault Integration

## What's wired up

1. **Static secrets** (`secret/prod/backend`, `secret/prod/postgres`) — KV v2,
   seeded by `vault/setup.sh`.
2. **Dynamic secrets** — the `database` secrets engine generates a unique,
   short-lived Postgres user/password pair per lease (`vault read
   database/creds/backend-dynamic`) instead of one long-lived shared password.
   Preferred over static secrets wherever the consumer can handle rotating
   creds without a restart (see `backend/database.py` docstring for the
   production wiring note).
3. **Kubernetes auth** — pods authenticate to Vault using their
   ServiceAccount token (`vault/setup.sh` step 3), no Vault token baked into
   any image or K8s Secret.
4. **JWT/OIDC auth for CI** — `scripts/secret_rotation.py` and the GitHub
   Actions workflow authenticate to Vault via GitHub's native OIDC token
   (`hashicorp/vault-action`), not a static `VAULT_TOKEN` secret.
5. **Secret injection into pods** — two supported paths, both present in this
   repo (`k8s/base/backend-deployment.yaml` uses path 1; `k8s/vault/external-secret.yaml`
   documents path 2):
   - **Vault Agent sidecar injection**: the `vault.hashicorp.com/agent-inject-*`
     annotations on the Deployment render secrets to a file inside the pod at
     runtime — nothing touches the K8s API's Secret objects.
   - **External Secrets Operator**: syncs Vault → a real K8s `Secret`, for
     compatibility with tooling that expects `envFrom.secretRef`.
6. **Automatic rotation** — `scripts/secret_rotation.py` rotates any Vault
   path referenced by a diff, on every merge to `main` (see `.github/workflows/pipeline.yml`,
   stage 5). Least-privilege policies (`vault/policies/ci-policy.hcl`) mean
   the CI identity can only touch the specific paths it's scoped to.

## Running locally

```bash
docker compose -f docker/docker-compose.yml up -d vault
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=dev-only-root-token
bash vault/setup.sh
vault kv get secret/prod/backend
```

## What you must change before real use

- `vault/setup.sh` has several `CHANGE_ME` / placeholder values (admin DB
  password, GitHub org/repo for OIDC binding) — search the file for `CHANGE_ME`.
- The dev-mode Vault server (`VAULT_DEV_ROOT_TOKEN_ID`) is for local testing
  only. Production Vault needs `vault operator init` + unseal + auto-unseal
  (e.g. via cloud KMS) + TLS.
