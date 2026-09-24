#!/usr/bin/env bash
# vault/setup.sh
#
# One-time Vault configuration for this project. Run against a Vault server
# that's already unsealed (the docker-compose `vault` service is a dev-mode
# server that's unsealed automatically — for a real deployment, run this
# after `vault operator init` + `vault operator unseal`).
#
# Usage:
#   export VAULT_ADDR=http://localhost:8200
#   export VAULT_TOKEN=dev-only-root-token   # or a real admin token in prod
#   bash vault/setup.sh
set -euo pipefail

echo "== 1. Enable KV v2 secrets engine =="
vault secrets enable -path=secret -version=2 kv || echo "  (already enabled)"

echo "== 2. Write policies =="
vault policy write privacy-aware-app vault/policies/app-policy.hcl
vault policy write ci-pipeline vault/policies/ci-policy.hcl
vault policy write ops-dashboard vault/policies/dashboard-policy.hcl

echo "== 3. Enable Kubernetes auth method (for in-cluster pods) =="
vault auth enable kubernetes || echo "  (already enabled)"
vault write auth/kubernetes/config \
    kubernetes_host="https://kubernetes.default.svc:443"

vault write auth/kubernetes/role/privacy-aware-app \
    bound_service_account_names=privacy-aware-app-sa \
    bound_service_account_namespaces=production \
    policies=privacy-aware-app \
    ttl=1h

vault write auth/kubernetes/role/ops-dashboard \
    bound_service_account_names=ops-dashboard-sa \
    bound_service_account_namespaces=production \
    policies=ops-dashboard \
    ttl=1h

echo "== 4. Enable JWT/OIDC auth for GitHub Actions (no static CI credentials) =="
vault auth enable jwt || echo "  (already enabled)"
vault write auth/jwt/config \
    bound_issuer="https://token.actions.githubusercontent.com" \
    oidc_discovery_url="https://token.actions.githubusercontent.com"

vault write auth/jwt/role/github-actions-ci \
    role_type="jwt" \
    bound_audiences="https://github.com/YOUR_ORG" \
    bound_claims="{\"repository\":\"YOUR_ORG/privacy-aware-cicd\"}" \
    user_claim="actor" \
    policies="ci-pipeline" \
    ttl=15m

echo "== 5. Enable the database secrets engine for DYNAMIC Postgres credentials =="
# Instead of a single static DB password, the backend can request a
# short-lived, uniquely-generated DB user/pass pair per pod lease.
vault secrets enable database || echo "  (already enabled)"
vault write database/config/privacy-cicd-postgres \
    plugin_name=postgresql-database-plugin \
    connection_url="postgresql://{{username}}:{{password}}@postgres:5432/privacy_cicd?sslmode=disable" \
    allowed_roles="backend-dynamic" \
    username="vault_admin" \
    password="CHANGE_ME_ADMIN_PASSWORD"

vault write database/roles/backend-dynamic \
    db_name=privacy-cicd-postgres \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
        GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    default_ttl="1h" \
    max_ttl="24h"

echo "== 6. Seed initial static secrets (placeholders — replace before real use) =="
vault kv put secret/prod/backend \
    database_url="postgresql+psycopg2://app_user:CHANGE_ME@postgres:5432/privacy_cicd" \
    jwt_secret_key="$(openssl rand -hex 32)"

vault kv put secret/prod/postgres \
    username="app_user" \
    password="CHANGE_ME" \
    dbname="privacy_cicd"

vault kv put secret/ci \
    ci_role_id="placeholder-role-id"

echo ""
echo "Vault setup complete."
echo "  - Static secrets:  vault kv get secret/prod/backend"
echo "  - Dynamic creds:   vault read database/creds/backend-dynamic"
