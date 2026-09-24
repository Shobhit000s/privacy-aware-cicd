# vault/policies/ci-policy.hcl
# Scoped to exactly what scripts/secret_rotation.py needs: read+write on the
# app/postgres secret paths it rotates, nothing else. No token, no standing
# credential — authenticated per-run via GitHub OIDC (see setup.sh step 4).

path "secret/data/prod/backend" {
  capabilities = ["read", "create", "update"]
}

path "secret/data/prod/postgres" {
  capabilities = ["read", "create", "update"]
}

path "secret/metadata/prod/*" {
  capabilities = ["list", "read"]
}
