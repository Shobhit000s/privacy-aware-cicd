# vault/policies/app-policy.hcl
# Least-privilege policy for the backend application pod.

path "secret/data/prod/backend" {
  capabilities = ["read"]
}

path "secret/data/prod/postgres" {
  capabilities = ["read"]
}

# Allow requesting short-lived dynamic Postgres credentials instead of a
# long-lived static password (see setup.sh step 5)
path "database/creds/backend-dynamic" {
  capabilities = ["read"]
}

# Deny everything else implicitly (Vault default-deny)
