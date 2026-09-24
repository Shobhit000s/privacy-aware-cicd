# vault/policies/dashboard-policy.hcl
# Read-only: the compliance dashboard displays secret *metadata* (rotation
# timestamps, which paths exist) but never needs to read secret values.

path "secret/metadata/prod/*" {
  capabilities = ["list", "read"]
}

path "sys/health" {
  capabilities = ["read"]
}
