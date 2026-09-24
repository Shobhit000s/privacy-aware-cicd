package privacy

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# --------------------------------------------------------------------------
# Deny set: any non-empty result here fails the CI/CD gate
# (evaluated as `data.privacy.deny` in the pipeline)
# --------------------------------------------------------------------------

default allow := false

allow if count(deny) == 0

# 1. No plaintext secrets in environment variables declared in the manifest
deny contains msg if {
	some env in input.deployment.env
	looks_like_secret(env.name)
	not env.valueFrom
	msg := sprintf("env var '%s' appears to hold a secret but is set as plaintext, not valueFrom a Secret/Vault reference", [env.name])
}

# 2. Containers must not run as root
deny contains msg if {
	input.deployment.securityContext.runAsNonRoot != true
	msg := "container securityContext.runAsNonRoot must be true"
}

# 3. Containers must not request privilege escalation
deny contains msg if {
	input.deployment.containerSecurityContext.allowPrivilegeEscalation == true
	msg := "allowPrivilegeEscalation must be false"
}

# 4. PII-shaped fields in the data schema must have an encryption-at-rest flag
deny contains msg if {
	some field in input.data_schema.fields
	is_pii_field(field.name)
	not field.encrypted
	msg := sprintf("field '%s' looks like PII (name pattern match) but is not marked encrypted", [field.name])
}

# 5. Any service touching PII fields must log access via the audit module
deny contains msg if {
	some field in input.data_schema.fields
	is_pii_field(field.name)
	not input.service.audit_logging_enabled
	msg := "service touches PII fields but audit_logging_enabled is false"
}

# 6. Cross-border data transfer requires explicit compliance approval
deny contains msg if {
	input.deployment.data_residency.destination_region != input.deployment.data_residency.source_region
	not input.deployment.data_residency.compliance_approved
	msg := sprintf("cross-region data transfer (%s -> %s) requires compliance_approved=true", [input.deployment.data_residency.source_region, input.deployment.data_residency.destination_region])
}

# 7. Logs must not contain raw request bodies when PII fields are present
deny contains msg if {
	input.service.logs_raw_request_body == true
	some field in input.data_schema.fields
	is_pii_field(field.name)
	msg := "service logs raw request bodies while handling PII fields — risk of PII leaking into logs"
}

# 8. Public ingress to a service holding PII requires WAF/rate-limiting annotation
deny contains msg if {
	input.deployment.ingress.public == true
	some field in input.data_schema.fields
	is_pii_field(field.name)
	not input.deployment.ingress.waf_enabled
	msg := "publicly-exposed service handles PII but has no WAF/rate-limiting enabled"
}

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

looks_like_secret(name) if {
	patterns := ["SECRET", "TOKEN", "PASSWORD", "PASSWD", "API_KEY", "APIKEY", "PRIVATE_KEY", "CREDENTIAL", "SSH_KEY"]
	some p in patterns
	contains(upper(name), p)
}

is_pii_field(name) if {
	patterns := ["email", "ssn", "social_security", "phone", "address", "dob", "date_of_birth", "passport", "credit_card", "national_id", "full_name"]
	some p in patterns
	contains(lower(name), p)
}
