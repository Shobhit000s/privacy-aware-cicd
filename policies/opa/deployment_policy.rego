package privacy

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# 9. Images must come from an approved registry
deny contains msg if {
	not image_from_approved_registry
	msg := sprintf("image '%s' is not from an approved registry", [input.deployment.image])
}

image_from_approved_registry if {
	some registry in input.approved_registries
	startswith(input.deployment.image, registry)
}

# 10. Image must have passed a vulnerability scan within the last 24h
deny contains msg if {
	input.scan_results.trivy.scanned_at_unix < (time.now_ns() / 1000000000) - 86400
	msg := "vulnerability scan is stale (>24h old); re-scan required before deploy"
}

# 11. No CRITICAL severity vulnerabilities allowed
deny contains msg if {
	input.scan_results.trivy.critical_count > 0
	msg := sprintf("%d CRITICAL vulnerabilities found by Trivy; deployment blocked", [input.scan_results.trivy.critical_count])
}

# 12. Gitleaks must report zero findings
deny contains msg if {
	input.scan_results.gitleaks.findings_count > 0
	msg := sprintf("gitleaks found %d potential secret(s) in the diff", [input.scan_results.gitleaks.findings_count])
}

# 13. Resource limits must be set (prevents noisy-neighbor / DoS risk)
deny contains msg if {
	not input.deployment.resources.limits.memory
	msg := "container has no memory limit set"
}

deny contains msg if {
	not input.deployment.resources.limits.cpu
	msg := "container has no cpu limit set"
}

# 14. Deployments to production require a passing ML risk score below threshold
deny contains msg if {
	input.environment == "production"
	input.ml_risk_score >= input.risk_threshold
	msg := sprintf("ML privacy-risk score %d exceeds threshold %d for production deploy", [input.ml_risk_score, input.risk_threshold])
}

# 15. Read-only root filesystem required in production
deny contains msg if {
	input.environment == "production"
	input.deployment.containerSecurityContext.readOnlyRootFilesystem != true
	msg := "production containers must set readOnlyRootFilesystem: true"
}
