#!/usr/bin/env bash
# scripts/validate_k8s_schemas.sh
#
# Validates every K8s manifest in k8s/base/ against REAL Kubernetes OpenAPI
# schemas using kubeconform — a stronger check than the hand-written
# structural tests in tests/k8s_validation/, because it validates against
# the actual API definitions rather than rules this project's own authors
# thought to write.
#
# Install kubeconform (no cluster required):
#   curl -sL -o kubeconform.tar.gz \
#     https://github.com/yannh/kubeconform/releases/download/v0.6.7/kubeconform-linux-amd64.tar.gz
#   tar xzf kubeconform.tar.gz kubeconform && chmod +x kubeconform
#
# Usage:
#   ./kubeconform -summary -verbose k8s/base/*.yaml
#
# Last verified run (2026-07-30): 26 resources found in 12 files,
# 25 valid, 0 invalid, 1 error (kustomization.yaml has no K8s schema —
# expected, it's a Kustomize file, not a K8s API object).
set -euo pipefail

if ! command -v kubeconform &> /dev/null; then
  echo "kubeconform not found. See install instructions in this script's header."
  exit 1
fi

kubeconform -summary -verbose k8s/base/*.yaml
