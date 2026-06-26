#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST_DIR="$(cd "${SCRIPT_DIR}/../manifests" && pwd)"

printf '[runtimeconditions] submitting RuntimeWorkload request through Kratix\n'
kubectl apply -f "${MANIFEST_DIR}/apps/request-logger-runtimeworkload.yaml"

printf '[runtimeconditions] waiting for RuntimeWorkload configure workflow\n'
kubectl -n demo wait runtimeworkload/request-logger \
  --for=condition=ConfigureWorkflowCompleted \
  --timeout=180s

printf '[runtimeconditions] waiting for generated Redis request\n'
kubectl -n demo wait redis/request-logger-cache \
  --for=create \
  --timeout=180s

kubectl -n demo wait redis/request-logger-cache \
  --for=condition=ConfigureWorkflowCompleted \
  --timeout=180s

printf '[runtimeconditions] waiting for generated application Deployment\n'
kubectl -n demo rollout status deployment/request-logger --timeout=240s

kubectl -n demo get runtimeworkload request-logger
kubectl -n demo get redis request-logger-cache
kubectl -n demo get deployment request-logger
