#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST_DIR="$(cd "${SCRIPT_DIR}/../manifests" && pwd)"

printf '[runtimeconditions] publishing breaking API catalog bundle\n'
kubectl apply -f "${MANIFEST_DIR}/catalog/todos-api-catalog-breaking.yaml"

printf '[runtimeconditions] submitting a RuntimeWorkload expected to fail contract validation\n'
kubectl apply -f "${MANIFEST_DIR}/apps/request-logger-breaking-runtimeworkload.yaml"
set +e
kubectl -n demo wait runtimeworkload/request-logger-breaking \
  --for=condition=ConfigureWorkflowCompleted \
  --timeout=120s
WAIT_STATUS=$?
set -e

if [[ "${WAIT_STATUS}" -eq 0 ]]; then
  printf '[runtimeconditions] breaking OpenAPI deployment unexpectedly succeeded\n' >&2
  exit 1
fi

printf '[runtimeconditions] RuntimeWorkload failed as expected. Recent workflow logs:\n'
kubectl -n demo get pods -l kratix.io/promise-name=runtime-workload || true
for pod in $(kubectl -n demo get pods -l kratix.io/promise-name=runtime-workload -o name 2>/dev/null | tail -n 3); do
  printf '[runtimeconditions] logs for %s\n' "${pod}"
  kubectl -n demo logs "${pod}" --all-containers=true --tail=120 || true
done

printf '[runtimeconditions] restoring compatible API catalog bundle\n'
kubectl apply -f "${MANIFEST_DIR}/catalog/todos-api-catalog.yaml"

printf '[runtimeconditions] breaking change demo completed\n'
