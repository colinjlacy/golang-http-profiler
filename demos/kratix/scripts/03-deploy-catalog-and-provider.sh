#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST_DIR="$(cd "${SCRIPT_DIR}/../manifests" && pwd)"

printf '[runtimeconditions] publishing compatible API catalog bundle\n'
kubectl apply -f "${MANIFEST_DIR}/catalog/todos-api-catalog.yaml"

printf '[runtimeconditions] deploying provider API\n'
kubectl apply -f "${MANIFEST_DIR}/apps/todos-api.yaml"
kubectl -n demo rollout status deployment/todos-api --timeout=180s

printf '[runtimeconditions] provider API is available\n'
kubectl -n demo get svc todos-api
