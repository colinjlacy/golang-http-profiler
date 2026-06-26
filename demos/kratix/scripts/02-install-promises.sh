#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST_DIR="$(cd "${SCRIPT_DIR}/../manifests" && pwd)"

printf '[runtimeconditions] installing Redis Promise\n'
kubectl apply -f "${MANIFEST_DIR}/promises/redis.yaml"
kubectl wait --for=condition=Established crd/redis.platform.demoteam.io --timeout=120s

printf '[runtimeconditions] installing RuntimeWorkload Promise\n'
kubectl apply -f "${MANIFEST_DIR}/promises/runtime-workload.yaml"
kubectl wait --for=condition=Established crd/runtimeworkloads.platform.demoteam.io --timeout=120s

printf '[runtimeconditions] platform Promises are installed\n'
kubectl get crds -l kratix.io/promise-name
