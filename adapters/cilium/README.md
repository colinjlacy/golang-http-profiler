# Cilium Network Policy Adapter

This adapter generates [Cilium Network Policies](https://docs.cilium.io/en/stable/network/kubernetes/policy/#ciliumnetworkpolicy) from ObservedBehaviors YAML files produced by the http-profiler.

## Overview

The adapter reads the `ObservedBehaviors` format (output from the http-profiler service map) and generates CiliumNetworkPolicy resources that enforce the observed network behaviors. It creates bidirectional policies with both ingress and egress rules, including:

- **Layer 3/4 rules**: Allow specific workloads to communicate on observed ports
- **Layer 7 HTTP rules**: Granular path and method matching for HTTP endpoints
- **Protocol-aware rules**: Port-based rules for databases, caches, and message buses

## Features

- **Bidirectional Policy Generation**: Creates both ingress and egress rules for each workload
- **Label-Based Selection**: Uses container labels to match endpoints (configurable via prefix matching)
- **Granular HTTP Rules**: Generates L7 rules with specific HTTP method and path combinations
- **Port Specifications**: Includes explicit port rules for non-HTTP protocols (PostgreSQL, Redis, NATS, etc.)
- **Flexible Output**: Choose between combined YAML file or separate files per workload
- **Deterministic Output**: Sorted keys ensure consistent policy generation across runs

## Installation

```bash
cd adapters/cilium
go mod download
go build -o cilium-adapter .
```

## Usage

### Basic Usage

Generate policies with default settings (separate files, `app.*` label prefix):

```bash
./cilium-adapter
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `INPUT_PATH` | `../../output/ebpf_service_map.yaml` | Path to ObservedBehaviors YAML file |
| `OUTPUT_PATH` | `./output` | Directory where policy files will be written |
| `OUTPUT_MODE` | `separate` | Output mode: `separate` (one file per workload) or `combined` (single multi-document YAML) |
| `LABEL_SELECTOR_PREFIXES` | `app.` | Comma-separated list of label prefixes to use for endpoint selectors |
| `INCLUDE_INFERRED` | `false` | Include policies for inferred workloads (databases, caches without direct profiling) |
| `NAMESPACE` | `default` | Kubernetes namespace (for future use) |

### Examples

**Generate policies using only `app.role` and `app.tier` labels:**

```bash
LABEL_SELECTOR_PREFIXES="app.role,app.tier" ./cilium-adapter
```

**Generate a single combined policy file:**

```bash
OUTPUT_MODE=combined ./cilium-adapter
```

**Use custom input and output paths:**

```bash
INPUT_PATH=/path/to/observed-behaviors.yaml \
OUTPUT_PATH=/path/to/policies \
./cilium-adapter
```

**Include all labels (no prefix filtering):**

```bash
LABEL_SELECTOR_PREFIXES="" ./cilium-adapter
```

## Output Structure

### Separate Files (Default)

When `OUTPUT_MODE=separate`, the adapter creates one YAML file per workload:

```
output/
├── http-service-policy.yaml
├── request-logger-policy.yaml
└── traffic-policy.yaml
```

Each file contains a single `CiliumNetworkPolicy` resource.

### Combined File

When `OUTPUT_MODE=combined`, the adapter creates a single multi-document YAML file:

```
output/
└── cilium-policies.yaml
```

The file contains all policies separated by `---` document markers.

## Policy Structure

Each generated policy includes:

### EndpointSelector

Matches workloads using labels with the configured prefix(es):

```yaml
endpointSelector:
  matchLabels:
    app.role: web-server
    app.tier: backend
    app.component: api
```

### Egress Rules

Allow outbound connections to observed destinations:

```yaml
egress:
  - toEndpoints:
      - matchLabels:
          app.role: cache
          app.tier: data
    toPorts:
      - ports:
          - port: "6379"
            protocol: TCP
```

### Ingress Rules

Allow inbound connections from observed sources:

```yaml
ingress:
  - fromEndpoints:
      - matchLabels:
          app.role: test-client
          app.tier: testing
    toPorts:
      - ports:
          - port: "8080"
            protocol: TCP
        rules:
          http:
            - method: GET
              path: /healthz
            - method: POST
              path: /echo
```

### Layer 7 HTTP Rules

For HTTP behaviors, the adapter generates granular L7 rules with method and path matching:

```yaml
toPorts:
  - ports:
      - port: "8080"
        protocol: TCP
    rules:
      http:
        - method: GET
          path: /
        - method: GET
          path: /healthz
        - method: POST
          path: /echo
        - method: GET
          path: /slow
```

This allows fine-grained control over which HTTP endpoints are allowed.

## Label Prefix Matching

The `LABEL_SELECTOR_PREFIXES` variable controls which container labels are used for endpoint selectors.

### How It Works

- **Prefix Matching**: Labels are included if their key starts with any of the specified prefixes
- **Multiple Prefixes**: Comma-separated list allows matching multiple label families
- **Empty String**: If set to empty (`""`), all labels are included

### Examples

**Match only `app.*` labels:**
```bash
LABEL_SELECTOR_PREFIXES="app."
# Matches: app.role, app.tier, app.component
# Excludes: com.docker.compose.*, nerdctl/*, io.containerd.*
```

**Match `app.*` and Docker Compose labels:**
```bash
LABEL_SELECTOR_PREFIXES="app.,com.docker.compose."
# Matches: app.role, com.docker.compose.service, com.docker.compose.project
# Excludes: nerdctl/*, io.containerd.*
```

**Use all labels:**
```bash
LABEL_SELECTOR_PREFIXES=""
# Includes all labels from the container runtime
```

## Applying Policies to Kubernetes

### Option 1: Apply Individual Files

```bash
kubectl apply -f output/http-service-policy.yaml
kubectl apply -f output/request-logger-policy.yaml
kubectl apply -f output/traffic-policy.yaml
```

### Option 2: Apply All at Once (Separate Files)

```bash
kubectl apply -f output/
```

### Option 3: Apply Combined File

```bash
kubectl apply -f output/cilium-policies.yaml
```

## Integration with http-profiler

### Step 1: Profile Your Services

Run the http-profiler to capture network behaviors:

```bash
sudo OUTPUT_PATH="./output/ebpf_http_profiler.log" \
     ENV_OUTPUT_PATH="./output/ebpf_env_profiler.yaml" \
     SERVICE_MAP_PATH="./output/ebpf_service_map.yaml" \
     CONTAINERD_SOCKET="$XDG_RUNTIME_DIR/containerd/containerd.sock" \
     ADI_PROFILE_ALLOWED="local,dev" \
     ./profiler
```

### Step 2: Generate Policies

```bash
cd adapters/cilium
./cilium-adapter
```

### Step 3: Review and Apply

```bash
# Review generated policies
cat output/*.yaml

# Apply to Kubernetes cluster with Cilium CNI
kubectl apply -f output/
```

## Limitations and Future Enhancements

### Current Limitations

1. **Inferred Workloads**: Currently skipped by default. When `INCLUDE_INFERRED=true` is supported in the future, basic policies will be generated for infrastructure services (databases, caches) that weren't directly profiled.

2. **External Destinations**: Workloads classified as "external" (outside the container runtime) only get egress rules from callers, no ingress policies.

3. **Port Inference**: HTTP behaviors without explicit port information default to port 80. Consider enhancing the profiler to capture actual destination ports.

4. **Protocol-Specific Rules**: Currently limited to HTTP L7 rules. Future versions could add protocol-aware rules for Redis, PostgreSQL, etc. (if Cilium supports them).

### Planned Enhancements

- [ ] Support for `CiliumClusterwideNetworkPolicy` (cluster-scoped policies)
- [ ] Policy validation and conflict detection
- [ ] Dry-run mode with policy preview
- [ ] Merge multiple ObservedBehaviors files from different environments
- [ ] Policy diff tool to compare observed vs deployed policies
- [ ] Integration with CI/CD pipelines for automated policy generation

## Troubleshooting

### No policies generated

**Issue**: Adapter completes but no policy files are created.

**Cause**: No workloads have labels matching the configured prefix.

**Solution**: 
- Check that your containers have labels with the expected prefix
- Use `LABEL_SELECTOR_PREFIXES=""` to include all labels
- Review the adapter logs for warnings about missing labels

### Policies too permissive

**Issue**: Generated policies allow more traffic than expected.

**Cause**: Using broad label prefixes that match many workloads.

**Solution**:
- Use more specific label prefixes (e.g., `app.role` instead of `app.`)
- Add more granular labels to your containers
- Review the ObservedBehaviors file to ensure accurate profiling

### HTTP rules not generated

**Issue**: Policies only have port rules, no L7 HTTP rules.

**Cause**: HTTP behaviors may not have `interface.http` facets populated.

**Solution**:
- Ensure the profiler is capturing HTTP traffic correctly
- Check that `ADI_PROFILE` is set on services generating HTTP traffic
- Review the ObservedBehaviors YAML to verify HTTP facets are present

## References

- [Cilium Network Policy Documentation](https://docs.cilium.io/en/stable/network/kubernetes/policy/#ciliumnetworkpolicy)
- [Cilium Policy Rules](https://docs.cilium.io/en/stable/security/policy/intro/#policy-rule)
- [ObservedBehaviors Schema](https://github.com/cncf/toc/issues/1797)
- [http-profiler Repository](../../README.md)
