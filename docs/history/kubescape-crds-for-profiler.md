# Kubescape CRDs and Profiler Integration Discussion

## Goal

Explore how Kubescape CRDs — particularly **NetworkNeighborhood** and **KnownServer** — can be used as inputs for an **application behavior profiler** that generates integration dependency profiles.

The profiler's goal is to derive application integration requirements from **observed runtime behavior**, and to enrich those observations with additional contextual information.

---

# Core Design Goal

The profiler should produce a **compact, near-real-time dataset describing integration dependencies**.

Key characteristics:

- Derived primarily from **observed runtime behavior**
- Continuously updated
- Enriched using **KnownServer** data
- Aggregated primarily by **container image:tag**
- Storage footprint limited to **~8MB or less**
- Supports **L3/L4 and L7** observations where available

---

# Kubescape CRDs of Interest

## NetworkNeighborhood

The `NetworkNeighborhood` CRD is produced by Kubescape's runtime sensor and describes observed network communication for workloads.

Key characteristics:

- Aggregated at the **workload level** (Deployment, StatefulSet, etc.)
- Observations stored **per container**
- Separate tracking for:
  - containers
  - initContainers
  - ephemeralContainers

Example structure:

```yaml
apiVersion: kubescape.io/v1
kind: NetworkNeighborhood
metadata:
  name: my-app-deployment
spec:
  containers:
    - name: app
      egress:
        - ipAddress: 10.96.12.34
          ports:
            - port: 5432
              protocol: TCP
      ingress:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: default
          podSelector:
            matchLabels:
              app: frontend
```

This provides **L3/L4 connectivity information** for each container in a workload.

---

# Image:Tag Profiling Strategy

The profiler will aggregate behavior by:

```
container image:tag
```

Reasoning:

- Multiple pods may use the same image
- Pods may contain multiple containers (sidecars)
- Image-level profiling creates reusable dependency profiles

### Mapping Process

1. Watch `NetworkNeighborhood` CRDs
2. Extract container-level traffic data
3. Resolve container name → image:tag from pod spec
4. Aggregate endpoints under image:tag

Example aggregation:

```
image:tag
  └─ observed endpoints
       ├─ internal workload targets
       └─ external endpoints
```

---

# Handling Sidecars and Init Containers

A key concern with image aggregation is **behavior contamination** from sidecars.

To avoid this, the dataset should retain an additional dimension:

```
image:tag + container role
```

Possible roles:

```
app
sidecar
init
ephemeral
```

Example key:

```
nginx:1.25 + app
envoy:1.29 + sidecar
```

This preserves useful distinctions while maintaining the primary image-based profiling model.

---

# Network Observation Types

## L3/L4 Data

Provided by `NetworkNeighborhood`:

- destination IP
- CIDR ranges
- ports
- protocol
- direction (ingress / egress)
- workload selectors

This will serve as the **authoritative source for network topology inside the cluster**.

---

## L7 Data

Desired but not guaranteed from Kubescape.

Potential sources:

- profiler eBPF sensors
- service mesh telemetry
- HTTP profiling tools

Example L7 metadata:

```
method
path
hostname
db operation
```

L7 data will likely be **merged into the same endpoint record** rather than coming directly from Kubescape CRDs.

---

# KnownServer CRD

The `KnownServer` CRD provides enrichment for external endpoints.

Example conceptual structure:

```yaml
apiVersion: kubescape.io/v1
kind: KnownServer
metadata:
  name: github
spec:
  server: github.com
  ipBlock:
    cidr: 140.82.112.0/20
```

Purpose:

- Map **CIDR ranges → meaningful server names**
- Provide **human readable identity** for external services
- Allow network policy generation tools to recognize known services

---

# KnownServer Usage in the Profiler

The profiler will use KnownServer objects to enrich observed external endpoints.

Example enrichment pipeline:

```
observed traffic
     ↓
destination IP
     ↓
match KnownServer CIDR
     ↓
attach service identity
```

Example result:

```
34.117.59.81:443
  → github.com
```

---

# KnownServer Scope

KnownServers may represent:

### External services

Examples:

- GitHub
- Stripe
- AWS APIs
- SaaS providers

### Internal services

Examples:

- shared logging clusters
- corporate APIs
- platform services

This allows the profiler to determine **external dependencies required to run the application**.

Example use case:

```
Profiler detects AWS S3 traffic
↓
KnownServer identifies S3
↓
Environment provisioning allocates S3 in new environment
```

---

# Endpoint Differentiation

In cases where the same IP serves multiple purposes, additional fields may be used:

```
IP
Port
Protocol
Path (L7)
Hostname
```

Kubescape's KnownServer schema only defines CIDR + name, so additional differentiation may need to occur inside the profiler itself.

---

# Completeness Semantics

Kubescape annotates NetworkNeighborhood resources with status fields such as:

```
kubescape.io/completion
kubescape.io/status
```

Example values:

```
complete
partial
```

Meaning:

- `complete` indicates sufficient observation data has been captured
- It does **not** mean observation has stopped

Profiler strategy:

- treat `complete` as **baseline readiness**
- continue streaming updates indefinitely

---

# Data Processing Model

Preferred architecture:

```
Kubescape CRDs
   │
   ▼
CRD Watcher / Aggregator
   │
   ▼
Profiler Dataset
   │
   ▼
Consumer systems
```

Data sources:

```
NetworkNeighborhood → traffic topology
KnownServer → endpoint identity
Profiler sensors → L7 metadata
```

---

# Aggregation Strategy

The aggregator should maintain an in-memory dataset:

```
image:tag(+role)
  └─ endpoints
        ├─ internal workloads
        └─ external services
```

Endpoint fields:

```
direction
ip
cidr
port
protocol
dns (optional)
knownServer identity
firstSeen
lastSeen
source
```

---

# Streaming Updates

The system should operate using **watch-based updates** rather than polling.

Flow:

```
watch CRDs
   ↓
process change
   ↓
update in-memory dataset
   ↓
emit compact snapshot
```

This provides **near real-time updates**.

---

# Data Size Constraints

The profiler should store **only aggregated endpoint sets**, not raw network events.

Strategies to keep storage small:

- Deduplicate endpoints
- Coalesce IPs into CIDRs where possible
- Track only metadata needed for dependency identification

Estimated dataset shape:

```
~100 images
~10 endpoints per image
≈ a few thousand records
```

Expected storage footprint:

```
< 8MB
```

---

# Cross-Cutting Design Decisions

## Scope

Resources will likely be **cluster-scoped**.

Rationale:

- observations span namespaces
- external endpoints are cluster-wide concepts

This can be revisited if multi-tenant isolation becomes necessary.

---

## Ground Truth Sources

Potential observation sources:

```
Kubescape runtime sensor
Profiler eBPF instrumentation
Service mesh telemetry
```

The exact precedence rules between them will be determined later.

---

## Latency Requirements

Target:

```
near real-time
```

Delays greater than a few minutes are considered problematic.

Streaming aggregation is therefore preferred.

---

# Key Design Outcome

The resulting dataset describes **application integration dependencies derived from observed behavior**.

Conceptually:

```
image:tag
   └─ dependency profile
         ├─ internal services
         └─ external services
```

This dataset can then be used to:

- generate infrastructure requirements
- allocate external services
- produce environment projections
- support dependency-aware deployments

---

# Summary

Kubescape CRDs provide a strong foundation for building a behavior-driven integration profiler.

Key takeaways:

- `NetworkNeighborhood` provides **container-level network observation**
- Profiles can be aggregated to **image:tag**
- `KnownServer` provides **CIDR → service identity enrichment**
- L7 information will likely come from **additional profiler sensors**
- The system should operate via **CRD watches and streaming aggregation**

The resulting profiler dataset will provide a **compact, continuously updated description of application integration dependencies derived entirely from observed runtime behavior**.