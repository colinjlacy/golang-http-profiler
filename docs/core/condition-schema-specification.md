# Observed Condition Schema Specification (Draft)

## Status
Draft v0

## Purpose

This document defines a **standardized schema for describing application dependencies derived from observed runtime behavior**.

The schema is designed to be:

- **Automatically generated** from an ObservedBehavior dataset
- **Portable across environments and platforms**
- **Semantically structured enough for downstream adapters**
- **Independent of infrastructure implementation details**

The schema intentionally captures **only information that can be derived from observation**, not developer intent or platform implementation choices.

Human refinement may occur later, but the schema itself must be **fully generatable from observation data**.

---

# Design Principles

The schema follows several strict design constraints.

### 1. Observation-derived

Every field in the schema must be deterministically derivable from an ObservedBehavior dataset.

Examples of valid sources:

- network protocol detection
- HTTP request/response inspection
- TCP port detection
- endpoint interaction patterns
- behavioral classification

---

### 2. Capability-oriented

Dependencies are expressed as **capabilities required by the workload**, not as specific products or services.

Example:

```
datastore.relational
```

instead of

```
postgres
```

Observed implementation details are recorded separately.

---

### 3. Implementation-neutral

The schema must **not encode infrastructure choices**, such as:

- managed vs self-hosted
- cloud provider
- region
- storage size
- availability requirements

These belong to downstream platform control planes.

---

### 4. Evidence traceable

Each dependency must reference the ObservedBehavior evidence that produced it.

---

### 5. Workload-scoped

All dependency definitions exist **within the context of a workload**.

Each workload contains a set of resource dependencies discovered through runtime observation.

---

# High-Level Structure

The schema is defined under a `resources` field within a workload document.

```
resources:
  <dependency-name>:
    ...
```

Each entry represents a **single observed dependency relationship**.

---

# Resource Schema

Each resource entry describes a dependency detected between workloads or between a workload and an external capability.

```
resources:
  <resource-name>:
    type: <capability-type>
    id: <stable-identity>
    condition:
      ...
```

---

# Field Definitions

## `type`

### Description

Defines the **capability class required by the workload**.

This is a normalized classification derived from observed protocol behavior.

### Requirements

- MUST represent a **broad capability category**
- MUST NOT encode vendor or product names
- MUST be derivable from protocol classification

### Examples

```
service.http
datastore.relational
cache
```

### Derivation Rules

| Observed Behavior | Derived Type |
|---|---|
HTTP requests | `service.http` |
PostgreSQL protocol | `datastore.relational` |
Redis protocol | `cache` |

---

## `id`

### Description

A **stable identifier for the dependency target**.

This value allows the same dependency target to be referenced consistently across workloads.

### Requirements

- MUST be deterministically generated
- SHOULD be stable across repeated observation runs
- SHOULD represent the destination workload or service identity

### Examples

```
workload-postgres
workload-redis
workload-http-service
```

---

# Condition Block

The `condition` block contains the **observation-derived details of the dependency**.

```
condition:
  sourceWorkloadRef: <workload-id>
  destinationWorkloadRef: <workload-id | optional>
  evidenceRefs:
  observedAs:
  evidenceSummary:
```

---

# `sourceWorkloadRef`

### Description

The workload where the dependency originates.

### Requirements

- MUST reference the workload that initiated the observed behavior.

### Example

```
sourceWorkloadRef: workload:container/traffic
```

---

# `destinationWorkloadRef`

### Description

The workload that received the observed request or connection.

### Requirements

- SHOULD be included when the destination workload is known.
- MAY be omitted for external dependencies.

### Example

```
destinationWorkloadRef: workload:container/postgres
```

---

# `evidenceRefs`

### Description

References to ObservedBehavior records that justify the existence of the dependency.

### Requirements

- MUST contain at least one reference
- MUST refer to ObservedBehavior identifiers

### Example

```
evidenceRefs:
  - behavior:traffic:tcp:postgres:5432:postgres
```

---

# `observedAs`

### Description

Describes **how the dependency manifested during runtime observation**.

This block captures protocol and interface details that were directly detected.

```
observedAs:
  protocol:
  category:
  network:
  interface:
```

---

## `observedAs.protocol`

### Description

The protocol detected in the observed traffic.

### Examples

```
http
postgres
redis
```

---

## `observedAs.category`

### Description

The high-level classification detected during observation.

### Examples

```
database
cache
```

---

## `observedAs.network`

### Description

Network transport details detected from observation.

```
network:
  transport:
  port:
```

### Fields

| Field | Description |
|---|---|
transport | Network transport protocol |
port | Observed destination port |

### Example

```
network:
  transport: tcp
  port: 5432
```

---

# `observedAs.interface`

### Description

A typed description of the **observed application-level interface**.

This field is protocol-specific.

---

## HTTP Interface

```
interface:
  http:
    operations:
      - method:
        path:
        requestSchema:
        responseSchema:
```

### Fields

| Field | Description |
|---|---|
method | HTTP method |
path | observed path |
requestSchema | observed request body schema |
responseSchema | observed response schema |

### Example

```
interface:
  http:
    operations:
      - method: GET
        path: /healthz
        requestSchema: null
        responseSchema:
          status: string
          time: string
```

---

## Datastore Interface

```
interface:
  datastore:
    protocol:
    transport:
    port:
```

### Example

```
interface:
  datastore:
    protocol: postgres
    transport: tcp
    port: 5432
```

---

## Cache Interface

```
interface:
  cache:
    protocol:
    transport:
    port:
```

### Example

```
interface:
  cache:
    protocol: redis
    transport: tcp
    port: 6379
```

---

# `evidenceSummary`

### Description

A summary of the observed behavioral evidence.

```
evidenceSummary:
  firstSeen:
  lastSeen:
  totalCount:
  observerConfidence:
```

### Fields

| Field | Description |
|---|---|
firstSeen | timestamp of first observation |
lastSeen | timestamp of last observation |
totalCount | number of observed interactions |
observerConfidence | detection confidence |

### Example

```
evidenceSummary:
  firstSeen: "2026-03-14T15:48:40.14442744-04:00"
  lastSeen: "2026-03-14T15:48:40.14442744-04:00"
  totalCount: 1
  observerConfidence: 1
```

---

# Example Resource Definition

```
resources:
  primary-db:
    type: datastore.relational
    id: workload-postgres
    condition:
      sourceWorkloadRef: workload:container/traffic
      destinationWorkloadRef: workload:container/postgres
      evidenceRefs:
        - behavior:traffic:tcp:postgres:5432:postgres
      observedAs:
        protocol: postgres
        category: database
        network:
          transport: tcp
          port: 5432
        interface:
          datastore:
            protocol: postgres
            transport: tcp
            port: 5432
      evidenceSummary:
        firstSeen: "2026-03-14T15:48:40.14442744-04:00"
        lastSeen: "2026-03-14T15:48:40.14442744-04:00"
        totalCount: 1
        observerConfidence: 1
```

---

# Summary

This schema standardizes a **portable representation of observed application dependencies**.

It provides:

- a normalized capability classification
- protocol-specific interface descriptions
- traceable evidence lineage
- deterministic generation from observation

The schema deliberately excludes infrastructure intent, platform preferences, and binding outputs.

These concerns are handled by downstream control planes and provisioning systems.