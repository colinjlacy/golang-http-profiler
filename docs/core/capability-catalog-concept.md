# The Concept of a CapabilityCatalog

## Context

The specification defines a portable description of **application integration dependencies** derived from observed runtime behavior.

These dependencies are expressed as **Conditions**.

Examples of Conditions might describe that a workload requires:

- an HTTP service dependency
- a relational datastore
- a Redis cache
- outbound HTTPS connectivity

However, the specification intentionally **does not define how those dependencies are fulfilled**.

Provisioning infrastructure, selecting cloud services, and binding resources to workloads are responsibilities of the **platform layer**, not the application behavior specification.

This separation leads to the concept of a **CapabilityCatalog**.

---

# The Core Idea

A **CapabilityCatalog** represents the platform’s supply-side view of available capabilities.

It answers the question:

> *Given an application requirement, how can the platform satisfy it?*

While Conditions describe **what the application needs**, the CapabilityCatalog describes **what the platform can provide**.

---

# Demand vs Supply

The relationship can be viewed as:

| Layer | Responsibility |
|------|------|
| **Application Behavior Spec** | Describe application requirements |
| **CapabilityCatalog** | Describe platform capabilities |
| **Platform Engine** | Bind requirements to capabilities |

```
Application Behavior
      │
      ▼
  Conditions
      │
      ▼
Capability Matching
      │
      ▼
Platform Provisioning
```

---

# Example

### Condition produced by observation

```
type: datastore.relational
condition:
  observedAs:
    protocol: postgres
    port: 5432
```

This expresses a requirement:

> "This workload needs a relational datastore compatible with PostgreSQL."

The Condition intentionally **does not specify**:

- AWS RDS
- Azure Database for PostgreSQL
- Cloud SQL
- a Kubernetes operator
- a local dev container

Those decisions belong to the platform.

---

### CapabilityCatalog entry (conceptual)

A platform might define capabilities such as:

```
capability: relational-database

implementations:
  - AWS RDS Postgres
  - Azure PostgreSQL Flexible Server
  - CloudSQL Postgres
  - Kubernetes Postgres Operator
```

The platform then decides which implementation to bind.

---

# Why This Is Not Part of the Spec

The specification intentionally **does not define the CapabilityCatalog**.

There are several reasons for this:

### Platforms differ dramatically

Different environments have radically different provisioning models:

- Kubernetes operators
- Crossplane
- Terraform
- Radius
- Kratix
- internal PaaS systems
- cloud-native managed services

Trying to standardize a universal catalog would be extremely difficult.

---

### Platforms already solve this problem

Many platform engineering systems already maintain internal catalogs of capabilities.

Examples include:

- **Crossplane compositions**
- **Radius resource types**
- **Kratix promises**
- **Terraform modules**
- **Internal platform service catalogs**

Rather than replacing these systems, the specification aims to **integrate with them**.

---

# How the CapabilityCatalog Fits Into the Architecture

The conceptual architecture looks like this:

```
ObservedBehavior
        │
        ▼
     Condition
        │
        ▼
Capability Matching (Platform Layer)
        │
        ▼
Infrastructure Provisioning
```

The platform layer may use any system capable of matching requirements to resources.

Possible implementations include:

- Crossplane
- Radius
- Kratix
- Terraform
- internal platform controllers

---

# Analogy

A useful analogy for platform engineers:

| Concept | Analogy |
|------|------|
| **Condition** | An application's dependency declaration |
| **CapabilityCatalog** | The platform’s service catalog |
| **Platform Engine** | The system that provisions services |

In other words:

```
Conditions = demand
Capabilities = supply
Platform = marketplace
```

---

# What This Enables

Separating Conditions from capability catalogs enables:

### Platform portability

The same application dependency description can be used in:

- AWS
- Azure
- on-prem Kubernetes
- local developer environments

---

### Platform flexibility

Platform teams can change infrastructure implementations without changing application specifications.

Example:

```
datastore.relational
```

could be fulfilled by:

- AWS RDS today
- Aurora tomorrow
- a Kubernetes operator in development environments

---

### Clear separation of concerns

| Role | Responsibility |
|------|------|
| Application teams | Define application behavior |
| Observation engines | Detect runtime dependencies |
| Behavior spec | Standardize dependency description |
| Platform teams | Define capability catalogs |
| Platform systems | Provision infrastructure |

---

# Key Takeaway

The CapabilityCatalog is not a new system or resource type.

It is a **conceptual interface between application requirements and platform capabilities**.

The specification defines the **requirements side** (Conditions).

Platform systems are responsible for implementing the **capability side**.

This allows the behavior specification to remain:

- portable
- implementation-neutral
- platform-agnostic

while still enabling automated infrastructure provisioning.