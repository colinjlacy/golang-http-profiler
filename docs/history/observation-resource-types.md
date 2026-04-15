# Application Integration Behavior Model  
## Object Catalog Reference

This document describes the canonical object types used in the **Behavior-Derived Integration Portability Model**.

The goal of these objects is to enable a pipeline that moves from **observed runtime behavior** to **portable runtime success across environments**.

The high-level lifecycle is:

Observed Behaviors → Derived Conditions → Environment Projections → Assertions → Generated Artifacts

Each object described below appears as a YAML resource and serves a specific role in that lifecycle.

---

# Object Catalog Overview

| Object | Produced By | Purpose |
|------|-------------|--------|
| ObservationEngine | Observer implementation | Describes a behavior observation engine |
| ObservationSet | Observers | Collection of behaviors captured during a run |
| WorkloadCatalog | Observers | Normalized identities for workloads |
| ObservedBehavior | Observers | Atomic runtime interaction record |
| ConditionSet | Core tooling | Portable runtime conditions derived from behaviors |
| Condition | Core tooling | Individual runtime condition |
| EnvironmentProjection | Platform team / automation | Target environment declaration |
| BindingSet | Platform team / automation | Concrete wiring of conditions to implementations |
| CapabilityCatalog | Platform team | Logical platform capability definitions |
| CapabilityBinding | Platform team | Mapping between behaviors/conditions and capabilities |
| AssertionSet | Core tooling | Checks derived from conditions + projections |
| Assertion | Core tooling | Individual verification rule |
| AssertionResult | CI / runtime checks | Outcome of executing assertions |
| NetworkPolicyBundle | Adapter | Generated network policies |
| MockBundle | Adapter | Generated service mocks |
| ResourceBundle | Adapter | Generated infrastructure resources |
| ProviderResolver | External adopter | Plugin enriching behaviors with provider semantics |
| SchemaBundle | Project maintainers | Machine-readable schema definitions |

---

# 1. ObservationEngine

## Purpose

An **ObservationEngine** describes a runtime system capable of detecting behaviors.

Examples include:

- eBPF observers
- Kubescape NetworkNeighborhood collectors
- service mesh telemetry
- API gateway logs
- cloud audit logs

The object provides metadata about the capabilities and limitations of the engine.

## Why this object exists

Multiple observation engines may contribute evidence to the same behavior record.  
Explicitly modeling the engine enables:

- provenance tracking
- signal confidence weighting
- multi-observer correlation
- compatibility negotiation

## Key fields

- name  
- type (ebpf, flow collector, mesh telemetry, etc.)
- version
- capabilities (what kinds of behaviors it can detect)
- limitations (what it cannot observe)

---

# 2. ObservationSet

## Purpose

An **ObservationSet** represents the results of a single observation run.

It contains:

- metadata about the capture window
- participating observation engines
- the workloads discovered
- the behaviors observed

ObservationSets are environment-scoped (dev, stage, local, etc).

## Why this object exists

ObservationSets allow:

- comparison of behavior across environments
- merging of multiple observation runs
- tracking freshness of captured data
- auditability of how behavior data was collected

## Key fields

- generatedAt
- environment
- observationEngines
- workloads
- behaviors

---

# 3. WorkloadCatalog

## Purpose

The **WorkloadCatalog** provides stable identities for workloads observed in the system.

Each workload corresponds to a unit of execution such as:

- Docker container
- Kubernetes workload
- serverless function
- process

## Why this object exists

Observers often produce ephemeral identifiers such as:

- container IDs
- pod names
- dynamic service names

The WorkloadCatalog normalizes these into stable identities.

This enables:

- deduplication across observation runs
- correlation across multiple observers
- stable references from behaviors

## Key fields

- workload id
- display name
- workload selectors (optional)
- software identity (image, binary, etc.)
- evidence timestamps

---

# 4. ObservedBehavior

## Purpose

An **ObservedBehavior** is the atomic unit of runtime evidence.

It represents a real interaction between a source workload and a destination.

Examples include:

- HTTP request
- database connection
- message bus subscription
- cache query

## Structure

An ObservedBehavior contains:

- source identity
- destination identity
- protocol information
- optional interface description
- optional network attributes
- evidence describing how the behavior was observed

## Why this object exists

ObservedBehavior records are the **ground truth** of the system.

Everything else in the model (conditions, projections, assertions) is derived from them.

## Key fields

- behavior id
- sourceRef
- destination
- facets (protocol, network, interface, etc.)
- evidence (firstSeen, lastSeen, count, observer attribution)

---

# 5. ConditionSet

## Purpose

A **ConditionSet** contains portable runtime conditions derived from observed behaviors.

Conditions describe **what must be true for the application to function**, independent of environment.

Examples include:

- relational database with MySQL semantics must exist
- HTTP API implementing a specific contract must be reachable
- object storage with S3 semantics must be available

## Why this object exists

Observed behaviors contain environment-specific details such as:

- container names
- ports
- local infrastructure

Conditions extract the **portable meaning** of those behaviors.

## Key fields

- condition set id
- referenced observations
- list of conditions

---

# 6. Condition

## Purpose

A **Condition** represents a single runtime requirement derived from observed behavior.

Conditions are portable and environment-neutral.

## Examples

- relational database requirement
- message bus availability
- HTTP service contract

## Key fields

- condition id
- subject workload
- condition type
- protocol or interface requirements
- supporting behaviors

---

# 7. EnvironmentProjection

## Purpose

An **EnvironmentProjection** describes a target runtime environment.

It specifies how derived conditions should be satisfied within a specific platform or cloud.

Examples include:

- AWS production environment
- Kubernetes development cluster
- on-prem platform deployment

## Why this object exists

The same application may run in multiple environments.

EnvironmentProjection allows the system to define **how conditions should be satisfied** in each environment.

## Key fields

- projection name
- target platform
- region or cluster
- provider preferences
- environment metadata

---

# 8. BindingSet

## Purpose

A **BindingSet** maps conditions to concrete implementations in a projection.

This is the wiring layer between portable requirements and real infrastructure.

## Examples

- mapping relational database condition to AWS RDS
- mapping object storage condition to S3
- mapping message bus condition to NATS cluster

## Key fields

- projection reference
- list of condition bindings
- provider resource references

---

# 9. CapabilityCatalog

## Purpose

Defines logical platform capabilities.

Capabilities represent reusable services provided by a platform team.

Examples include:

- relational database
- email service
- identity provider
- message bus

## Why this object exists

Some environments introduce an abstraction layer between applications and infrastructure.

The CapabilityCatalog allows these abstractions to be modeled explicitly.

## Key fields

- capability id
- capability description
- optional interface definitions
- ownership metadata

---

# 10. CapabilityBinding

## Purpose

Associates behaviors or conditions with platform capabilities.

For example, an application that sends email through SendGrid might instead bind to a platform capability called `email-service`.

## Key fields

- capability reference
- matching rules
- scope of application

---

# 11. AssertionSet

## Purpose

An **AssertionSet** contains validation checks derived from conditions and projections.

These assertions verify that runtime success conditions are satisfied.

Assertions can be used during:

- CI/CD pipelines
- environment validation
- runtime health checks

## Key fields

- projection reference
- list of assertions
- severity levels

---

# 12. Assertion

## Purpose

An **Assertion** is a single validation rule.

Assertions may verify:

- connectivity
- contract compatibility
- policy correctness
- resource existence

## Key fields

- assertion id
- assertion type
- validation target
- evaluation logic

---

# 13. AssertionResult

## Purpose

Captures the results of executing assertions.

AssertionResults allow systems to determine whether an environment projection is valid.

## Key fields

- assertion reference
- pass/fail result
- evidence or logs
- timestamp

---

# 14. NetworkPolicyBundle

## Purpose

Generated Kubernetes or Cilium network policies derived from behaviors.

These policies restrict network traffic to only the connections required by the application.

---

# 15. MockBundle

## Purpose

Generated service mocks used during testing and development.

Mocks may be produced from observed HTTP interfaces or API contracts.

Tools such as Microcks may consume this bundle.

---

# 16. ResourceBundle

## Purpose

Generated infrastructure resources.

These may include definitions for:

- Terraform
- Radius
- Score
- Crossplane
- CloudFormation

The bundle describes the infrastructure required to satisfy derived conditions.

---

# 17. ProviderResolver

## Purpose

A plugin responsible for enriching behaviors with provider-specific semantics.

For example, resolving an RDS endpoint into an AWS ARN.

ProviderResolvers allow external ecosystems to extend the model.

---

# 18. SchemaBundle

## Purpose

Provides machine-readable schema definitions for all canonical objects.

SchemaBundles enable:

- validation
- code generation
- API compatibility checks
- ecosystem tooling

---

# Closing Notes

The object catalog intentionally separates:

- **observed evidence**
- **portable conditions**
- **target environment declarations**
- **validation checks**
- **generated artifacts**

This separation enables portability, extensibility, and multi-observer collaboration across platforms and cloud providers.