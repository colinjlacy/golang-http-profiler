# Runtime Conditions Profile Specification (Draft v0.1)

## Status

**Draft v0.1 — Working Specification**

This document defines the **Runtime Conditions Profile**, a portable, declarative specification describing the externally satisfied runtime dependencies required by an application workload.

This specification also defines:

- The **core Condition model**
- The **core kind-to-interface validity matrix**
- A **declarative extension model** for vendor-defined integrations
- Validation responsibilities and compatibility rules

---

# 1. Purpose

The Runtime Conditions Profile provides a **portable declaration of required external runtime capabilities** needed for an application workload to function successfully.

These capabilities may include:

- HTTP services
- Relational databases
- Caches
- Message buses
- Vendor-defined integration services

The Runtime Conditions Profile:

- **SHOULD be generated automatically when possible**
- **MAY be authored manually when automated generation is not feasible**
- **MUST remain valid regardless of generation method**
- **MUST remain implementation-neutral**
- **MUST remain infrastructure-agnostic**

The profile defines **requirements**, not implementations.

---

# 2. Scope

This specification defines a portable format for describing the external capabilities that an application workload depends on in order to function properly. These dependencies represent integrations with services that exist outside the workload itself, such as HTTP APIs, databases, caches, and message systems.

The Runtime Conditions Profile models each dependency as an independent  requirement that describes the expected interface characteristics needed to interact with an external system. The specification focuses on describing what capabilities must be present, without describing how those capabilities are implemented or fulfilled.

This specification is limited to externally satisfied integrations and does not attempt to describe internal execution behavior, infrastructure configuration, deployment topology, or platform-specific provisioning. It also does not require or depend on any upstream observation system, although such systems may be used to generate Runtime Conditions Profiles.

---

# 3. Core Design Principles

## 3.1 Declarative

Profiles MUST be declarative documents describing what is required, not how to fulfill it.

A Runtime Conditions Profile MUST be associated with a uniquely identifiable
workload and SHOULD correspond to a specific version of that workload. The profile version SHOULD align with the workload version.

A Runtime Conditions Profile MUST describe exactly one workload identity
and MUST NOT represent multiple unrelated workloads within a single profile.

## 3.2 Portable

Profiles SHOULD be portable across environments and platforms when expressed using only core specification vocabulary.

Profiles that use extension-defined vocabulary MAY introduce platform-specific or vendor-specific semantics. Such profiles remain portable to the extent that the required extensions are available.

## 3.3 Implementation-Neutral

Profiles MUST describe required capabilities without prescribing how those capabilities are implemented or provisioned.

Core specification vocabulary MUST remain vendor-neutral and MUST NOT encode assumptions about specific infrastructure implementations.

Vendor-specific or platform-specific identifiers MAY be used only when introduced through declared extensions.

Profiles MUST NOT encode:

- Infrastructure configuration details
- Deployment topology
- Resource sizing
- Geographic placement
- Provider-specific provisioning instructions

## 3.4 Extensible

Profiles MAY include extension-defined vocabulary to describe capabilities beyond those defined in the core specification.

Profiles that use extension-defined vocabulary MUST identify the extensions on which that vocabulary depends.

Use of extensions MUST NOT alter or redefine the meaning of core specification vocabulary.

## 3.5 Deterministically Validatable

Profiles MUST adhere to the structural and semantic validation rules defined by the core specification.

Profiles that reference extension-defined vocabulary MUST also adhere to the validation rules defined by those extensions.

---

# 4. Runtime Conditions Profile Structure

A Runtime Conditions Profile defines a collection of independent runtime Conditions.

Examples in this specification are expressed using YAML for readability. The data model defined by this specification is serialization-neutral and MAY be represented using YAML, JSON, or other compatible formats.

## Top-Level Structure

```yaml
## Top-Level Structure

apiVersion: runtimeconditions.io/v1alpha1
kind: RuntimeConditionsProfile

metadata:
  name: example-profile

workload:
  uri: https://github.com/example-org/example-service
  version: v1.2.3

extensions:
  - core
  - aws.runtime/v1alpha1

conditions:
  - name: primary-db
    kind: datastore.relational
    interface:
      datastore:
        protocol: postgres

  - name: payments-api
    kind: service.http
    interface:
      http:
        protocol: https
        operations:
          - method: POST
            path: /charge
```

---

# 5. Condition Model

Each Condition represents an **independent required runtime dependency**.

## Condition Fields

| Field | Required | Description |
|------|----------|-------------|
| `kind` | YES | Required capability classification |
| `interface` | YES | Interface definition required for matching |
| `name` | NO | Unique identifier within profile |

IF a `name` is applied to a Condition, then the `name` MUST be unique within the profile.
---

# 6. Core Condition Kinds

The core specification defines a set of **capability classes**, referred to as
**Kinds**, that represent common categories of externally satisfied
runtime dependencies.

Each Condition MUST declare exactly one `kind`.

Kinds represent **broad capability families**, not specific technologies.

The following core kinds are defined:

- `service` — External service integrations such as APIs
- `datastore` — Persistent data storage systems
- `cache` — Volatile data storage optimized for fast access
- `message_bus` — Messaging and event distribution systems

These kinds are intentionally broad to allow multiple interaction models
to exist within the same capability family.

---

# 7. Interface Model

Each Condition MUST define an `interface` block describing how the workload
interacts with the declared capability.

The `interface` block defines:

- The **interaction model**
- The **matching characteristics**
- Any **additional details required for fulfillment matching**

## Interface Structure

```yaml
interface:
  type: <interface-type>
```

The `type` field identifies the interaction model associated with the
declared `kind`.

Additional fields MAY be required depending on the selected interface type.

Interface definitions are validated based on:

- The declared `kind`
- The declared `interface.type`
- Core validation rules
- Extension validation rules (when applicable)

---

# 8. Core Interface Types

This section describes the **structure and purpose** of core interface
types. Allowed interface types are validated separately in the
validation section.

---

## 8.1 Service Interface

Service interfaces describe callable external services such as APIs.

Service interfaces typically define:

- Request methods
- Request paths
- Optional request schemas
- Optional response schemas

Example:

```yaml
kind: service

interface:
  type: http
  operations:
    - method: POST
      path: /charge
      requestBodySchema: {}
      responseSchema: {}
```

### Operation Fields

| Field | Required | Description |
|------|----------|-------------|
| `method` | YES | HTTP method |
| `path` | YES | Request path |
| `requestBodySchema` | NO | Request body schema |
| `responseSchema` | NO | Response schema |

### Validation Expectations

- `operations` MUST be non-empty
- `method` MUST be a valid HTTP method
- `path` MUST be a non-empty string
- Schema fields remain open-ended

---

## 8.2 Datastore Interface

Datastore interfaces describe persistent storage systems.

Datastore interfaces identify the storage model used by the workload.

Example:

```yaml
kind: datastore

interface:
  type: relational
```

Additional optional fields MAY be defined by extensions.

---

## 8.3 Cache Interface

Cache interfaces describe volatile key/value storage systems.

Example:

```yaml
kind: cache

interface:
  type: redis
```

---

## 8.4 Message Bus Interface

Message bus interfaces describe messaging or event systems.

Example:

```yaml
kind: message_bus

interface:
  type: kafka
```

---

# 9. Core Validation Rules

Validation ensures that Conditions are structurally correct and
semantically consistent.

Validation occurs in multiple phases.

---

## 9.1 Structural Validation

A Condition is invalid if:

- `kind` is missing
- `interface` is missing
- `interface.type` is missing

If a `name` field is provided, it MUST be unique within the profile.

---

## 9.2 Kind-to-Interface Type Validation

Each `kind` supports a defined set of valid `interface.type` values.

The following interface types are valid for core kinds:

### Service

Allowed interface types:

- `http`

Additional validation rules:

- `operations` MUST be present
- `operations` MUST NOT be empty

Allowed HTTP Methods:

- GET  
- HEAD  
- POST  
- PUT  
- PATCH  
- DELETE  
- OPTIONS  
- TRACE  

---

### Datastore

Allowed interface types:

- `relational`
- `document`

---

### Cache

Allowed interface types:

- `redis`
- `memcached`

---

### Message Bus

Allowed interface types:

- `nats`
- `kafka`
- `amqp`
- `mqtt`

---

## 9.3 Invalid Condition Examples

Invalid relational datastore example:

```yaml
kind: datastore

interface:
  type: mongodb
```

Invalid interface type for cache:

```yaml
kind: cache

interface:
  type: relational
```

Invalid service definition:

```yaml
kind: service

interface:
  type: http
  operations: []
```

---

# 10. Extension Model

The Runtime Conditions Profile supports extension-defined vocabulary.

Extensions allow:

- New kinds
- New interface types
- New interface fields
- Additional validation rules

Extensions MUST NOT redefine core semantics incompatibly.

---

# 11. Extension Declaration

Profiles that reference extension-defined vocabulary MUST declare
those extensions.

```yaml
extensions:
  - core
  - aws.runtime/v1alpha1
  - redis.compat/v1
```

---

# 12. Extension Definition Structure

Extensions are defined as independent artifacts.

```yaml
apiVersion: runtimeconditions.io/v1alpha1
kind: ValidationExtensionDefinition

metadata:
  name: aws.runtime
  version: v1alpha1

spec:

  kinds:
    - name: aws.object_store

  interfaceTypes:
    - name: object_store

  typeExtensions:
    - targetKind: cache
      addTypes:
        - valkey

  validationRules:
    - id: cache-valkey
      appliesToKind: cache
      rule: type in ["redis","memcached","valkey"]
```

---

# 13. Extension Capabilities

Extensions MAY:

| Action | Description |
|-------|-------------|
| Add Kind | Introduce new namespaced kind |
| Add Interface Type | Define new interface types |
| Add Fields | Extend interface schema |
| Add Rules | Add semantic validation |

---

# 14. Extension Compatibility Rules

Extensions MUST:

- Use namespaced identifiers
- Preserve core semantics
- Not redefine core kinds incompatibly
- Not invalidate core-valid documents

---

# 15. Namespacing Requirements

Vendor-defined elements MUST use namespaced identifiers.

Examples:

```yaml
aws.object_store
aws.s3
redis.valkey
acme.streaming_bus
```

---

# 16. Unknown Extension Handling

If a referenced extension cannot be resolved:

- The profile MUST be marked unresolved
- Conditions referencing unknown types MUST be invalid

---

# 17. Validation Layers

Validation occurs in the following order:

1. Core structural validation
2. Core semantic validation
3. Extension resolution
4. Extension validation

---

# 18. Example: Core-Only Profile

```yaml
apiVersion: runtimeconditions.io/v1alpha1
kind: RuntimeConditionsProfile

metadata:
  name: checkout-service

workload:
  uri: https://github.com/example-org/checkout-service
  version: v1.2.3

extensions:
  - core

conditions:

  - name: primary-db
    kind: datastore
    interface:
      type: relational

  - name: session-cache
    kind: cache
    interface:
      type: redis

  - name: payments-api
    kind: service
    interface:
      type: http
      operations:
        - method: POST
          path: /charge
```

---

# 19. Example: AWS Extension Profile

```yaml
apiVersion: runtimeconditions.io/v1alpha1
kind: RuntimeConditionsProfile

metadata:
  name: storage-enabled

workload:
  uri: https://github.com/example-org/storage-service
  version: v1.4.0

extensions:
  - core
  - aws.runtime/v1alpha1

conditions:

  - name: object-storage
    kind: aws.object_store
    interface:
      type: object_store
```

---

# 20. Future Considerations

Possible future extensions include:

- GraphQL service interfaces
- Authentication hints
- TLS requirements
- Data durability requirements
- Queue/topic semantics
- Retry and timeout expectations

These are intentionally excluded from v0.1.

---

# 21. Summary

The Runtime Conditions Profile defines:

- A portable dependency declaration format
- A structured interface typing model
- Deterministic validation behavior
- A declarative extension mechanism
- Vendor-neutral semantics

This provides a foundation for reliable downstream capability
matching while preserving ecosystem flexibility.