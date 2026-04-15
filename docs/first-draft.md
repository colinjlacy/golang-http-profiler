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

The following Condition kinds are defined in the **core specification**.

| Kind | Interface | Allowed subtype / protocol values |
|------|-----------|-----------------------------------|
| `service` | `http` | protocols: `http`, `https` |
| `datastore` | `datastore` | types: `relational`, `document` |
| `cache` | `cache` | protocols: `redis`, `memcached` |
| `message_bus` | `messageBus` | protocols: `nats`, `kafka`, `amqp`, `mqtt` |

---

# 7. Core Kind-to-Interface Validity Matrix

This matrix defines the valid interface shapes and protocol values permitted for each core kind.

| Kind | Interface | Allowed Protocols |
|------|-----------|-------------------|
| `service.http` | `http` | `http`, `https` |
| `datastore.relational` | `datastore` | `postgres`, `mysql`, `mariadb`, `sqlserver`, `oracle`, `sqlite` |
| `datastore.document` | `datastore` | `mongodb`, `couchbase` |
| `cache` | `cache` | `redis`, `memcached` |
| `message_bus` | `messageBus` | `nats`, `kafka`, `amqp`, `mqtt` |

---

# 8. Interface Definitions

Each Condition kind requires a specific interface block.

---

# 8.1 HTTP Service Interface

```yaml
interface:
  http:
    protocol: https
    operations:
      - method: POST
        path: /charge
        requestBodySchema: {}
        responseSchema: {}
```

## Required Fields

| Field | Requirement |
|------|--------------|
| `protocol` | MUST be `http` or `https` |
| `operations` | MUST be non-empty list |

## Operation Fields

| Field | Required |
|------|----------|
| `method` | YES |
| `path` | YES |
| `requestBodySchema` | OPTIONAL |
| `responseSchema` | OPTIONAL |

## Allowed HTTP Methods

- GET  
- HEAD  
- POST  
- PUT  
- PATCH  
- DELETE  
- OPTIONS  
- TRACE  

## Validation Rules

- `operations` MUST NOT be empty
- `path` MUST be non-empty string
- `method` MUST be valid HTTP method
- `requestBodySchema` MUST NOT be used with GET or HEAD
- Schema fields MUST remain open-ended

---

# 8.2 Datastore Interface

```yaml
interface:
  datastore:
    protocol: postgres
```

## Validation Rules

- `protocol` MUST be valid for declared kind
- HTTP operations MUST NOT appear

---

# 8.3 Cache Interface

```yaml
interface:
  cache:
    protocol: redis
```

---

# 8.4 Message Bus Interface

```yaml
interface:
  messageBus:
    protocol: nats
```

---

# 9. Core Validation Rules

## 9.1 Structural Validation

A Condition is invalid if:

- `name` is missing
- `kind` is missing
- `interface` is missing

---

## 9.2 Kind-to-Interface Validation

A Condition MUST:

- Use the interface required by its `kind`
- Use only permitted protocol values
- Avoid incompatible interface blocks

Invalid examples:

```yaml
kind: datastore.relational
interface:
  datastore:
    protocol: mongodb
```

```yaml
kind: cache
interface:
  http:
    protocol: https
```

---

# 10. Extension Model

The Runtime Conditions Profile supports vendor-defined extensions.

Extensions allow:

- New kinds
- New interfaces
- New protocol values
- Optional interface fields
- Additional semantic rules

Extensions MUST NOT redefine core semantics incompatibly.

---

# 11. Extension Declaration

Profiles that use extension-defined terms MUST declare them.

```yaml
extensions:
  - core
  - aws.runtime/v1alpha1
  - redis.compat/v1
```

---

# 12. Extension Definition Structure

Extensions are declared as separate artifacts.

```yaml
apiVersion: runtimeconditions.io/v1alpha1
kind: ValidationExtensionDefinition

metadata:
  name: aws.runtime
  version: v1alpha1

spec:

  kinds:
    - name: aws.object_store
      interface: objectStore
      protocols:
        - aws.s3

  interfaces:
    - name: objectStore
      fields:
        - name: protocol
          required: true

  protocolExtensions:
    - targetKind: cache
      addProtocols:
        - valkey

  validationRules:
    - id: cache-valkey
      appliesToKind: cache
      rule: protocol in ["redis","memcached","valkey"]
```

---

# 13. Extension Capabilities

Extensions MAY:

| Action | Description |
|-------|-------------|
| Add Kind | Introduce new namespaced kind |
| Add Interface | Define new interface type |
| Add Protocol | Extend allowed protocol list |
| Add Optional Fields | Extend interface schema |
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

If an extension is declared but unavailable:

- Profile MUST be marked unresolved
- Conditions using unknown vocabulary MUST be invalid

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

extensions:
  - core

conditions:

  - name: primary-db
    kind: datastore.relational
    interface:
      datastore:
        protocol: postgres

  - name: session-cache
    kind: cache
    interface:
      cache:
        protocol: redis

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

# 19. Example: AWS Extension Profile

```yaml
apiVersion: runtimeconditions.io/v1alpha1
kind: RuntimeConditionsProfile

metadata:
  name: storage-enabled

extensions:
  - core
  - aws.runtime/v1alpha1

conditions:

  - name: object-storage
    kind: aws.object_store
    interface:
      objectStore:
        protocol: aws.s3
```

---

# 20. Future Considerations

Possible future extensions include:

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
- A constrained validation matrix
- A structured extension system
- Vendor-neutral semantics
- Deterministic validation behavior

This provides a foundation for reliable downstream capability matching while preserving ecosystem flexibility.
