# Resource Generation Model

This document categorizes the internal data resources from the observation data catalog according to how they are created and maintained.

Each resource falls into one of three categories:

1. **Fully Auto-Generated**
2. **Generated but Requires Human Modification**
3. **Human-Authored (Source of Intent)**

A useful architectural rule:

- **Observed data → always auto-generated**
- **Platform intent → human-authored**
- **Mappings between the two → generated then refined**

---

# 1. Fully Auto-Generated Resources

These resources are derived entirely from runtime evidence or deterministic computation. Humans should rarely or never edit them directly.

## Observation Layer

### ObservationEngine

Mostly auto-generated.

Reasons:

- Engines can self-register
- Capability metadata can be introspected
- Provenance metadata can be attached automatically

Human involvement is rare and usually limited to describing capabilities.

---

### ObservationSet

Fully auto-generated.

Generated from:

- capture window
- active observation engines
- runtime environment
- collected evidence

This object represents **one capture run** of observation data.

---

### WorkloadCatalog

Mostly auto-generated.

Generated from:

- Kubernetes metadata
- container runtime metadata
- process discovery
- service mesh data

Possible human adjustments:

- naming normalization
- grouping workloads
- identity overrides

---

### ObservedBehavior

Fully auto-generated.

Derived from:

- eBPF HTTP observation
- TCP connections
- DNS resolution
- process metadata
- container metadata
- environment variables

Humans should **never modify this resource**.

This object represents **ground truth runtime evidence**.

---

### AssertionResult

Fully auto-generated.

Produced by evaluating assertions against:

- conditions
- environment projections
- bindings
- generated artifacts

This resource records pass/fail validation outcomes.

---

### SchemaBundle

Usually auto-generated.

Derived from:

- CRD definitions
- schema definitions
- catalog specifications

Humans maintain the schema source, but the bundle itself is generated automatically.

---

# 2. Generated but Requires Human Editing

These resources can be inferred automatically but often benefit from human refinement.

They represent **interpreted meaning derived from observed behavior**.

---

## ConditionSet

Initially auto-generated.

Derived from observed behavior:

Observed:

```
service-a → mysql:3306
```

Generated condition:

```
requires relational database capability
```

Human refinement may include:

- specifying semantics
- defining reliability expectations
- defining version constraints
- adding performance requirements

---

## Condition

Generated from observed behavior but often refined.

Example:

Auto-generated:

```
requires HTTP endpoint GET /orders
```

Human modification:

```
requires OpenAPI contract version >= v2
```

Conditions describe **portable runtime requirements**.

---

## CapabilityBinding

Often generated automatically but frequently edited.

Example:

Auto-generated:

```
relational-db -> mysql
```

Human refinement:

```
relational-db -> AWS RDS
```

or

```
relational-db -> PlanetScale
```

This layer maps **requirements to capabilities**.

---

## BindingSet

Partially generated.

Derived from:

```
Conditions + EnvironmentProjection
```

Humans often adjust:

- provider selection
- scaling characteristics
- availability requirements
- cost constraints

---

## NetworkPolicyBundle

Baseline network policies can be generated automatically.

However security teams frequently refine:

- explicit allow rules
- deny rules
- segmentation boundaries

This pattern is similar to:

- Kubescape network policy generation
- Cilium policy generation

---

## MockBundle

Auto-generated from:

- ObservedBehavior
- OpenAPI inference

Developers may refine:

- mock responses
- edge cases
- failure scenarios
- latency simulation

---

## ResourceBundle

Initially generated from bindings.

Examples include:

- Terraform
- Radius
- Crossplane
- CloudFormation

Engineers frequently adjust:

- sizing
- multi-region configuration
- secret integration
- scaling policies

---

# 3. Human-Authored Resources

These represent **developer or platform intent** and cannot reliably be inferred from observation alone.

They act as **control inputs to the system**.

---

## EnvironmentProjection

Always human-authored.

Defines:

- target environment
- cloud provider
- region
- cost preferences
- reliability requirements
- compliance requirements

Example:

```
environment: production
provider: aws
region: us-east-1
database_preference: managed
```

Observation cannot determine these values.

---

## CapabilityCatalog

Human-authored.

Defines platform capabilities such as:

```
relational-db
message-queue
email-service
object-storage
cache
```

These capabilities represent **platform abstractions**.

They must be curated by platform engineers.

---

## ProviderResolver

Mostly human-authored.

Encodes platform-specific mappings such as:

```
relational-db -> AWS RDS
email -> AWS SES
queue -> AWS SQS
object-storage -> S3
```

This resource represents **platform expertise**.

---

## AssertionSet

Human-authored templates.

Examples:

```
all conditions must have bindings
all services must have network policies
database latency < 100ms
external APIs must use TLS
```

Assertion sets represent **organizational standards and policies**.

---

## Assertion

Typically authored manually.

Assertions may be generated automatically, but most originate from:

- security policies
- reliability requirements
- compliance rules
- operational standards

---

# 4. Summary Table

| Resource | Category | Notes |
|--------|--------|------|
| ObservationEngine | Mostly auto-generated | Engine metadata |
| ObservationSet | Auto-generated | Observation capture |
| WorkloadCatalog | Mostly auto-generated | Runtime discovery |
| ObservedBehavior | Auto-generated | Ground truth |
| ConditionSet | Generated → edited | Derived requirements |
| Condition | Generated → edited | Requirement semantics |
| EnvironmentProjection | Manual | Environment intent |
| BindingSet | Generated → edited | Implementation mapping |
| CapabilityCatalog | Manual | Platform abstraction |
| CapabilityBinding | Generated → edited | Capability mapping |
| ProviderResolver | Manual | Platform expertise |
| AssertionSet | Manual templates | Organizational rules |
| Assertion | Mostly manual | Policy definition |
| AssertionResult | Auto-generated | Evaluation output |
| NetworkPolicyBundle | Generated → edited | Security output |
| MockBundle | Generated → edited | Testing output |
| ResourceBundle | Generated → edited | Infrastructure output |
| SchemaBundle | Generated | System schema |

---

# 5. Three Tiers of Authority

The architecture naturally forms three layers.

## Tier 1 — Evidence

Runtime truth:

```
ObservedBehavior
ObservationSet
WorkloadCatalog
```

---

## Tier 2 — Meaning

Interpreted runtime requirements:

```
Condition
ConditionSet
```

---

## Tier 3 — Intent

Human-defined platform behavior:

```
EnvironmentProjection
CapabilityCatalog
Assertions
```

---

Everything else becomes **derived outputs**.

---

# 6. Core Architectural Principle

This system separates **evidence from intent**.

Traditional infrastructure pipelines mix these together.

This architecture instead uses the model:

```
Evidence  → what the application actually does
Intent    → what the platform wants
Projection → how the two meet
Artifacts → deployable output
```

This separation enables:

- automatic infrastructure generation
- automatic security policy generation
- automated CI mocks
- environment portability
- runtime-driven documentation