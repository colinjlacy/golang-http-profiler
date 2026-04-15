# Internal Graph Data Model

This diagram treats the system as a graph-centered pipeline:

**ObservationEngine / ObservationSet / WorkloadCatalog / ObservedBehavior**
→ **ConditionSet / Condition**
→ **EnvironmentProjection / BindingSet / CapabilityCatalog / CapabilityBinding**
→ **AssertionSet / Assertion / AssertionResult**
→ **NetworkPolicyBundle / MockBundle / ResourceBundle**

This follows the lifecycle defined in the object catalog:
**Observed Behaviors → Derived Conditions → Environment Projections → Assertions → Generated Artifacts**.

---

## 1. Internal Graph Data Model

```mermaid
flowchart TB

subgraph Stage1["Stage 1 — Observation / Evidence"]
  OE[ObservationEngine]
  OS[ObservationSet]
  WC[WorkloadCatalog]
  WB1[Workload]
  WB2[Workload]
  OB1[ObservedBehavior: HTTP call]
  OB2[ObservedBehavior: DB connection]
  OB3[ObservedBehavior: External API call]
end

subgraph Stage2["Stage 2 — Portable Meaning"]
  CS[ConditionSet]
  C1[Condition: HTTP dependency]
  C2[Condition: Relational DB semantics]
  C3[Condition: External service capability]
end

subgraph Stage3["Stage 3 — Environment Realization"]
  EP[EnvironmentProjection]
  BS[BindingSet]
  CC[CapabilityCatalog]
  CB[CapabilityBinding]
  PR[ProviderResolver]
end

subgraph Stage4["Stage 4 — Verification"]
  AS[AssertionSet]
  A1[Assertion: connectivity]
  A2[Assertion: contract compatibility]
  A3[Assertion: resource existence]
  AR[AssertionResult]
end

subgraph Stage5["Stage 5 — Generated Artifacts"]
  NPB[NetworkPolicyBundle]
  MB[MockBundle]
  RB[ResourceBundle]
  SB[SchemaBundle]
end

OE --> OS
OS --> WC
OS --> OB1
OS --> OB2
OS --> OB3

WC --> WB1
WC --> WB2

WB1 --> OB1
WB1 --> OB2
WB1 --> OB3
OB1 --> WB2

OB1 --> CS
OB2 --> CS
OB3 --> CS

CS --> C1
CS --> C2
CS --> C3

C1 --> BS
C2 --> BS
C3 --> BS

EP --> BS
CC --> CB
CB --> BS
PR --> BS

BS --> AS
CS --> AS
EP --> AS

AS --> A1
AS --> A2
AS --> A3
A1 --> AR
A2 --> AR
A3 --> AR

CS --> NPB
CS --> MB
BS --> RB
SB -. validates .-> OE
SB -. validates .-> OS
SB -. validates .-> WC
SB -. validates .-> CS
SB -. validates .-> EP
SB -. validates .-> AS
SB -. validates .-> NPB
SB -. validates .-> MB
SB -. validates .-> RB
```

---

## 2. What each stage means

### Stage 1 — Observation / Evidence

- **ObservationEngine** describes the observer producing the signal.
- **ObservationSet** groups captured data from a run.
- **WorkloadCatalog** normalizes runtime identities.
- **ObservedBehavior** is the atomic runtime interaction record.

### Stage 2 — Portable Meaning

- **ConditionSet** groups derived runtime requirements.
- **Condition** expresses a single requirement (e.g., relational DB, HTTP API).

### Stage 3 — Environment Realization

- **EnvironmentProjection** defines the target platform.
- **BindingSet** wires conditions to concrete implementations.
- **CapabilityCatalog** defines reusable platform capabilities.
- **CapabilityBinding** maps requirements to capabilities.
- **ProviderResolver** enriches bindings with provider-specific semantics.

### Stage 4 — Verification

- **AssertionSet** groups validation checks.
- **Assertion** expresses a specific rule.
- **AssertionResult** records validation outcomes.

### Stage 5 — Generated Artifacts

- **NetworkPolicyBundle** for Kubernetes/Cilium policies.
- **MockBundle** for generated mocks and CI testing.
- **ResourceBundle** for Terraform/Radius/Crossplane artifacts.
- **SchemaBundle** validates the entire ecosystem.

---

## 3. Artifact placement in the mental model

```mermaid
flowchart LR

A[Observed Behaviors] --> B[Derived Conditions]
B --> C[Environment Projections]
C --> D[Assertions]
D --> E[Generated Artifacts]

A1[ObservationEngine]
A2[ObservationSet]
A3[WorkloadCatalog]
A4[ObservedBehavior]

B1[ConditionSet]
B2[Condition]

C1[EnvironmentProjection]
C2[BindingSet]
C3[CapabilityCatalog]
C4[CapabilityBinding]
C5[ProviderResolver]

D1[AssertionSet]
D2[Assertion]
D3[AssertionResult]

E1[NetworkPolicyBundle]
E2[MockBundle]
E3[ResourceBundle]
E4[SchemaBundle]
```

---

## 4. Recommended node and edge types

### Node types

ObservationEngine  
ObservationSet  
Workload  
ObservedBehavior  
Condition  
EnvironmentProjection  
Binding  
Capability  
Assertion  
Artifact  
Provider  
Schema  

### Edge types

PRODUCED_BY  
RECORDED_IN  
IDENTIFIED_AS  
OBSERVED_FROM  
OBSERVED_TO  
DERIVES  
PROJECTED_INTO  
BOUND_TO  
SATISFIED_BY  
VERIFIED_BY  
RESULTED_IN  
GENERATED_AS  
VALIDATED_BY  
ENRICHED_BY  

---

## 5. Example graph paths

### Security path

ObservedBehavior(service-a → service-b HTTP)  
→ Condition(service-a requires access)  
→ EnvironmentProjection(prod-cluster)  
→ BindingSet(resolve workload)  
→ Assertion(connectivity valid)  
→ NetworkPolicyBundle

### API mock generation path

ObservedBehavior(service-a → orders-api GET /orders)  
→ Condition(HTTP contract dependency)  
→ Assertion(contract reachable)  
→ MockBundle(mock server)

### Environment migration path

ObservedBehavior(app → mysql endpoint port 3306)  
→ Condition(relational DB semantics)  
→ EnvironmentProjection(aws-prod)  
→ BindingSet(bind AWS RDS)  
→ ProviderResolver(enrich provider semantics)  
→ ResourceBundle(terraform/radius)

### Platform capability abstraction path

ObservedBehavior(app → email API)  
→ Condition(email capability)  
→ CapabilityBinding(email-service abstraction)  
→ BindingSet(dev=SendGrid, prod=SES)  
→ Assertion(validate provider availability)  
→ ResourceBundle

---

## 6. Architectural insight

ObservedBehavior = evidence  
Condition = portable meaning  
Binding = environment-specific realization  
Assertion = proof of runtime success  
Bundle = emitted artifact

---

## 7. Framing sentence

The system turns runtime evidence into a portable application dependency graph, then projects that graph into environment-specific bindings, validations, and generated artifacts.

---

## 8. Compact slide diagram

```mermaid
flowchart LR
  OB[ObservedBehavior] --> C[Condition]
  C --> EP[EnvironmentProjection]
  EP --> B[BindingSet]
  C --> A[AssertionSet]
  B --> RB[ResourceBundle]
  C --> MB[MockBundle]
  C --> SBOB[SoftwareBillOfBehavior]
  SBOB --> NPB[NetworkPolicyBundle]

%% Style definitions
classDef init fill:#b7e4c7,stroke:#1b5e20,stroke-width:2px,color:#000;
classDef runtime fill:#fff3b0,stroke:#c98a00,stroke-width:2px,color:#000;
classDef security fill:#ffb3b3,stroke:#c62828,stroke-width:2px,color:#000;
classDef mock fill:#b3d9ff,stroke:#1565c0,stroke-width:2px,color:#000;
classDef assertion fill:#ffd59e,stroke:#ef6c00,stroke-width:2px,color:#000;
classDef infra fill:#b7e4c7,stroke:#2e7d32,stroke-width:2px,color:#000;

%% Apply styles
class OB init
class C runtime
class NPB,SBOB security
class MB mock
class A assertion
class EP,B,RB infra
linkStyle default stroke:#222222,stroke-width:4px
```
