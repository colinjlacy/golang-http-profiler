# Decision Summary: DependencyProfile vs Adapter-Based Interpretation

## Context

The specification currently defines two core data sets:

- **ObservedBehavior** — the canonical record of runtime observations.
- **Condition** — a deterministic, portable representation of integration requirements derived from observed behavior.

During design discussions, a potential intermediate dataset called **DependencyProfile** was considered. The intent of such a dataset would be to normalize, deduplicate, and aggregate observations before generating Conditions.

However, introducing a new core dataset at this stage risks expanding the specification surface area prematurely.

The project has therefore decided to **not introduce DependencyProfile as a core data set at this time**.

Instead, interpretation logic will be expressed through **adapters**.

---

# Core Principle

The specification maintains a strict separation between:

| Layer | Purpose |
|-----|-----|
| **ObservedBehavior** | Evidence notebook of observed runtime behavior |
| **Condition** | Deterministic, portable dependency requirements |

ObservedBehavior must remain:

- append-only
- evidence-oriented
- devoid of conclusions
- free of interpretation or normalization logic

Condition must remain:

- deterministically derived
- implementation-neutral
- capability-oriented
- traceable back to observed evidence

---

# Adapter Model

The transformation from `ObservedBehavior` to `Condition` will be performed by **adapters**.

Adapters interpret observations and produce dependency conditions according to defined rules.

Two adapter categories are anticipated.

---

# Baseline Adapter

The **Baseline Adapter** represents the canonical transformation pipeline defined by the specification.

### Purpose

Convert raw observed behaviors directly into Conditions using only information derivable from the observations themselves.

### Characteristics

The baseline adapter must be:

- deterministic
- observation-derived
- provider-neutral
- knowledge-base independent
- reproducible across implementations

### Responsibilities

The baseline adapter:

- reads `ObservedBehavior`
- derives dependency Conditions
- populates evidence references
- preserves observed protocol/interface information

The baseline adapter **must not rely on**:

- cloud provider knowledge
- service identity catalogs
- vendor-specific mappings
- manually curated endpoint identities

### Example Pipeline

```
ObservedBehavior
      ↓
Baseline Adapter
      ↓
Condition
```

### Example (Conceptual)

ObservedBehavior:

```
protocol: http
destination: payments-api:8080
method: GET
path: /charge
```

Condition produced:

```
type: service.http
condition:
  observedAs:
    protocol: http
    interface:
      http:
        operations:
          - method: GET
            path: /charge
```

---

# Enriched Adapters

In addition to the baseline adapter, implementations may introduce **Enriched Adapters**.

These adapters perform additional interpretation, aggregation, or enrichment beyond what is strictly observable.

### Purpose

Enable higher-level interpretations while preserving the baseline model.

### Examples of enrichment

Possible enrichment behaviors include:

- collapsing logically equivalent HTTP operations
- merging multiple observations into a single dependency relationship
- incorporating external datasets (e.g. platform service catalogs)
- aggregating behavior across `image:tag`
- merging L3/L4 and L7 observations
- generating higher-level dependency artifacts

### Example Pipeline

```
ObservedBehavior
      ↓
Enriched Adapter
      ↓
Condition
```

or

```
ObservedBehavior
      ↓
Enriched Adapter
      ↓
Optional Derived Artifact
      ↓
Condition
```

### Important Constraint

Enriched adapters **must not redefine the meaning of ObservedBehavior**.

They may interpret or aggregate observations, but they must preserve traceability back to the original evidence.

---

# Why DependencyProfile Is Not Introduced (Yet)

The originally proposed `DependencyProfile` dataset would have served as a normalized summary of observed dependency behavior.

While useful conceptually, introducing it as a **core specification object** would:

- increase the complexity of the spec
- prematurely standardize normalization logic
- constrain future adapter implementations

Instead, implementations are free to construct **internal normalization datasets** if needed.

These datasets are considered **implementation artifacts**, not normative specification resources.

---

# Future Flexibility

This design leaves open the possibility of introducing additional artifacts later if they prove broadly useful.

For example, future specifications may standardize objects such as:

- normalized dependency summaries
- behavioral inventories
- integration catalogs

However, these should emerge from real ecosystem needs rather than being defined prematurely.

---

# Resulting Architecture

The current architecture becomes:

```
ObservedBehavior
        │
        ▼
   Baseline Adapter
        │
        ▼
      Condition
```

With optional enriched pipelines:

```
ObservedBehavior
        │
        ▼
   Enriched Adapter
        │
        ├── Optional internal normalization
        │
        ▼
      Condition
```

---

# Summary

The specification adopts an **adapter-based interpretation model**.

Key decisions:

- `ObservedBehavior` remains a pure observation record.
- `Condition` remains the portable dependency representation.
- `DependencyProfile` is **not introduced as a core dataset**.
- A **Baseline Adapter** provides the canonical transformation from observations to Conditions.
- **Enriched Adapters** may exist to provide higher-level interpretation or aggregation.

This approach preserves the minimal core specification while allowing future ecosystem growth through adapters and optional artifacts.