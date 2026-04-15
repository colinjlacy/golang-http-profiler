# Behavior Mental Model Map

## 1. Conceptual Model

This diagram explains the big picture: observe reality → model behavior → generate artifacts → produce business outcomes.

```mermaid
flowchart TB

subgraph Observation
A[eBPF Profilers]
B[Service Mesh Observations]
C[Network Sensors]
D[Other Observation Engines]
end

subgraph Behavior_Model
E[ObservedBehavior CRD\nCanonical Behavior Dataset]
end

subgraph Derived_Artifacts
F[Security Policies\nCiliumNetworkPolicies\nKubernetes NetworkPolicy]
G[API Specifications\nOpenAPI Generation]
H[Mock Servers\nCI Testing Environments]
I[Infrastructure as Code\nRadius / Terraform / Bicep]
J[Integration Maps\nService Dependency Graphs]
K[Cloud Resource Definitions\nDatabases, Queues, APIs]
L[Architecture Documentation]
M[IAM Permissions]
end

subgraph Business_Outcomes
N[Secure by Default Deployments]
O[Automated CI Testing]
P[Environment Migration\nLocal → Cloud]
Q[Self-Documenting Architecture]
R[Reduced Integration Breakage]
S[Developer Productivity]
end

Observation --> E
E --> Derived_Artifacts

F --> N
G --> O
H --> O
I --> P
K --> P
J --> Q
L --> Q
M --> N

O --> S
P --> S
Q --> S
N --> S
```

## 2. Causal Dependency Graph

This diagram shows the detailed causal chain from low-level signals → enriched understanding → generated outputs.

```mermaid
flowchart TB

subgraph Runtime_Signals
A1[HTTP Request\nGET /orders]
A2[TCP Connection\nPort 5432]
A3[DNS Resolution]
A4[Container Metadata]
A5[Environment Variables]
end

subgraph Raw_Observations
B1[HTTP Endpoint Observed]
B2[Service → Service Call]
B3[Service → Database Connection]
B4[External API Calls]
end

subgraph Enrichment
C1[Service Identity Resolution]
C2[Protocol Detection]
C3[Known Servers Lookup\n(Kubescape Concept)]
C4[Port-Based DB Identification]
C5[Environment Metadata]
end

subgraph Canonical_Model
D1[ObservedBehavior CRD]
end

subgraph Derived_Graph
E1[Service Dependency Graph]
E2[API Endpoint Map]
E3[Infrastructure Dependency Graph]
E4[External Integration Graph]
end

subgraph Artifact_Generators
F1[Network Policy Generator]
F2[OpenAPI Spec Generator]
F3[Mock Server Generator]
F4[IaC Generator]
F5[Cloud Migration Generator]
F6[Architecture Diagram Generator]
F7[IAM Policy Generator]
end

subgraph Generated_Artifacts
G1[CiliumNetworkPolicies]
G2[OpenAPI Specs]
G3[Mock APIs]
G4[Radius / Terraform Infrastructure]
G5[Cloud Service Definitions]
G6[Architecture Docs]
G7[Least Privilege IAM]
end

Runtime_Signals --> Raw_Observations
Raw_Observations --> Enrichment
Enrichment --> D1

D1 --> Derived_Graph

Derived_Graph --> Artifact_Generators

F1 --> G1
F2 --> G2
F3 --> G3
F4 --> G4
F5 --> G5
F6 --> G6
F7 --> G7
```

## 3. Relationship to Kubescape Concepts

Kubescape provides a specific implementation of part of this model, particularly the security branch.

```mermaid
Relationship to Kubescape Concepts

Kubescape provides a specific implementation of part of this model, particularly the security branch.

flowchart LR

A[Observed Network Traffic]
B[Network Neighborhood CRD\nKubescape]
C[Known Servers CRD\nKubescape]
D[Enriched Network Model]
E[Network Policies]

A --> B
C --> D
B --> D
D --> E
```

In the broader system architecture proposed here:

```text
Kubescape NetworkNeighborhood
            ↓
      ObservedBehavior
            ↓
     Multi-Domain Outputs
```

Kubescape contributes network-level behavior capture, but the larger Application Modeling Engine expands this to include:

- API modeling
- Infrastructure generation
- CI testing automation
- Architecture documentation
- Cloud resource provisioning

## 4. High-Level System Architecture

```mermaid
flowchart TB

A[eBPF Observers\nHTTP profiler\nnetwork sensors]
B[Observation Engines]
C[Raw Observations]

D[Observation Aggregator]

E[ObservedBehavior CRD]

F[Behavior Graph Builder]

G1[Security Generators]
G2[API Generators]
G3[Infrastructure Generators]
G4[Documentation Generators]
G5[Testing Generators]

H1[CiliumNetworkPolicies]
H2[OpenAPI Specs]
H3[Radius Infrastructure]
H4[Architecture Diagrams]
H5[Mock APIs]

A --> B
B --> C
C --> D
D --> E

E --> F

F --> G1
F --> G2
F --> G3
F --> G4
F --> G5

G1 --> H1
G2 --> H2
G3 --> H3
G4 --> H4
G5 --> H5
```

