# Runtime Conditions Profile Specification (Draft)

## Status

**Draft — Request for Comments**

This document is an early working draft of the Runtime Conditions Profile specification.

It is intentionally not marked with a version and is being published solely to solicit early feedback from the community.

This draft is expected to evolve significantly based on review and discussion before a stable version is tagged.

## Request for Feedback

The authors are particularly interested in feedback on:

- Core Condition model structure
- Extension model design
- Extension authoring and conformance rules
- Validation behavior and layering
- Namespacing approach
- Overall scope boundaries

Early architectural feedback is strongly encouraged.

---

# 1. Purpose

The Runtime Conditions Profile provides a **portable declaration of required external runtime capabilities** needed for an application workload to function successfully.

These capabilities may include:

- HTTP services
- Relational databases
- Caches
- Vendor-defined integration services

The Runtime Conditions Profile:

- **SHOULD be generated automatically when possible**
- **MAY be authored manually when automated generation is not feasible**
- **MUST remain valid regardless of generation method**
- **MUST remain implementation-neutral**
- **MUST remain infrastructure-agnostic**

The core specification defines a stable profile envelope, workload identity model, Condition object model, validation lifecycle, and extension contract.

The profile defines **requirements**, not implementations or environment-specific values.

---

# 2. Scope

This specification defines a portable format for describing the external capabilities that an application workload depends on in order to function properly. These dependencies represent integrations with services that exist outside the workload itself, such as HTTP APIs, databases, caches, and message systems.

The Runtime Conditions Profile models each dependency as an independent Condition. Each Condition has a required capability classification and a required interface description. The core specification defines that object shape; extensions define the concrete vocabulary that gives a Condition operational meaning.

This specification is limited to externally satisfied integrations. It does not attempt to describe internal execution behavior, infrastructure configuration, deployment topology, platform-specific provisioning, or concrete configuration values assigned in a target environment. It also does not require or depend on any upstream observation system, although such systems may be used to generate Runtime Conditions Profiles.

A profile validated only against the core specification uses the core document envelope and Condition structure but does not use any extension-defined capability vocabulary. Practical Runtime Conditions Profiles normally declare one or more extensions that define Condition kinds, interface types, field values, and additional validation rules.

This split allows the core specification to remain a stable interchange contract while allowing capability vocabulary to evolve through extensions.

---

# 3. Core Design Principles

## 3.1 Declarative

Profiles MUST be declarative documents describing what is required, not how to fulfill it.

A Runtime Conditions Profile MUST be associated with a uniquely identifiable
workload and SHOULD correspond to a specific version of that workload. The profile version SHOULD align with the workload version.

A Runtime Conditions Profile MUST describe exactly one workload identity
and MUST NOT represent multiple unrelated workloads within a single profile.

## 3.2 Portable

Profiles SHOULD be portable across environments and platforms when expressed using the core structure and extension vocabulary that remains implementation-neutral.

Profiles that use extension-defined vocabulary MAY introduce platform-specific or vendor-specific semantics. Such profiles remain portable to the extent that the required extensions are available.

## 3.3 Implementation-Neutral

Profiles MUST describe required capabilities without prescribing how those capabilities are implemented or provisioned.

Core specification vocabulary MUST remain vendor-neutral and MUST NOT encode assumptions about specific infrastructure implementations.

Vendor-specific or platform-specific identifiers MAY be used only when introduced through declared extensions.

Profiles MUST NOT encode:

- Infrastructure configuration details
- Concrete target-environment connection values
- Deployment topology
- Resource sizing
- Geographic placement
- Provider-specific provisioning instructions

## 3.4 Extensible

Profiles MAY include extension-defined vocabulary to describe concrete capabilities within the core Condition model.

Profiles that use extension-defined vocabulary MUST identify the extensions on which that vocabulary depends.

Use of extensions MUST NOT alter or redefine the meaning of core specification vocabulary.

## 3.5 Deterministically Validatable

Profiles MUST adhere to the structural and semantic validation rules defined by the core specification.

Profiles that reference extension-defined vocabulary MUST also adhere to the validation rules defined by those extensions.

## 3.6 Security and Privacy

Profiles MUST NOT contain secret values, credentials, tokens, private keys, passwords, or other sensitive runtime values.

Profiles MUST NOT contain concrete target-environment connection values, such as environment-specific hostnames, service URLs, usernames, passwords, or generated resource identifiers.

Profiles MAY contain non-secret identifiers required to describe workload requirements, such as operation paths, schema field names, extension identifiers, workload identifiers, labels, and environment variable names when introduced by an extension.

Labels SHOULD describe classification and governance facts about the workload or profile. Labels MUST NOT contain protected data, customer data, personal data, secret values, or concrete target-environment values.

Tools that generate, store, or transmit profiles SHOULD treat profiles as potentially sensitive because they may reveal dependency structure, API paths, schema shapes, and workload identity.

---

# 4. Runtime Conditions Profile Structure

A Runtime Conditions Profile defines a collection of independent runtime Conditions.

Examples in this specification are expressed using YAML for readability. The data model defined by this specification is serialization-neutral and MAY be represented using YAML, JSON, or other compatible formats.

## 4.1 Serialization Requirements

Profiles MAY be serialized as YAML or JSON.

Serialization processors MUST preserve the data model defined by this specification. Map ordering MUST NOT affect profile meaning.

A serialized profile is invalid if:

- It contains duplicate keys within the same mapping
- A required field is present with a `null` value
- A field whose type is defined as a string, boolean, array, or object is present with a different type

An optional field that is omitted and an optional field that is present with `null` MUST NOT be treated as equivalent. Optional fields SHOULD be omitted when they are not used.

For deterministic comparison, signing, or caching, tools MAY produce a canonical serialized form by converting the profile to JSON, sorting object keys lexicographically, preserving array order, omitting insignificant whitespace, and omitting optional fields that are not used.

Comments, YAML anchors, and YAML aliases are serialization conveniences and are not part of the Runtime Conditions Profile data model.

## 4.2 Top-Level Fields

| Field        | Required | Description |
| ------------ | -------- | ----------- |
| `apiVersion` | YES      | Runtime Conditions Profile API version |
| `kind`       | YES      | Document kind. MUST be `RuntimeConditionsProfile` |
| `metadata`   | YES      | Profile metadata |
| `workload`   | YES      | Workload identity described by this profile |
| `extensions` | YES      | Extension identifiers declared by the profile. MAY be empty |
| `conditions` | YES      | Runtime Conditions declared for the workload. MAY be empty |

The `apiVersion` value defined by this draft is:

```text
runtimeconditions.io/v1alpha1
```

The `kind` value MUST be:

```text
RuntimeConditionsProfile
```

## 4.3 Metadata Fields

```yaml
metadata:
  name: example-profile
  labels:
    compliance.example.com/hipaa: "true"
    compliance.example.com/sox: "true"
    owner.example.com/team: platform
    lifecycle.example.com/stage: production
```

| Field    | Required | Description |
| -------- | -------- | ----------- |
| `name`   | YES      | Human-readable profile name |
| `labels` | NO       | Machine-readable profile and workload classification labels |

`metadata.name` MUST be a non-empty string.

`metadata.name` SHOULD be stable for the workload and profile purpose. It is not required to be globally unique.

`metadata.labels`, when present, MUST be a mapping of string keys to string values.

Label keys MUST be non-empty strings. Label values MUST be strings. Values that represent booleans, numbers, stages, or enum-like categories MUST still be serialized as strings.

Label keys SHOULD be namespaced using a DNS-style prefix followed by a slash and a label name:

```text
<namespace>/<name>
```

Examples:

- `compliance.example.com/hipaa`
- `compliance.example.com/sox`
- `owner.example.com/team`
- `lifecycle.example.com/stage`
- `risk.example.com/criticality`
- `data.example.com/classification`

Unqualified label keys MAY be used for private local conventions, but portable labels SHOULD use namespaced keys to reduce collisions between organizations, tools, and extensions.

The `runtimeconditions.io/` namespace is reserved for labels defined by the core specification or first-party Runtime Conditions extensions.

Labels are intended for stable, machine-readable classification and selection. Tools MAY use labels to:

- Select, filter, group, and search profiles
- Apply policy or compliance workflows
- Route ownership, review, approval, or escalation workflows
- Associate profiles with business domains, teams, services, or lifecycle stages
- Support inventory, reporting, maintenance, migration, and decommissioning workflows

Labels are appropriate for facts that external systems may act on, such as compliance scope, owning team, business domain, lifecycle stage, criticality, or data classification.

Labels MUST NOT define runtime dependency requirements. Labels MUST NOT replace Conditions, extension-defined fields, workload identity, or target-environment fulfillment data.

Changing a label MAY change how external systems process, route, report on, or govern a profile. Changing a label MUST NOT change the meaning of any Condition declared by the profile.

## 4.4 Workload Fields

```yaml
workload:
  uri: https://github.com/example-org/example-service
  version: v1.2.3
```

| Field     | Required | Description |
| --------- | -------- | ----------- |
| `uri`     | YES      | Stable workload identifier |
| `version` | NO       | Workload version described by the profile |

`workload.uri` MUST be a non-empty string and SHOULD identify the workload source, package, image, service, or other stable workload identity.

`workload.version`, when present, MUST be a non-empty string.

A Runtime Conditions Profile MUST describe exactly one workload identity and MUST NOT represent multiple unrelated workloads within a single profile.

## 4.5 Core Structural Shape

A profile that uses only the core specification can declare workload identity and an empty Condition collection.

Non-empty `conditions` require one or more extensions for extension-resolved or semantic validity because the core specification does not define any concrete Condition vocabulary.

```yaml
apiVersion: runtimeconditions.io/v1alpha1
kind: RuntimeConditionsProfile

metadata:
  name: structural-profile
  labels:
    owner.example.com/team: platform
    lifecycle.example.com/stage: development

workload:
  uri: https://github.com/example-org/example-service
  version: v1.2.3

extensions: []

conditions: []
```

---

# 5. Condition Model

Each Condition represents an **independent required runtime dependency**.

The core specification owns the Condition object model. A Condition MUST be a mapping with:

- `kind`: a required non-empty string
- `interface`: a required mapping
- `name`: an optional non-empty string
- `optional`: an optional boolean

Extensions MAY add fields to the Condition object according to the extension rules defined by this specification.

## Condition Fields


| Field       | Type    | Required | Description                                           |
| ----------- | ------- | -------- | ----------------------------------------------------- |
| `kind`      | string  | YES      | Required capability classification                    |
| `interface` | object  | YES      | Interface definition required for matching            |
| `name`      | string  | NO       | Unique identifier within profile                      |
| `optional`  | boolean | NO       | Whether the Condition is optional. Defaults to `false` |

The `kind` value identifies what class of capability is required. The value MUST be defined by exactly one resolved extension.

The `interface` value describes the workload-facing interaction model for the declared `kind`. The interface object MUST contain a `type` field as defined in Section 7.

## Condition Names and References

`conditions[].name`, when present, MUST be a non-empty string and MUST be unique within the profile.

Profiles intended for automation SHOULD provide `name` for every Condition.

The canonical structural reference for a Condition is its JSON Pointer path:

```text
#/conditions/<index>
```

The index is zero-based and refers to the Condition's position in the serialized `conditions` array.

When `name` is present, tools MAY also refer to the Condition by name within the profile:

```text
condition:<name>
```

Name-based references are stable only within the profile that declares the name. Cross-profile references SHOULD use workload identity plus condition name, or another higher-level identifier defined outside this core specification.

Condition array order MUST NOT change the meaning of independent Conditions, but it affects JSON Pointer references. Tools that rewrite profiles SHOULD preserve Condition order when possible.

## Optional Conditions

The `optional` field is a boolean that indicates whether a Condition is optional.

When `optional` is omitted, it MUST be understood as `false`, meaning the Condition is required. It MAY be defined explicitly, but only setting `optional: true` changes downstream behavior.

The logic for determining what makes a Condition optional is beyond the scope of this specification. It is the responsibility of both the developer and the platform team to decide how optional integration Conditions are handled.

---

# 6. Condition Vocabulary

The core specification defines the Condition abstraction and required structural fields, but it does not define any concrete Condition `kind` values, `interface.type` values, engine values, or type-specific interface fields.

Condition vocabulary is supplied by extensions.

Each Condition MUST declare exactly one `kind`. The declared `kind` MUST be defined by exactly one resolved extension.

Kinds represent capability classifications. An extension MAY define broad kinds such as API, datastore, or cache, or narrower kinds for domain-specific integration requirements.

---

# 7. Interface Model

Each Condition MUST define an `interface` block describing how the workload interacts with the declared capability.

## Interface Structure

```yaml
interface:
  type: <interface-type>
```

The `interface` value MUST be a mapping.

The `type` field is required and MUST be a non-empty string. It identifies the interaction model associated with the declared `kind`.

The declared `interface.type` MUST be defined by exactly one resolved extension for the declared `kind`.

Additional fields MAY be defined within `interface` by the extension that defines the declared `kind` and `interface.type`, or by another extension that explicitly extends that kind and interface type.

Interface definitions are validated based on:

- Core structural validation rules
- The extension that defines the declared `kind`
- The extension that defines the declared `interface.type`
- Extensions that add fields, values, or validation rules for the declared `kind` and `interface.type`

---

# 8. Core Validation Rules

Validation ensures that Conditions are structurally correct and semantically consistent.

Validation occurs in multiple phases.

---

## 8.1 Structural Validation

A profile is structurally invalid if:

- `apiVersion` is missing or is not `runtimeconditions.io/v1alpha1`
- `kind` is missing or is not `RuntimeConditionsProfile`
- `metadata` is missing
- `metadata.name` is missing or empty
- `metadata.labels` is present and is not a mapping
- Any `metadata.labels` key is not a non-empty string
- Any `metadata.labels` value is not a string
- `workload` is missing
- `workload.uri` is missing or empty
- `extensions` is missing or is not an array
- `conditions` is missing or is not an array
- Any required field is present with a `null` value
- Any mapping contains duplicate keys

A Condition is structurally invalid if:

- It is not a mapping
- `kind` is missing or is not a non-empty string
- `interface` is missing or is not a mapping
- `interface.type` is missing or is not a non-empty string
- `name` is present but is not a non-empty string
- `optional` is present but is not a boolean

If a `name` field is provided, it MUST be unique within the profile.

---

## 8.2 Vocabulary Resolution

Vocabulary resolution determines which extension defines each non-core value or field used by a profile.

A profile is invalid if:

- A Condition `kind` is not defined by a resolved extension
- A Condition `kind` is defined by more than one resolved extension for the same scope
- An `interface.type` is not defined by a resolved extension for the declared `kind`
- An `interface.type` is defined by more than one resolved extension for the same `kind`
- An extension-defined interface field is not defined by a resolved extension for the declared `kind` and `interface.type`
- An extension-defined interface field is defined by more than one resolved extension for the same `kind` and `interface.type`
- An allowed value for a field is defined by more than one resolved extension for the same field and scope
- An extension-defined Condition field is not defined by a resolved extension
- An extension-defined Condition field is defined by more than one resolved extension unless the field name is explicitly namespaced and unambiguous

Profile generators SHOULD fail before emitting profiles that contain unresolved or conflicting vocabulary. Profile validators MUST reject such profiles.

---

## 8.3 Invalid Condition Examples

Invalid unresolved kind:

```yaml
kind: datastore
interface:
  type: relational
```

Invalid unresolved interface type:

```yaml
kind: cache
interface:
  type: relational
```

Invalid unresolved interface field:

```yaml
kind: api
interface:
  type: http
  engine: postgres
```

## 8.4 Profile Validity Levels

Validators SHOULD distinguish the following validity levels:

| Level | Description |
| ----- | ----------- |
| Structural validity | The profile satisfies the core document shape and type requirements |
| Extension-resolved validity | All declared extensions and transitive dependencies can be resolved, and all vocabulary has exactly one owner in its scope |
| Semantic validity | The profile satisfies all core and extension-defined semantic validation rules |

A core-only profile with an empty `conditions` array can be structurally and semantically valid, but it does not describe operational runtime dependencies.

A core-only profile that contains Conditions with arbitrary `kind` and `interface.type` values may satisfy structural validation, but it is not extension-resolved valid and does not describe operational runtime dependencies.

A profile with non-empty `conditions` is not extension-resolved valid unless every Condition kind, interface type, extension-defined field, and extension-defined field value resolves to exactly one owner.

## 8.5 Required Validator Behavior

A conforming validator MUST report validation failure when a profile is structurally invalid, contains unresolved extension vocabulary, contains vocabulary ownership conflicts, or violates extension-defined semantic rules.

Validation errors SHOULD identify:

- Error category
- JSON Pointer location within the profile
- Offending field or value, when applicable
- Extension involved, when applicable
- Expected valid vocabulary or type, when practical

Minimum error categories are:

- `structural`
- `unknown-extension`
- `extension-dependency`
- `unresolved-vocabulary`
- `vocabulary-conflict`
- `semantic`

---

# 9. Extension Model

The Runtime Conditions Profile supports extension-defined vocabulary.

Extensions allow:

- New kinds
- New interface types
- New Condition fields
- New interface fields
- New field values
- Additional validation rules
- Additional allowed values for existing fields where semantically compatible

Extensions MAY add fields to the Condition object itself, not only to the `interface` block. This allows extensions to describe additional workload requirements, matching signals, metadata, or workload-facing inputs that are outside the core Condition model.

Extensions MUST NOT redefine core semantics incompatibly.

## 9.1 First-Party Extensions

First-party extensions MAY be published alongside the core specification to provide common Condition vocabulary and common extension-defined fields.

First-party extensions are not core vocabulary. They MUST follow the same declaration, ownership, compatibility, and validation rules as any other extension.

Implementations MAY bundle support for first-party extensions for generation, validation, and resolver workflows. Bundled implementation support does not make extension vocabulary implicit. A profile that uses first-party extension vocabulary MUST declare that vocabulary directly or through a resolvable bundle extension.

Common Condition kinds, common `interface.type` values, common engine values, and workload configuration inputs are expected to be defined by first-party extensions rather than by the core specification.

---

# 10. Extension Declaration

Profiles that reference extension-defined vocabulary MUST identify those extensions.

## 10.1 Extension Identifier Format

An extension identifier is a stable, versioned string.

Extension identifiers MUST consist of three or more slash-separated path segments:

```text
<publisher>/<extension-name>/<version>
```

The final segment MUST be a version segment.

All non-version segments MUST contain only lowercase ASCII letters, digits, dots, and hyphens. They MUST start and end with a lowercase ASCII letter or digit.

Version segments MUST use one of the following forms:

- `v<major>`
- `v<major>alpha<minor>`
- `v<major>beta<minor>`

Examples:

- `runtimeconditions.io/common-capabilities/v1alpha1`
- `runtimeconditions.io/env-configuration/v1alpha1`
- `aws.runtime/object-store/v1alpha1`

Extension identifiers are case-sensitive and MUST be compared as exact strings.

Extension aliases are not defined by this specification. Validators MUST NOT treat two different extension identifiers as equivalent unless one is resolved through an explicit bundle or dependency declaration.

## 10.2 Profile Extension Declaration

```yaml
extensions:
  - runtimeconditions.io/common-capabilities/v1alpha1
  - aws.runtime/object-store/v1alpha1
  - redis.compat/valkey/v1
```

Extension declarations identify the vocabulary required to validate and interpret the profile. Implementations MAY bundle support for first-party extensions, but generated profiles MUST declare the required vocabulary either directly or through resolvable extension dependencies or bundles.

The `extensions` array MUST NOT contain duplicate extension identifiers.

Extensions MAY declare dependencies on other extensions. During validation, declared extensions and their transitive dependencies form the resolved extension set.

Extensions MAY act as bundles by declaring dependencies without adding vocabulary of their own. Bundle extensions are a convenience mechanism and MUST NOT change the semantics of the extensions they include.

## 10.3 Extension Dependency Resolution

Extension dependencies MUST identify exact extension versions.

Dependency version ranges are not defined by this specification.

A profile is invalid if:

- A declared extension cannot be resolved
- A transitive dependency cannot be resolved
- Extension dependency resolution contains a cycle
- Two resolved extensions conflict over vocabulary ownership

Dependency resolution MUST be deterministic and MUST NOT depend on declaration order.

## 10.4 Extension Bundles

A bundle extension is an extension that declares dependencies and does not define additional vocabulary.

Bundle extensions MAY appear in a profile's `extensions` array.

Validators MUST expand bundle dependencies during extension resolution.

If a generated profile uses vocabulary from extensions included by a bundle, the profile MAY declare only the bundle extension, provided the bundle definition is resolvable and the bundle dependencies fully account for the vocabulary used by the profile.

Bundles MUST NOT change validation behavior, vocabulary ownership, or semantics of the extensions they include.

---

# 11. Extension Definition Structure

Extensions are defined as independent artifacts.

An extension definition MUST identify all vocabulary it owns and MUST provide enough scope information for validators to detect ownership conflicts deterministically.

When an extension defines a field value, it MUST identify the field path and the kind or interface type scope in which the value is valid.

## 11.1 Extension Definition Fields

| Field        | Required | Description |
| ------------ | -------- | ----------- |
| `apiVersion` | YES      | Runtime Conditions API version used for the extension definition |
| `kind`       | YES      | Extension definition kind. MUST be `ValidationExtensionDefinition` |
| `metadata`   | YES      | Extension metadata |
| `spec`       | YES      | Extension vocabulary, dependencies, and validation rules |

`metadata.name` MUST identify the extension without its version segment.

`metadata.version` MUST identify the extension version.

`metadata.name` and `metadata.version` together MUST form a valid extension identifier as defined in Section 10.1.

The canonical extension identifier is:

```text
<metadata.name>/<metadata.version>
```

For example:

```yaml
metadata:
  name: runtimeconditions.io/common-capabilities
  version: v1alpha1
```

defines:

```text
runtimeconditions.io/common-capabilities/v1alpha1
```

## 11.2 Extension Spec Fields

| Field             | Required | Description |
| ----------------- | -------- | ----------- |
| `dependencies`    | NO       | Exact extension identifiers required by this extension |
| `bundle`          | NO       | Whether this extension is only a dependency bundle. Defaults to `false` |
| `kinds`           | NO       | Condition kinds owned by this extension |
| `interfaceTypes`  | NO       | Interface types owned by this extension |
| `conditionFields` | NO       | Condition-level fields owned by this extension |
| `interfaceFields` | NO       | Interface-level fields owned by this extension |
| `fieldValues`     | NO       | Field values owned by this extension |
| `validationRules` | NO       | Semantic validation rules defined by this extension |

An extension with `bundle: true` MUST declare at least one dependency and MUST NOT define `kinds`, `interfaceTypes`, `conditionFields`, `interfaceFields`, `fieldValues`, or `validationRules`.

An extension with `bundle` omitted or set to `false` MUST define at least one owned vocabulary item or validation rule.

## 11.3 Vocabulary Declaration Fields

Each entry in `kinds` MUST include:

| Field | Required | Description |
| ----- | -------- | ----------- |
| `name` | YES | Condition kind owned by the extension |

Each entry in `interfaceTypes` MUST include:

| Field        | Required | Description |
| ------------ | -------- | ----------- |
| `name`       | YES      | Interface type owned by the extension |
| `targetKind` | YES      | Condition kind for which the interface type is valid |

Each entry in `conditionFields` MUST include:

| Field                     | Required | Description |
| ------------------------- | -------- | ----------- |
| `name`                    | YES      | Condition-level field owned by the extension |
| `appliesToKinds`          | NO       | Kinds to which the field applies |
| `appliesToInterfaceTypes` | NO       | Interface types to which the field applies within the applicable kinds |
| `appliesToAllKinds`       | NO       | Whether the field may apply to all Conditions. Defaults to `false` |

Each `conditionFields` entry MUST declare either a non-empty `appliesToKinds` list or `appliesToAllKinds: true`.

If `appliesToInterfaceTypes` is omitted, the field applies to all interface types for the applicable kinds unless narrowed by extension-defined validation rules.

Each entry in `interfaceFields` MUST include:

| Field        | Required | Description |
| ------------ | -------- | ----------- |
| `name`       | YES      | Interface-level field owned by the extension |
| `targetKind` | YES      | Condition kind for which the field is valid |
| `targetType` | YES      | Interface type for which the field is valid |

Each entry in `fieldValues` MUST include:

| Field        | Required | Description |
| ------------ | -------- | ----------- |
| `field`      | YES      | Field path whose allowed values are being defined |
| `targetKind` | YES      | Condition kind scope for the value |
| `targetType` | NO       | Interface type scope for the value |
| `values`     | YES      | Non-empty list of field values owned by the extension |

Each `fieldValues.values` list MUST contain unique values.

Each entry in `validationRules` MUST include:

| Field | Required | Description |
| ----- | -------- | ----------- |
| `id`  | YES      | Rule identifier unique within the extension |

Validation rule expression language is not defined by this draft. Extension specifications MUST describe validation behavior in sufficient detail for independent implementations to produce equivalent results.

## 11.4 Extension Definition Example

```yaml
apiVersion: runtimeconditions.io/v1alpha1
kind: ValidationExtensionDefinition

metadata:
  name: cache.compat/valkey
  version: v1alpha1

spec:

  dependencies:
    - runtimeconditions.io/common-capabilities/v1alpha1

  fieldValues:
    - field: interface.engine
      targetKind: cache
      targetType: key_value
      values:
        - valkey

  validationRules:
    - id: cache-engine-valkey
      appliesToKind: cache
      appliesToInterfaceType: key_value
      rule: interface.engine may be valkey wherever interface.engine is valid
```

---

# 12. Extension Capabilities

Extensions MAY:


| Action              | Description                               |
| ------------------- | ----------------------------------------- |
| Add Kind            | Introduce a Condition kind                |
| Add Interface Type  | Define interface types for a kind         |
| Add Condition Field | Extend the Condition object shape         |
| Add Interface Field | Extend interface schema                   |
| Add Field Value     | Define allowed values for a field in a specific scope |
| Add Rules           | Add semantic validation                   |
| Add Dependencies    | Require other extensions                  |
| Add Bundle          | Group extensions without changing their semantics |


---

# 13. Extension Compatibility Rules

Extensions MUST:

- Preserve core semantics
- Not redefine or narrow the meaning of core fields
- Not invalidate profiles outside the extension's declared vocabulary scope

Extensions SHOULD use namespaced identifiers where they introduce vocabulary that is vendor-specific, platform-specific, or likely to conflict with shared vocabulary.

Extensions MAY define unqualified vocabulary for broadly shared semantics, such as `postgres` as an engine value, but each unqualified vocabulary item MUST have exactly one owner in the resolved extension set.

Extensions MAY add field values only where those values are semantically compatible with the field, declared `kind`, and declared `interface.type`.

Extensions MAY add new Condition fields when the field does not conflict with core fields and does not alter the meaning of any core field. Extension-defined Condition fields MUST declare the kinds to which they apply, or MUST explicitly declare that they may apply to all Conditions. Extension-defined Condition fields SHOULD also declare applicable interface types when validity depends on `interface.type`.

---

# 14. Extension-Defined Field Placement

Extensions MAY define fields in the following locations:

- As additional fields on a Condition object
- As additional fields within `condition.interface`

Extensions MUST NOT define additional top-level profile fields.

Extensions MUST NOT define additional fields within `metadata` or `workload`.

Extensions MUST NOT redefine, replace, or change the meaning of core fields.

The following top-level field names are reserved by the core specification:

- `apiVersion`
- `kind`
- `metadata`
- `workload`
- `extensions`
- `conditions`

The following Condition field names are reserved by the core specification:

- `name`
- `kind`
- `interface`
- `optional`

The following interface field name is reserved by the core specification:

- `type`

Future versions of the core specification MAY define additional reserved field names. Extension authors SHOULD use namespaced field names for experimental or organization-specific fields to reduce collision risk.

---

# 15. Vocabulary Ownership and Conflict Resolution

Every extension-defined vocabulary item has an ownership scope.

Ownership scope is determined by:

- Vocabulary category, such as Condition kind, interface type, Condition field, interface field, or field value
- Field path, when the vocabulary item is a field value
- Target Condition `kind`, when applicable
- Target `interface.type`, when applicable

A profile is invalid if the resolved extension set contains more than one owner for the same vocabulary item in the same ownership scope.

For example, if two resolved extensions both define `postgres` as an allowed value for `interface.engine` when `kind: datastore` and `interface.type: relational`, the profile is invalid.

An extension that wants to use vocabulary owned by another extension MUST declare a dependency on that extension and reference the existing vocabulary. It MUST NOT redefine that vocabulary.

Profile generators SHOULD detect extension vocabulary conflicts before generating a profile. Profile validators MUST reject profiles whose resolved extension sets contain vocabulary ownership conflicts.

---

# 16. Namespacing Requirements

Extension-defined vocabulary SHOULD use namespaced identifiers to avoid collisions with core or other extension-defined elements.

Namespacing applies to:

- Extension-defined `kind` values
- Extension-defined `interface.type` values
- Extension-defined Condition field names
- Extension-defined interface field names
- Extension-defined field values when the value is not intended to be shared vocabulary

Namespacing typically uses a prefix that identifies the originating organization or vendor.

Extension-defined vocabulary MAY use unqualified names only when the name is defined by exactly one resolved extension in its ownership scope and can be resolved unambiguously during validation.

Examples of valid namespaced identifiers:

```yaml
kind: aws.object_store
interface:
  type: aws.s3
```

```yaml
kind: api
interface:
  type: acme.soap
```

Values defined within existing fields, such as `engine`, do not require namespacing unless necessary to prevent
collisions.

---

# 17. Unknown Extension Handling

Profiles MAY reference extension-defined vocabulary through the `extensions` declaration.

If a profile references extension-defined vocabulary that cannot be resolved through its declared extensions, the profile MUST be considered invalid.

This includes cases where:

- A `kind` value is not defined in any resolved extension
- An `interface.type` value is not defined in any resolved extension for the declared `kind`
- A Condition field defined by an extension is used without the corresponding extension being declared
- An interface field defined by an extension is used without the corresponding extension being declared
- A field value defined by an extension is used without the corresponding extension being declared
- A declared extension cannot be located or resolved during validation

Validation systems MUST reject Conditions that rely on unknown or unresolved extension-defined vocabulary.

---

# 18. Validation Layers

Validation occurs in the following order:

1. Core structural validation
2. Extension declaration resolution
3. Extension dependency and bundle expansion
4. Vocabulary ownership and conflict validation
5. Extension semantic validation

---

# 19. Conformance

This specification defines conformance for profiles, extensions, generators, validators, and resolvers.

## 19.1 Profile Conformance

A conforming Runtime Conditions Profile MUST:

- Satisfy all core structural requirements
- Declare all required extensions directly or through resolvable dependencies or bundles
- Avoid unresolved vocabulary
- Avoid vocabulary ownership conflicts
- Satisfy all semantic validation rules for resolved extensions
- Avoid concrete target-environment values and secret values
- Use labels only for classification, governance, ownership, policy, reporting, and lifecycle workflows around the profile

## 19.2 Extension Conformance

A conforming extension MUST:

- Use a valid extension identifier
- Provide a valid extension definition artifact
- Identify all vocabulary it owns
- Declare exact-version dependencies on vocabulary owned by other extensions
- Avoid redefining vocabulary owned by another resolved extension
- Provide deterministic validation rules that can be implemented independently
- Respect core field placement and reserved-name rules

## 19.3 Generator Conformance

A conforming generator MUST emit structurally valid profiles.

A conforming generator SHOULD fail before emitting a profile that contains unresolved vocabulary, missing extensions, extension dependency errors, or known vocabulary ownership conflicts.

A conforming generator MUST NOT emit secret values or concrete target-environment connection values into a profile, including within labels.

## 19.4 Validator Conformance

A conforming validator MUST implement the validation layers defined by this specification.

A conforming validator MUST reject structurally invalid profiles, unresolved extensions, extension dependency cycles, vocabulary ownership conflicts, unresolved vocabulary, and semantic validation failures.

A conforming validator SHOULD report diagnostics using the minimum error categories defined in Section 8.5.

## 19.5 Resolver Conformance

A resolver is a tool that interprets a valid Runtime Conditions Profile for a target platform, deployment workflow, catalog, or policy system.

A conforming resolver MUST NOT treat a structurally valid but extension-unresolved profile as semantically valid.

A conforming resolver MUST preserve the distinction between requirements declared by a profile and concrete fulfillment choices made for a target environment.

---

# 20. Example: Core-Only Structural Profile

This profile is valid against the core specification, but it does not describe any runtime dependencies because no extension-defined Condition vocabulary is declared.

```yaml
apiVersion: runtimeconditions.io/v1alpha1
kind: RuntimeConditionsProfile

metadata:
  name: structural-profile
  labels:
    owner.example.com/team: platform
    lifecycle.example.com/stage: development

workload:
  uri: https://github.com/example-org/example-service
  version: v1.2.3

extensions: []

conditions: []
```

---

# 21. Example: Extension-Backed Profile

This profile declares meaningful runtime dependencies by using extension-defined vocabulary.

```yaml
apiVersion: runtimeconditions.io/v1alpha1
kind: RuntimeConditionsProfile

metadata:
  name: checkout-service
  labels:
    compliance.example.com/hipaa: "true"
    compliance.example.com/sox: "true"
    owner.example.com/team: payments
    lifecycle.example.com/stage: production

workload:
  uri: https://github.com/example-org/checkout-service
  version: v1.2.3

extensions:
  - runtimeconditions.io/common-capabilities/v1alpha1

conditions:
  - name: primary-db
    kind: datastore
    interface:
      type: relational
      engine: postgres

  - name: payments-api
    kind: api
    interface:
      type: http
      operations:
        - method: POST
          path: /charge
```

---

# 22. Summary

The Runtime Conditions Profile defines:

- A portable dependency profile envelope
- Machine-readable profile labels for classification, policy, ownership, and lifecycle workflows
- A core Condition object contract
- A base interface structure
- Deterministic validation behavior
- A declarative extension mechanism
- Vendor-neutral structural semantics and extension governance

This provides a foundation for reliable extension-backed capability matching while preserving ecosystem flexibility.
