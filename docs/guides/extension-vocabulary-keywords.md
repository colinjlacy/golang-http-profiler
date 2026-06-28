# Extension Vocabulary Keywords

## Status

**Non-normative implementation guidance**

This guide explains how to choose the vocabulary keywords inside a `RuntimeConditionsExtensionDefinition`. The core draft defines the extension document shape. This guide explains authoring intent and the first-party tooling expectations that make an extension easier to validate, bind to code, and generate from source.

---

# 1. Keyword Decision Table

| Authoring intent | Use | Defines |
| ---- | ---- | ---- |
| Add a new Condition category | `spec.kinds` | Values for `conditions[].kind` |
| Add a new interface type for a kind | `spec.interfaceTypes` | Values for `conditions[].interface.type` |
| Add a new top-level Condition field | `spec.conditionFields` | Fields beside `name`, `kind`, `interface`, and other Condition fields |
| Add a new field under `interface` | `spec.interfaceFields` | Fields inside `conditions[].interface` |
| Define allowed values for a field path | `spec.fieldValues` | Portable string values for an already-defined field path |
| Validate object shape or conditional rules | `spec.schemas` | JSON Schema rules for matching Conditions |
| Reuse vocabulary owned by another extension | `spec.dependencies` | Extension definitions that must be resolved before validation |

`runtimeconditions.bindings.yaml` and `runtimeconditions.package.yaml` do not define vocabulary. They map language package symbols to vocabulary already defined by extension YAML.

---

# 2. Kinds

Use `kinds` when the extension introduces a new Condition category.

```yaml
spec:
  kinds:
    - name: aws.object_store
```

A kind is the outer integration category. It should be stable enough for adapters to route to platform capabilities. Avoid creating a kind for every operation unless each operation has materially different runtime requirements.

First-party tooling expects each kind name to have exactly one owner in the resolved extension set.

---

# 3. Interface Types

Use `interfaceTypes` when a kind can be fulfilled through one or more concrete interface shapes.

```yaml
spec:
  interfaceTypes:
    - name: aws.s3
      targetKind: aws.object_store
```

This defines `interface.type: aws.s3` only for `kind: aws.object_store`.

Do not use `interfaceFields` to define `interface.type`. Interface type values belong in `interfaceTypes`.

---

# 4. Condition Fields

Use `conditionFields` to define an extension-owned field at the Condition object level.

```yaml
spec:
  conditionFields:
    - name: configuration
      appliesToKinds:
        - cache
      appliesToInterfaceTypes:
        - key_value
```

This permits a Condition shape like:

```yaml
conditions:
  - name: request-cache
    kind: cache
    interface:
      type: key_value
    configuration:
      env:
        - property: url
          name: REDIS_URL
```

The `conditionFields` entry defines ownership of the top-level `configuration` field. It does not define every nested property under `configuration`; use `fieldValues` for portable value sets and `schemas` for object shape.

For first-party tooling support:

- `appliesToKinds` must be non-empty.
- Every referenced kind must resolve through the extension or its dependencies.
- Every `appliesToInterfaceTypes` value must resolve for each referenced kind.
- Condition fields with the same name must not have overlapping scopes.

---

# 5. Interface Fields

Use `interfaceFields` to define an extension-owned field inside `interface`.

```yaml
spec:
  interfaceFields:
    - name: bucketClass
      targetKind: aws.object_store
      targetType: aws.s3
```

This permits a Condition shape like:

```yaml
conditions:
  - name: s3-object-store
    kind: aws.object_store
    interface:
      type: aws.s3
      bucketClass: standard
```

Interface fields are scoped to one kind and one interface type. If the field has a controlled set of adapter-visible values, define those values with `fieldValues`.

---

# 6. Field Values

Use `fieldValues` to define allowed string values for an already-defined field path in a specific scope.

```yaml
spec:
  fieldValues:
    - field: interface.bucketClass
      targetKind: aws.object_store
      targetType: aws.s3
      values:
        - standard
        - archive
```

`fieldValues` is for vocabulary that generators, validators, and adapters should treat as portable. It should not be used for user-specific configuration values, secret values, target environment identifiers, or values that only a specific adapter understands.

`fieldValues` does not create the field. The field path must resolve to either:

- `interface.type`, which is backed by `interfaceTypes`.
- An `interfaceFields` entry for the same `targetKind` and `targetType`.
- A `conditionFields` entry whose scope includes the declared `targetKind` and optional `targetType`.

Values inside a single `fieldValues` entry must be unique. First-party tooling currently treats `fieldValues.values` as strings.

---

# 7. Field Path Semantics

Field paths are dot-separated paths rooted in either the Condition object or the `interface` object.

| Path form | Meaning |
| ---- | ---- |
| `interface.type` | The interface type value defined by `interfaceTypes` |
| `interface.<field>` | A field inside `conditions[].interface`, defined by `interfaceFields` |
| `<conditionField>.<child>` | A nested field under a top-level Condition field defined by `conditionFields` |
| `[]` | Array item traversal, such as `configuration.env[].property` |

Examples:

```yaml
fieldValues:
  - field: interface.engine
    targetKind: cache
    targetType: key_value
    values:
      - redis
      - memcached

  - field: configuration.env[].property
    targetKind: cache
    targetType: key_value
    values:
      - url
      - hostname
      - port
```

The first path resolves through `interfaceFields` for `interface.engine`. The second path resolves through a `conditionFields` definition for the top-level `configuration` field. The nested `env[]` and `property` segments are validated by JSON Schema and by the `fieldValues` entry.

Avoid creating `fieldValues` for a path whose root field is not owned by the extension or one of its dependencies.

---

# 8. Schemas

Use `schemas` to validate structure, required fields, conditional rules, and non-enum constraints.

```yaml
spec:
  schemas:
    - id: configuration-properties-cache-key-value
      appliesToKind: cache
      appliesToInterfaceType: key_value
      description: Validates allowed environment configuration properties for key/value cache integrations.
      schema:
        type: object
        properties:
          configuration:
            type: object
            properties:
              env:
                type: array
                items:
                  type: object
                  required:
                    - property
                    - name
        additionalProperties: true
```

Schemas apply additively. A Condition must satisfy every schema whose scope matches its `kind` and `interface.type`.

Prefer `fieldValues` for portable enum-like values and `schemas` for object shape. Most non-trivial fields need both:

- `conditionFields` defines the field root.
- `fieldValues` defines portable choices inside that field.
- `schemas` validates the nested structure.

---

# 9. Dependencies

Use `dependencies` when an extension references vocabulary it does not own.

```yaml
spec:
  dependencies:
    - https://runtimeconditions.io/extensions/common-integrations/v1alpha1/runtimeconditions.extension.yaml

  conditionFields:
    - name: configuration
      appliesToKinds:
        - cache
      appliesToInterfaceTypes:
        - key_value
```

In this example, the additive extension owns `configuration`, but `cache` and `key_value` are dependency-owned vocabulary.

Do not copy dependency-owned kinds, interface types, fields, or field values into the new extension. Declare the dependency and reference the existing vocabulary.

---

# 10. Tooling-Ready Checklist

Before treating an extension as first-party tooling-ready:

- Define only vocabulary the extension owns.
- Declare dependencies for referenced vocabulary the extension does not own.
- Make every `fieldValues.field` path resolve to a condition or interface field in the declared target scope.
- Use `fieldValues` for portable string values, not deployment-specific data.
- Use JSON Schema to validate nested object shape.
- Scope schemas to resolved kinds and interface types.
- Avoid overlapping `conditionFields` definitions.
- Keep declaration bindings or package manifests separate from extension vocabulary.
- Validate the extension and its dependency graph with first-party tooling.
