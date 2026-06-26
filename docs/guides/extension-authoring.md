# Extension Authoring Guide

## Status

**Non-normative implementation guidance**

This guide documents the repository convention for writing Runtime Conditions extension definitions. The core profile draft defines the extension document shape. This guide explains how extension authors should use that shape so extensions compose cleanly.

---

# 1. Ownership

An extension definition owns only the vocabulary it introduces.

An extension MAY define:

- Condition kinds
- Interface types
- Condition fields
- Interface fields
- Allowed field values
- JSON Schema validation rules

An extension MUST NOT redefine vocabulary owned by another extension. If it needs to build on that vocabulary, it must declare a dependency and reference the dependency-owned kind, interface type, or field in scoped definitions.

---

# 2. Base Extensions

A base extension introduces vocabulary directly.

The Common Integrations extension owns common application integration vocabulary:

```yaml
apiVersion: runtimeconditions.io/v1alpha1
kind: RuntimeConditionsExtensionDefinition

metadata:
  uri: https://runtimeconditions.io/extensions/common-integrations
  version: v1alpha1

spec:
  kinds:
    - name: api
    - name: datastore
    - name: cache

  interfaceTypes:
    - name: http
      targetKind: api
    - name: relational
      targetKind: datastore
    - name: document
      targetKind: datastore
    - name: key_value
      targetKind: cache
```

Because this extension owns `api`, `datastore`, `cache`, `http`, `relational`, `document`, and `key_value`, other extensions must not redefine them.

---

# 3. Additive Extensions

An additive extension builds on dependency-owned vocabulary without copying it.

The Environment Configuration extension adds the `configuration` field to common integration Conditions. It does not redefine common's kinds or interface types:

```yaml
apiVersion: runtimeconditions.io/v1alpha1
kind: RuntimeConditionsExtensionDefinition

metadata:
  uri: https://runtimeconditions.io/extensions/env-configuration
  version: v1alpha1

spec:
  dependencies:
    - https://runtimeconditions.io/extensions/common-integrations:v1alpha1

  conditionFields:
    - name: configuration
      appliesToKinds:
        - api
      appliesToInterfaceTypes:
        - http
    - name: configuration
      appliesToKinds:
        - datastore
      appliesToInterfaceTypes:
        - relational
        - document
    - name: configuration
      appliesToKinds:
        - cache
      appliesToInterfaceTypes:
        - key_value
```

The dependency makes the referenced common vocabulary available. The additive extension owns only `configuration` and the rules for values inside that field.

---

# 4. Field Values

Use `fieldValues` to define allowed values for extension-owned fields in a specific vocabulary scope.

```yaml
fieldValues:
  - field: configuration.env[].property
    targetKind: api
    targetType: http
    values:
      - url
      - baseUrl
      - hostname
      - port
      - scheme
      - username
      - password
      - token
      - tls

  - field: configuration.env[].property
    targetKind: cache
    targetType: key_value
    values:
      - url
      - hostname
      - port
      - scheme
      - username
      - password
      - database
      - token
      - tls
```

The field path is owned by the additive extension. The target kind and interface type may come from the same extension or from a declared dependency.

---

# 5. Schemas

Extension schemas should validate the fields owned by that extension and leave unrelated fields open.

```yaml
schemas:
  - id: configuration-shape
    description: Validates the environment configuration field shape.
    schema:
      $schema: https://json-schema.org/draft/2020-12/schema
      type: object
      properties:
        configuration:
          type: object
          oneOf:
            - required:
                - env
            - required:
                - alternatives
      additionalProperties: true
```

Use `appliesToKind` and `appliesToInterfaceType` when a schema is valid only for one target scope:

```yaml
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
      additionalProperties: true
```

Schemas from multiple resolved extensions apply additively. A Condition must satisfy every schema whose scope matches it.

---

# 6. Go Declaration Packages

Go declaration packages should mirror extension ownership.

A base extension package exports the declarations and option types for the vocabulary it owns:

```go
package commonintegrations

type APIOption interface {
	CommonIntegrationsAPIOption()
}

type CacheOption interface {
	CommonIntegrationsCacheOption()
}

func API(name string, options ...APIOption) Declaration {
	return Declaration{}
}

func Cache(name string, options ...CacheOption) Declaration {
	return Declaration{}
}
```

An additive extension package exports only its own options. It may import a base package so its options can satisfy the base package's marker interfaces:

```go
package envconfiguration

import common "github.com/colinjlacy/runtime-conditions-profiles/extensions/common-integrations/go"

type ConditionOption interface {
	common.APIOption
	common.DatastoreOption
	common.CacheOption
	envConfigurationConditionOption()
}

type conditionOption struct{}

func (conditionOption) CommonIntegrationsAPIOption()       {}
func (conditionOption) CommonIntegrationsDatastoreOption() {}
func (conditionOption) CommonIntegrationsCacheOption()     {}
func (conditionOption) envConfigurationConditionOption()   {}

func Env(property, name string, options ...EnvOption) ConditionOption {
	return conditionOption{}
}
```

Application code imports both packages when it uses both extensions:

```go
import (
	common "github.com/colinjlacy/runtime-conditions-profiles/extensions/common-integrations/go"
	env "github.com/colinjlacy/runtime-conditions-profiles/extensions/env-configuration/go"
)

var _ = common.Cache("request-cache",
	common.KeyValue(common.Redis),
	env.EnvAlternative(env.Env("url", "REDIS_URL")),
)
```

The generated profile lists both extensions because both packages directly contributed vocabulary:

```yaml
extensions:
  - https://runtimeconditions.io/extensions/common-integrations:v1alpha1
  - https://runtimeconditions.io/extensions/env-configuration:v1alpha1
```

If a workload imports only `common-integrations/go`, the profile lists only `common-integrations`. If it imports `env-configuration/go` but does not apply an env option to a Condition, the profile does not list `env-configuration`.

Adapters and validators still resolve transitive extension dependencies from extension definitions. Direct profile declarations and dependency resolution are separate steps.

---

# 7. Package Manifest Option Augmentation

The package manifest for a base declaration package maps source calls to Conditions:

```yaml
go:
  importPath: github.com/colinjlacy/runtime-conditions-profiles/extensions/common-integrations/go
  package: commonintegrations

  declarations:
    - function: Cache
      nameArg: 0
      kind: cache
      options:
        - function: KeyValue
          target: interface.type
          value: key_value
          engineArg: 0
```

The package manifest for an option-only extension maps source calls to fields that can augment compatible Conditions:

```yaml
go:
  importPath: github.com/colinjlacy/runtime-conditions-profiles/extensions/env-configuration/go
  package: envconfiguration

  options:
    - function: Env
      target: configuration.env[]
      appliesToKinds:
        - api
        - datastore
        - cache
      stringArgs:
        property: 0
        name: 1
```

Generators use `go.options` only when an option call appears inside a compatible declaration call. Standalone option calls are ignored for profile emission.

---

# 8. Authoring Checklist

- Define only vocabulary your extension owns.
- Declare dependencies for vocabulary you reference but do not own.
- Scope additive fields to the dependency-owned kinds and interface types they augment.
- Use `fieldValues` for portable, adapter-visible enums.
- Use JSON Schema for machine-readable validation.
- Keep schemas focused on your extension's fields and allow unrelated properties.
- Export only declaration functions for vocabulary your package owns.
- For additive Go packages, export typed options that satisfy base package marker interfaces.
- Describe additive Go options with package-level `go.options` mappings.
- Do not encode secrets, concrete target-environment values, or provider-specific fulfillment choices.
