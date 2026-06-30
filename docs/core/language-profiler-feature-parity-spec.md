# Language Profiler Feature Parity Specification

## Status

Draft implementation target

## Purpose

This document defines the minimum feature set for adding a new first-party language profiler that reaches parity with the current declarative-binding profiler behavior.

It is intended to be handed to an implementation agent as a concrete build target. The target is not "parse source code and emit something plausible." The target is:

```text
resolved language packages
  -> runtimeconditions.bindings.yaml
  -> runtimeconditions.extension.yaml
  -> dependency extension definitions
  -> validated cumulative extension set
  -> source usage mapped to Conditions
  -> generated Runtime Conditions Profile
  -> profile validation
```

This document describes first-party tooling behavior. It does not add fields to the Runtime Conditions Profile spec and does not make code generation required for a hand-written profile to be valid.

---

# 1. Scope

A language profiler that implements this specification supports declarative Runtime Conditions binding packages.

In scope:

- Language-native project discovery.
- Language-native dependency or package resolution.
- Discovery of Runtime Conditions package artifacts.
- Validation of extension definitions and binding manifests before extraction.
- Source parsing with language-native symbol or type analysis.
- Profile generation from declarative helper calls.
- Profile validation against the resolved extension vocabulary.
- A request logger demo equivalent to `demos/apps/request-logger-http/`.
- Test fixtures that prove valid and invalid authoring behavior.
- Golden profile fixtures that lock expected output.

Out of scope for this parity target:

- SDK/runtime `runtimeconditions.package.yaml` extraction.
- Automatic generation of declarative binding code from extension YAML.
- Extension JSON Schema execution during profile validation.
- Adapter output, Kubernetes resources, Kratix resources, or platform fulfillment logic.

---

# 2. Naming and Repository Layout

Language-specific files must not repeat the language name when the directory already provides that context.

Required pattern:

```text
<language>/profiler/
  README.md
  <language package/build files>
  <profiler entrypoint>
  src/ or package source files
  testdata/
```

Examples:

```text
python/profiler/profiler.py
javascript/profiler/src/profiler.ts
typescript/profiler/src/profiler.ts
rust/profiler/src/main.rs
java/profiler/src/main/java/io/runtimeconditions/profiler/ProfilerCli.java
```

Do not create names such as:

```text
python/profiler/python_profiler.py
javascript/profiler/javascript-profiler.ts
rust/profiler/rust_profiler.rs
```

The directory names carry the language identity. File names should describe the role: `profiler`, `extractor`, `validator`, `resolver`, `discovery`, `cli`, or the ecosystem's conventional entrypoint.

---

# 3. Required Commands

Each language profiler must expose these user-facing actions, even if the exact flag syntax follows language or ecosystem conventions:

| Command | Required | Purpose |
| ---- | ---- | ---- |
| `discover` | YES | Print discovered project metadata, resolved artifacts, Runtime Conditions manifests, extension definitions, and diagnostics. |
| `generate` | YES | Generate a Runtime Conditions Profile from source declarations. |
| `validate-extension` | YES | Validate one extension package and its binding manifest for the target language. |
| `validate-extensions` | YES | Validate all discovered extension packages under a root or package set for the target language. |

The profiler must be runnable as an independent tool from the repository checkout. If the ecosystem supports an executable package, archive, binary, or script wrapper, the profiler should provide one.

Examples:

```text
python/profiler/profiler.py generate ...
node javascript/profiler/dist/profiler.js generate ...
cargo run --manifest-path rust/profiler/Cargo.toml -- generate ...
java -jar java/profiler/target/runtimeconditions-java-profiler-0.1.0-SNAPSHOT.jar generate ...
```

---

# 4. Package Artifact Discovery

The profiler must discover Runtime Conditions metadata from the language's normal package resolution model. It must not crawl arbitrary global dependency caches looking for manifests.

The profiler must recognize these files:

```text
runtimeconditions.bindings.yaml
runtimeconditions.extension.yaml
```

It may also discover `runtimeconditions.package.yaml`, but SDK/runtime extraction is not part of this parity target.

## 4.1 Binding Packages

A declarative binding package provides:

```text
runtimeconditions.bindings.yaml
runtimeconditions.extension.yaml
declarative source files
```

The binding manifest must use:

```yaml
apiVersion: runtimeconditions.io/v1alpha1
kind: RuntimeConditionsBinding

metadata:
  extension: <extension id URI>
  language: <language id>

<language-specific section>: {}
```

The language-specific section maps source symbols to extension-owned vocabulary. It must not define vocabulary itself.

## 4.2 Extension Definition Loading

The profiler must load the package-local `runtimeconditions.extension.yaml` next to the manifest when present.

For local development and fixtures, the profiler may support a manifest-local override path. The override must resolve relative to the manifest and must point to an extension definition whose `metadata.id` exactly matches the manifest extension ID.

## 4.3 Dependency Closure

After loading the direct extension definition, the profiler must recursively resolve extension IDs listed in:

```yaml
spec:
  dependencies:
    - <extension id URI>
```

The implementation may support local roots, package-local artifacts, configured catalogs, or ecosystem package metadata as resolver inputs. The implementation must fail with an actionable diagnostic when a dependency cannot be resolved.

---

# 5. Required Validation

Validation must happen before source extraction is trusted.

The profiler must validate:

- Manifest `apiVersion`.
- Manifest `kind`.
- Manifest `metadata.language`.
- Manifest extension ID.
- Package-local extension definition existence.
- Manifest extension ID equals extension definition `metadata.id`.
- Extension definition `apiVersion`.
- Extension definition `kind`.
- Extension definition `metadata.id`.
- Extension dependency closure.
- Duplicate extension IDs in the resolved set.
- Cycles in extension dependencies.
- Vocabulary conflicts in the resolved set.
- Binding references to unknown kinds, interface types, fields, field values, or unsupported targets.
- Binding source symbols exist in the declarative package when source is available.
- Binding argument indexes are valid for the mapped source symbol when source signatures are available.
- Generated profile core shape.
- Generated profile extension dependency closure.
- Generated profile condition `kind`.
- Generated profile `interface.type`.
- Generated profile interface fields and field values.
- Generated profile condition fields and field values.

The implementation must report diagnostics that include:

- A diagnostic category or code.
- The source file or artifact when available.
- The invalid path, symbol, or vocabulary term.
- The reason validation failed.

---

# 6. Source Analysis Requirements

The profiler must use the target language's native parsing, AST, symbol, type, or compiler facilities where available.

It must support:

- Direct imports of declaration classes/functions/modules.
- Wildcard or grouped imports where the language supports them.
- Static or member imports where the language supports them.
- Fully qualified declaration calls where the language supports them.
- Cross-file string constants used as declaration names, paths, URIs, environment variable names, or other static values.
- Constant or enum-like values mapped through the binding manifest.
- Nested option calls.
- Class/type literals or language-equivalent schema references when the binding manifest supports schema extraction.
- Multi-file projects.
- Multi-module or multi-package projects when the ecosystem supports them.

The profiler must not execute workload code.

The profiler may execute the language package manager or build tool to resolve dependencies, compile metadata, or classpaths when that is the normal ecosystem behavior.

---

# 7. Declarative Binding Behavior

The profiler must map source declarations into Conditions using only binding manifests and resolved extension vocabulary.

The current parity target requires support for these Condition shapes:

## 7.1 HTTP API Condition

Declaration should produce:

```yaml
name: todos-api
kind: api
interface:
  type: http
  spec:
    format: openapi
    uri: catalog://api/default/todos-api
    version: 1.0.0
  operations:
    - method: GET
      path: /todos/{id}
      responseSchema:
        id: integer
        title: string
        completed: boolean
configuration:
  env:
    - property: baseUrl
      name: TODOS_API_URL
```

Required mapping features:

- Declaration name argument.
- Static API spec option.
- HTTP operation option.
- Response schema from a local type/class/model.
- Configuration env option from a dependency extension.

## 7.2 Redis Cache Condition

Declaration should produce:

```yaml
name: request-cache
kind: cache
interface:
  type: key_value
  engine: redis
configuration:
  alternatives:
    - env:
        - property: url
          name: REDIS_URL
    - env:
        - property: hostname
          name: REDIS_HOST
        - property: port
          name: REDIS_PORT
```

Required mapping features:

- Declaration name argument.
- Enum or constant-backed interface value.
- Nested configuration alternatives.
- Multiple env entries inside one alternative.
- Transitive extension closure: using env configuration should include both `env-configuration` and its dependency `common-integrations`.

---

# 8. Profile Output Requirements

Generated profiles must include:

```yaml
apiVersion: runtimeconditions.io/v1alpha1
kind: RuntimeConditionsProfile
metadata:
  name: <profile name>
workload:
  uri: <workload uri>
  version: <workload version>
extensions:
  - <direct and transitive extension ids>
conditions:
  - ...
```

The `extensions` list must contain the direct and transitive extension closure required by emitted Conditions. It must not include an imported but unused extension package.

The profiler must produce deterministic output:

- Deterministic extension ordering.
- Deterministic condition ordering based on source traversal.
- Deterministic map/object ordering where the language serializer permits it.
- Stable golden fixture output.

---

# 9. Required Fixtures

Each language profiler must include file-backed fixtures under its profiler testdata directory.

Recommended layout:

```text
<language>/profiler/testdata/
  authoring/
  profile-generation/
  golden/
```

If the ecosystem convention requires a different testdata location, the same logical structure must still be present.

## 9.1 Authoring Fixtures

The authoring fixture runner must read a fixture config file for each case:

```yaml
valid: true
wantErrorContains: <optional diagnostic substring>
```

Required authoring cases:

| Fixture | Expected | Purpose |
| ---- | ---- | ---- |
| `base-valid` | pass | Minimal valid binding manifest, extension definition, and source declaration. |
| `binding-kind-mismatch-invalid` | fail | Manifest kind is not `RuntimeConditionsBinding`. |
| `binding-language-mismatch-invalid` | fail | Manifest language does not match the profiler language. |
| `binding-vocabulary-invalid` | fail | Binding references vocabulary not defined by the resolved extension set. |
| `missing-function-invalid` | fail | Manifest maps a source function/method that does not exist. |
| `non-string-name-arg-invalid` | fail | Name argument points to a non-string value. |
| `bad-string-arg-index-invalid` | fail | String argument index is out of range or points to the wrong type. |
| `bad-class-or-schema-arg-invalid` | fail | Schema/class/type argument is out of range or points to an unsupported value. |
| `constant-mismatch-invalid` | fail | Binding constant value does not match source constant or enum value. |
| `duplicate-extension-id-invalid` | fail | Two discovered definitions use the same extension ID from different artifacts. |
| `unresolved-dependency-invalid` | fail | Extension dependency cannot be resolved. |
| `transitive-dependency-valid` | pass | Extension A depends on B, B depends on C, and bindings validate against the closure. |
| `vocabulary-conflict-invalid` | fail | Resolved extensions define conflicting kinds, interface types, fields, or field values. |
| `overlapping-field-invalid` | fail | Two extensions claim the same condition field for overlapping kind/interface scopes. |

These fixtures must exercise real files, not only in-memory strings.

## 9.2 Profile Generation Fixtures

Required profile generation fixtures:

| Fixture | Purpose |
| ---- | ---- |
| `declarative-app` | Baseline app that emits API and cache Conditions. |
| `wildcard-import` | Uses wildcard/grouped imports for declaration symbols. |
| `semantic-resolution` | Uses cross-file constants, imported models, static/member imports, and fully qualified calls where supported. |
| `unused-extension` | Imports or references an extension package symbol outside a Condition declaration; generated profile must not include the unused extension. |
| `request-logger-http` | Demo fixture that mirrors `demos/apps/request-logger-http/`. |

Each fixture must have a golden profile file. The test must fail when generated YAML differs from the golden output.

## 9.3 Build Tool or Package Manager Fixtures

The profiler must include fixtures for the target language's package manager or build tool.

Examples:

- Python: `pyproject.toml`, virtualenv/import metadata, editable local package.
- JavaScript/TypeScript: `package.json`, lockfile, local workspace package.
- Rust: `Cargo.toml`, workspace member, path dependency.
- Java: Maven project, Gradle project, classpath/JAR artifact.

The tests must prove:

- Project type detection.
- Module/workspace member discovery.
- Resolved package/artifact inspection.
- Manifest discovery from package output or package source layout.
- Explicit development override paths.

---

# 10. Request Logger Demo Requirement

Each language implementation must add a demo equivalent to:

```text
demos/apps/request-logger-http/
```

Recommended layout:

```text
demos/apps/request-logger-http-<language>/
  <language package/build metadata>
  Dockerfile
  source files
```

The demo must:

- Be buildable using the target language's normal toolchain.
- Include explicit Runtime Conditions declarations in source.
- Declare the same Conditions as the Go request logger.
- Include an HTTP readiness endpoint or equivalent simple runtime behavior where reasonable.
- Read the same environment variables:
  - `TODOS_API_URL`
  - `REDIS_URL`
  - `REDIS_HOST`
  - `REDIS_PORT`
- Be profiled by the language profiler without special-case demo logic.

The generated profile must include exactly these condition names:

```text
todos-api
request-cache
```

The generated profile must include these extension IDs:

```text
https://runtimeconditions.io/extensions/common-integrations/v1alpha1/runtimeconditions.extension.yaml
https://runtimeconditions.io/extensions/env-configuration/v1alpha1/runtimeconditions.extension.yaml
```

---

# 11. Required Test Commands

Each profiler must document one primary test command that runs the full language profiler test suite.

Examples:

```text
python -m pytest python/profiler
npm test --workspace javascript/profiler
cargo test --manifest-path rust/profiler/Cargo.toml
mvn -q test -f java/profiler/pom.xml
```

The primary test command must run:

- Artifact discovery tests.
- Package manager/build tool resolver tests.
- Authoring fixture validation tests.
- Profile generation golden tests.
- Request logger demo profile generation test.

Each profiler must also document one command that builds the runnable profiler tool and one command that generates the request logger demo profile.

---

# 12. Acceptance Criteria

A new language profiler reaches this parity target when all of the following are true:

1. The profiler has a language-native project under `<language>/profiler/`.
2. No file inside that project repeats the language name as a redundant prefix or suffix.
3. The profiler can run `discover`, `generate`, `validate-extension`, and `validate-extensions`.
4. The profiler discovers `runtimeconditions.bindings.yaml` and `runtimeconditions.extension.yaml` from resolved packages or development roots.
5. The profiler validates extension definitions, dependency closure, binding manifests, source symbols, generated profile vocabulary, and profile extension closure.
6. The profiler uses language-native AST/symbol/type analysis and does not execute workload code.
7. The profiler emits deterministic profile YAML.
8. The required authoring fixtures pass or fail for documented reasons.
9. The required profile generation fixtures match golden outputs.
10. The request logger demo builds.
11. The profiler generates a request logger profile with the same Conditions as the Go demo.
12. The primary language test command passes.
13. Existing Go profiler tests and extension validation still pass.

---

# 13. Implementation Notes for Agents

Do not start by designing a new extension vocabulary. Use the existing first-party extensions:

```text
extensions/common-integrations/
extensions/env-configuration/
```

Do not invent new manifest filenames. Use:

```text
runtimeconditions.bindings.yaml
runtimeconditions.package.yaml
runtimeconditions.extension.yaml
```

Do not make the profiler depend on another language profiler for parsing or source extraction. Shared behavior may be reimplemented or eventually moved into a common validator library, but the language profiler must remain native to its language's project and source model.

Do not special-case the request logger demo. It must pass through the same artifact discovery, manifest validation, source analysis, extraction, and profile validation path as any other workload.

Do not treat package-manager caches as catalogs to scan. Resolve dependencies through the language's normal project metadata, then inspect only the resolved packages, modules, artifacts, workspaces, source sets, or explicit development roots.
