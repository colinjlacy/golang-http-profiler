# Java Profiler

The Java profiler starts with build-tool-aware artifact discovery.

Current implementation:

- Detects Maven, Gradle, or source-only project layouts.
- Resolves build-tool classpath entries through Maven or Gradle when `--resolve-build-classpath` is used.
  - Maven uses `./mvnw` when present, otherwise `mvn`.
  - Gradle uses `./gradlew` when present, otherwise `gradle`.
- Discovers Runtime Conditions artifacts in Java resource layout:
  - `META-INF/runtimeconditions/runtimeconditions.bindings.yaml`
  - `META-INF/runtimeconditions/runtimeconditions.package.yaml`
  - `META-INF/runtimeconditions/runtimeconditions.extension.yaml`
- Discovers the same artifacts in JAR classpath entries.
- Supports repository-local source layouts where the manifest is placed at the package root.
- Validates discovered artifacts before they can be used by future extraction:
  - manifest kind and `metadata.language`
  - required Java manifest section
  - package-local `runtimeconditions.extension.yaml`
  - manifest extension ID against extension definition `metadata.id`
  - duplicate extension definitions and unresolved extension dependencies across discovered artifacts

Not implemented yet:

- Java AST or bytecode extraction.
- Embedded Maven Resolver or Gradle Tooling API integration.
- Profile generation.

## Compile and Run

```sh
javac -d /tmp/runtimeconditions-java-profiler \
  src/main/java/io/runtimeconditions/profiler/*.java

java -cp /tmp/runtimeconditions-java-profiler \
  io.runtimeconditions.profiler.ProfilerCli discover \
  --project src/testdata/maven-app \
  --resolve-build-classpath
```

## Test

```sh
javac -d /tmp/runtimeconditions-java-profiler-test \
  src/main/java/io/runtimeconditions/profiler/*.java \
  src/test/java/io/runtimeconditions/profiler/ArtifactDiscoveryTest.java \
  src/test/java/io/runtimeconditions/profiler/ClasspathResolverTest.java \
  src/test/java/io/runtimeconditions/profiler/ManifestValidationTest.java

java -cp /tmp/runtimeconditions-java-profiler-test \
  io.runtimeconditions.profiler.ArtifactDiscoveryTest src/testdata

java -cp /tmp/runtimeconditions-java-profiler-test \
  io.runtimeconditions.profiler.ClasspathResolverTest

java -cp /tmp/runtimeconditions-java-profiler-test \
  io.runtimeconditions.profiler.ManifestValidationTest src/testdata
```
