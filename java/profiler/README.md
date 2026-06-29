# Java Profiler

The Java profiler starts with build-tool-aware artifact discovery.

Current implementation:

- Detects Maven, Gradle, or source-only project layouts.
- Discovers Runtime Conditions artifacts in Java resource layout:
  - `META-INF/runtimeconditions/runtimeconditions.bindings.yaml`
  - `META-INF/runtimeconditions/runtimeconditions.package.yaml`
  - `META-INF/runtimeconditions/runtimeconditions.extension.yaml`
- Discovers the same artifacts in JAR classpath entries.
- Supports repository-local source layouts where the manifest is placed at the package root.

Not implemented yet:

- Java AST or bytecode extraction.
- Maven Resolver or Gradle Tooling API dependency graph integration.
- Profile generation.

## Compile and Run

```sh
javac -d /tmp/runtimeconditions-java-profiler \
  src/main/java/io/runtimeconditions/profiler/*.java

java -cp /tmp/runtimeconditions-java-profiler \
  io.runtimeconditions.profiler.ProfilerCli discover --project src/testdata/maven-app
```

## Test

```sh
javac -d /tmp/runtimeconditions-java-profiler-test \
  src/main/java/io/runtimeconditions/profiler/*.java \
  src/test/java/io/runtimeconditions/profiler/ArtifactDiscoveryTest.java

java -cp /tmp/runtimeconditions-java-profiler-test \
  io.runtimeconditions.profiler.ArtifactDiscoveryTest src/testdata
```

