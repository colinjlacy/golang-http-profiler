# Java Runtime Conditions

This tree contains Java-native Runtime Conditions tooling.

## Layout

- `profiler/`: Java profiler module. The initial implementation discovers Runtime Conditions package artifacts from Maven and Gradle project layouts; Java source extraction is not implemented yet.

The Java profiler is intentionally separate from the Go profiler. Shared behavior should live in manifest conventions, extension validation, profile validation, and cross-language fixtures, not in a Go parser for Java source.

