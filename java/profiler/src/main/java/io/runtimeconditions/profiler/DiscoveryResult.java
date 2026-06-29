package io.runtimeconditions.profiler;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

final class DiscoveryResult {
    private final Path projectRoot;
    private final BuildTool buildTool;
    private final List<Path> modules;
    private final List<Path> classpathEntries;
    private final List<RuntimeConditionsArtifact> artifacts;
    private final List<ValidatedRuntimeConditionsArtifact> validatedArtifacts;

    DiscoveryResult(
            Path projectRoot,
            BuildTool buildTool,
            List<Path> modules,
            List<Path> classpathEntries,
            List<RuntimeConditionsArtifact> artifacts,
            List<ValidatedRuntimeConditionsArtifact> validatedArtifacts) {
        this.projectRoot = Objects.requireNonNull(projectRoot, "projectRoot");
        this.buildTool = Objects.requireNonNull(buildTool, "buildTool");
        this.modules = List.copyOf(modules);
        this.classpathEntries = List.copyOf(classpathEntries);
        this.artifacts = List.copyOf(artifacts);
        this.validatedArtifacts = List.copyOf(validatedArtifacts);
    }

    Path projectRoot() {
        return projectRoot;
    }

    BuildTool buildTool() {
        return buildTool;
    }

    List<Path> modules() {
        return modules;
    }

    List<Path> classpathEntries() {
        return classpathEntries;
    }

    List<RuntimeConditionsArtifact> artifacts() {
        return artifacts;
    }

    List<ValidatedRuntimeConditionsArtifact> validatedArtifacts() {
        return validatedArtifacts;
    }

    List<RuntimeConditionsDiagnostic> diagnostics() {
        List<RuntimeConditionsDiagnostic> diagnostics = new ArrayList<>();
        for (ValidatedRuntimeConditionsArtifact artifact : validatedArtifacts) {
            diagnostics.addAll(artifact.diagnostics());
        }
        return List.copyOf(diagnostics);
    }

    boolean hasErrors() {
        return diagnostics().stream()
                .anyMatch(diagnostic -> diagnostic.severity() == RuntimeConditionsDiagnostic.Severity.ERROR);
    }
}
