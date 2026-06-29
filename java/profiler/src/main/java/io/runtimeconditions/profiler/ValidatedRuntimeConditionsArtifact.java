package io.runtimeconditions.profiler;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

final class ValidatedRuntimeConditionsArtifact {
    private final RuntimeConditionsArtifact artifact;
    private final String manifestExtensionId;
    private final String extensionId;
    private final String extensionDefinitionUri;
    private final ExtensionDefinitionModel extensionDefinition;
    private final JavaManifestModel javaManifest;
    private final List<String> dependencies;
    private final List<RuntimeConditionsDiagnostic> diagnostics;

    ValidatedRuntimeConditionsArtifact(
            RuntimeConditionsArtifact artifact,
            String manifestExtensionId,
            String extensionId,
            String extensionDefinitionUri,
            ExtensionDefinitionModel extensionDefinition,
            JavaManifestModel javaManifest,
            List<String> dependencies,
            List<RuntimeConditionsDiagnostic> diagnostics) {
        this.artifact = Objects.requireNonNull(artifact, "artifact");
        this.manifestExtensionId = manifestExtensionId;
        this.extensionId = extensionId;
        this.extensionDefinitionUri = extensionDefinitionUri;
        this.extensionDefinition = extensionDefinition;
        this.javaManifest = javaManifest;
        this.dependencies = List.copyOf(dependencies);
        this.diagnostics = new ArrayList<>(diagnostics);
    }

    RuntimeConditionsArtifact artifact() {
        return artifact;
    }

    String manifestExtensionId() {
        return manifestExtensionId;
    }

    String extensionId() {
        return extensionId;
    }

    String extensionDefinitionUri() {
        return extensionDefinitionUri;
    }

    ExtensionDefinitionModel extensionDefinition() {
        return extensionDefinition;
    }

    JavaManifestModel javaManifest() {
        return javaManifest;
    }

    List<String> dependencies() {
        return dependencies;
    }

    List<RuntimeConditionsDiagnostic> diagnostics() {
        return List.copyOf(diagnostics);
    }

    void addDiagnostic(RuntimeConditionsDiagnostic diagnostic) {
        diagnostics.add(Objects.requireNonNull(diagnostic, "diagnostic"));
    }
}
