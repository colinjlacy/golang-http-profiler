package io.runtimeconditions.profiler;

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

final class DiscoveryResult {
    private final Path projectRoot;
    private final BuildTool buildTool;
    private final List<Path> modules;
    private final List<RuntimeConditionsArtifact> artifacts;

    DiscoveryResult(Path projectRoot, BuildTool buildTool, List<Path> modules, List<RuntimeConditionsArtifact> artifacts) {
        this.projectRoot = Objects.requireNonNull(projectRoot, "projectRoot");
        this.buildTool = Objects.requireNonNull(buildTool, "buildTool");
        this.modules = List.copyOf(modules);
        this.artifacts = List.copyOf(artifacts);
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

    List<RuntimeConditionsArtifact> artifacts() {
        return artifacts;
    }
}

