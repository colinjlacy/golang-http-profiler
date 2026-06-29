package io.runtimeconditions.profiler;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

final class BuildToolClasspathResolver {
    private final CommandRunner commandRunner;

    BuildToolClasspathResolver() {
        this(new DefaultCommandRunner());
    }

    BuildToolClasspathResolver(CommandRunner commandRunner) {
        this.commandRunner = commandRunner;
    }

    List<Path> resolve(Path projectRoot, BuildTool buildTool, List<Path> modules) throws IOException {
        return switch (buildTool) {
            case MAVEN -> new MavenClasspathResolver(commandRunner).resolve(projectRoot, modules);
            case GRADLE -> new GradleClasspathResolver(commandRunner).resolve(projectRoot, modules);
            case SOURCE_ONLY -> List.of();
        };
    }
}

