package io.runtimeconditions.profiler;

import java.nio.file.Path;
import java.util.List;

final class DiscoveryOptions {
    private final List<Path> classpathEntries;
    private final boolean resolveBuildClasspath;

    DiscoveryOptions(List<Path> classpathEntries, boolean resolveBuildClasspath) {
        this.classpathEntries = List.copyOf(classpathEntries);
        this.resolveBuildClasspath = resolveBuildClasspath;
    }

    List<Path> classpathEntries() {
        return classpathEntries;
    }

    boolean resolveBuildClasspath() {
        return resolveBuildClasspath;
    }
}

