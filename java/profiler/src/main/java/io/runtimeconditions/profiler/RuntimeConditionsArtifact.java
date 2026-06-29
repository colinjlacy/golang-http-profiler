package io.runtimeconditions.profiler;

import java.nio.file.Path;
import java.util.Objects;

final class RuntimeConditionsArtifact {
    enum Kind {
        BINDING,
        PACKAGE
    }

    private final Kind kind;
    private final String manifestUri;
    private final String extensionUri;
    private final String origin;
    private final Path sourcePath;

    RuntimeConditionsArtifact(Kind kind, String manifestUri, String extensionUri, String origin, Path sourcePath) {
        this.kind = Objects.requireNonNull(kind, "kind");
        this.manifestUri = Objects.requireNonNull(manifestUri, "manifestUri");
        this.extensionUri = extensionUri;
        this.origin = Objects.requireNonNull(origin, "origin");
        this.sourcePath = sourcePath;
    }

    Kind kind() {
        return kind;
    }

    String manifestUri() {
        return manifestUri;
    }

    String extensionUri() {
        return extensionUri;
    }

    String origin() {
        return origin;
    }

    Path sourcePath() {
        return sourcePath;
    }
}

