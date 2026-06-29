package io.runtimeconditions.profiler;

import java.util.List;
import java.util.Map;
import java.util.Objects;

final class JavaManifestModel {
    private final String packageName;
    private final Map<String, String> constants;
    private final List<JavaSymbolMapping> declarations;
    private final List<JavaSymbolMapping> options;

    JavaManifestModel(
            String packageName,
            Map<String, String> constants,
            List<JavaSymbolMapping> declarations,
            List<JavaSymbolMapping> options) {
        this.packageName = packageName;
        this.constants = Map.copyOf(Objects.requireNonNull(constants, "constants"));
        this.declarations = List.copyOf(Objects.requireNonNull(declarations, "declarations"));
        this.options = List.copyOf(Objects.requireNonNull(options, "options"));
    }

    String packageName() {
        return packageName;
    }

    Map<String, String> constants() {
        return constants;
    }

    List<JavaSymbolMapping> declarations() {
        return declarations;
    }

    List<JavaSymbolMapping> options() {
        return options;
    }
}
