package io.runtimeconditions.profiler;

import java.util.Objects;

final class RuntimeConditionsDiagnostic {
    enum Severity {
        ERROR
    }

    private final Severity severity;
    private final String code;
    private final String source;
    private final String message;

    RuntimeConditionsDiagnostic(Severity severity, String code, String source, String message) {
        this.severity = Objects.requireNonNull(severity, "severity");
        this.code = Objects.requireNonNull(code, "code");
        this.source = source == null ? "" : source;
        this.message = Objects.requireNonNull(message, "message");
    }

    Severity severity() {
        return severity;
    }

    String code() {
        return code;
    }

    String source() {
        return source;
    }

    String message() {
        return message;
    }
}
