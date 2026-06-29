package io.runtimeconditions.profiler;

import java.util.List;
import java.util.Map;
import java.util.Objects;

final class JavaSymbolMapping {
    private final String className;
    private final String memberName;
    private final String memberField;
    private final String target;
    private final String kind;
    private final String interfaceType;
    private final String value;
    private final String method;
    private final Integer nameArg;
    private final Integer classArg;
    private final Integer enumArg;
    private final Map<String, Integer> stringArgs;
    private final List<String> appliesToKinds;
    private final List<String> appliesToInterfaceTypes;
    private final List<JavaSymbolMapping> options;

    JavaSymbolMapping(
            String className,
            String memberName,
            String memberField,
            String target,
            String kind,
            String interfaceType,
            String value,
            String method,
            Integer nameArg,
            Integer classArg,
            Integer enumArg,
            Map<String, Integer> stringArgs,
            List<String> appliesToKinds,
            List<String> appliesToInterfaceTypes,
            List<JavaSymbolMapping> options) {
        this.className = className;
        this.memberName = memberName;
        this.memberField = memberField;
        this.target = target;
        this.kind = kind;
        this.interfaceType = interfaceType;
        this.value = value;
        this.method = method;
        this.nameArg = nameArg;
        this.classArg = classArg;
        this.enumArg = enumArg;
        this.stringArgs = Map.copyOf(Objects.requireNonNull(stringArgs, "stringArgs"));
        this.appliesToKinds = List.copyOf(Objects.requireNonNull(appliesToKinds, "appliesToKinds"));
        this.appliesToInterfaceTypes = List.copyOf(Objects.requireNonNull(appliesToInterfaceTypes, "appliesToInterfaceTypes"));
        this.options = List.copyOf(Objects.requireNonNull(options, "options"));
    }

    String className() {
        return className;
    }

    String memberName() {
        return memberName;
    }

    String memberField() {
        return memberField;
    }

    String target() {
        return target;
    }

    String kind() {
        return kind;
    }

    String interfaceType() {
        return interfaceType;
    }

    String value() {
        return value;
    }

    String method() {
        return method;
    }

    Integer nameArg() {
        return nameArg;
    }

    Integer classArg() {
        return classArg;
    }

    Integer enumArg() {
        return enumArg;
    }

    Map<String, Integer> stringArgs() {
        return stringArgs;
    }

    List<String> appliesToKinds() {
        return appliesToKinds;
    }

    List<String> appliesToInterfaceTypes() {
        return appliesToInterfaceTypes;
    }

    List<JavaSymbolMapping> options() {
        return options;
    }
}
