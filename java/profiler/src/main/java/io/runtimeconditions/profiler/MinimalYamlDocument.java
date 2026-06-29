package io.runtimeconditions.profiler;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class MinimalYamlDocument {
    private final Map<String, String> scalars;
    private final Map<String, List<String>> sequences;
    private final Set<String> sections;

    private MinimalYamlDocument(Map<String, String> scalars, Map<String, List<String>> sequences, Set<String> sections) {
        this.scalars = Map.copyOf(scalars);
        Map<String, List<String>> copiedSequences = new HashMap<>();
        for (Map.Entry<String, List<String>> entry : sequences.entrySet()) {
            copiedSequences.put(entry.getKey(), List.copyOf(entry.getValue()));
        }
        this.sequences = Map.copyOf(copiedSequences);
        this.sections = Set.copyOf(sections);
    }

    static MinimalYamlDocument parse(String source) {
        Map<String, String> scalars = new LinkedHashMap<>();
        Map<String, List<String>> sequences = new LinkedHashMap<>();
        Set<String> sections = new HashSet<>();
        List<PathPart> stack = new ArrayList<>();
        String[] lines = source.split("\\R");
        for (String rawLine : lines) {
            if (rawLine.isBlank()) {
                continue;
            }
            int indent = leadingSpaces(rawLine);
            String line = rawLine.trim();
            if (line.startsWith("#")) {
                continue;
            }
            while (!stack.isEmpty() && indent <= stack.get(stack.size() - 1).indent()) {
                stack.remove(stack.size() - 1);
            }
            if (line.startsWith("- ")) {
                if (!stack.isEmpty()) {
                    String key = join(stack);
                    sequences.computeIfAbsent(key, ignored -> new ArrayList<>()).add(trimScalar(line.substring(2).trim()));
                }
                continue;
            }
            int colon = line.indexOf(':');
            if (colon < 1) {
                continue;
            }
            String key = line.substring(0, colon).trim();
            String value = line.substring(colon + 1).trim();
            if (indent == 0) {
                sections.add(key);
            }
            List<String> path = new ArrayList<>();
            for (PathPart part : stack) {
                path.add(part.key());
            }
            path.add(key);
            if (value.isEmpty()) {
                stack.add(new PathPart(indent, key));
            } else {
                scalars.put(String.join(".", path), trimScalar(value));
            }
        }
        return new MinimalYamlDocument(scalars, sequences, sections);
    }

    String scalar(String... path) {
        return scalars.get(String.join(".", path));
    }

    List<String> sequence(String... path) {
        return sequences.getOrDefault(String.join(".", path), List.of());
    }

    boolean hasSection(String section) {
        return sections.contains(section);
    }

    private static int leadingSpaces(String value) {
        int spaces = 0;
        while (spaces < value.length() && value.charAt(spaces) == ' ') {
            spaces++;
        }
        return spaces;
    }

    private static String join(List<PathPart> path) {
        List<String> keys = new ArrayList<>();
        for (PathPart part : path) {
            keys.add(part.key());
        }
        return String.join(".", keys);
    }

    private static String trimScalar(String value) {
        if (value.length() >= 2) {
            char first = value.charAt(0);
            char last = value.charAt(value.length() - 1);
            if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
                return value.substring(1, value.length() - 1);
            }
        }
        return value;
    }

    private static final class PathPart {
        private final int indent;
        private final String key;

        private PathPart(int indent, String key) {
            this.indent = indent;
            this.key = key;
        }

        private int indent() {
            return indent;
        }

        private String key() {
            return key;
        }
    }
}
