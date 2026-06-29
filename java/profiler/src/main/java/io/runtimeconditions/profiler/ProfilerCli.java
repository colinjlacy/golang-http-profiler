package io.runtimeconditions.profiler;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class ProfilerCli {
    private ProfilerCli() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0 || "discover".equals(args[0])) {
            discover(args.length == 0 ? new String[0] : dropFirst(args));
            return;
        }
        throw new IllegalArgumentException("unknown command: " + args[0]);
    }

    private static void discover(String[] args) throws Exception {
        Path project = Path.of(".");
        List<Path> classpath = new ArrayList<>();
        boolean json = false;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--project" -> project = Path.of(requireValue(args, ++i, "--project"));
                case "--classpath" -> classpath.addAll(splitClasspath(requireValue(args, ++i, "--classpath")));
                case "--json" -> json = true;
                default -> throw new IllegalArgumentException("unknown flag: " + args[i]);
            }
        }

        DiscoveryResult result = new JavaProjectDiscovery().discover(project, classpath);
        if (json) {
            printJson(result);
            return;
        }
        printText(result);
    }

    private static String[] dropFirst(String[] args) {
        String[] result = new String[args.length - 1];
        System.arraycopy(args, 1, result, 0, result.length);
        return result;
    }

    private static String requireValue(String[] args, int index, String flag) {
        if (index >= args.length) {
            throw new IllegalArgumentException(flag + " requires a value");
        }
        return args[index];
    }

    private static List<Path> splitClasspath(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        String[] parts = value.split(java.io.File.pathSeparator);
        List<Path> result = new ArrayList<>();
        for (String part : parts) {
            if (!part.isBlank()) {
                result.add(Path.of(part));
            }
        }
        return result;
    }

    private static void printText(DiscoveryResult result) {
        System.out.println("project: " + result.projectRoot());
        System.out.println("buildTool: " + result.buildTool().name().toLowerCase());
        for (Path module : result.modules()) {
            System.out.println("module: " + module);
        }
        for (RuntimeConditionsArtifact artifact : result.artifacts()) {
            System.out.println("artifact: kind=" + artifact.kind().name().toLowerCase()
                    + " manifest=" + artifact.manifestUri()
                    + " extension=" + nullToEmpty(artifact.extensionUri())
                    + " origin=" + artifact.origin());
        }
    }

    private static void printJson(DiscoveryResult result) {
        StringBuilder out = new StringBuilder();
        out.append("{\n");
        out.append("  \"project\": \"").append(json(result.projectRoot().toString())).append("\",\n");
        out.append("  \"buildTool\": \"").append(result.buildTool().name().toLowerCase()).append("\",\n");
        out.append("  \"modules\": [");
        for (int i = 0; i < result.modules().size(); i++) {
            if (i > 0) {
                out.append(", ");
            }
            out.append("\"").append(json(result.modules().get(i).toString())).append("\"");
        }
        out.append("],\n");
        out.append("  \"artifacts\": [\n");
        for (int i = 0; i < result.artifacts().size(); i++) {
            RuntimeConditionsArtifact artifact = result.artifacts().get(i);
            out.append("    {");
            out.append("\"kind\": \"").append(artifact.kind().name().toLowerCase()).append("\", ");
            out.append("\"manifest\": \"").append(json(artifact.manifestUri())).append("\", ");
            out.append("\"extension\": ");
            if (artifact.extensionUri() == null) {
                out.append("null");
            } else {
                out.append("\"").append(json(artifact.extensionUri())).append("\"");
            }
            out.append(", \"origin\": \"").append(json(artifact.origin())).append("\"");
            out.append("}");
            if (i + 1 < result.artifacts().size()) {
                out.append(",");
            }
            out.append("\n");
        }
        out.append("  ]\n");
        out.append("}\n");
        System.out.print(out);
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private static String json(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}

