package io.runtimeconditions.profiler;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

final class MavenClasspathResolver implements ClasspathResolver {
    private final CommandRunner commandRunner;

    MavenClasspathResolver(CommandRunner commandRunner) {
        this.commandRunner = commandRunner;
    }

    @Override
    public List<Path> resolve(Path projectRoot, List<Path> modules) throws IOException {
        Path root = projectRoot.toAbsolutePath().normalize();
        Set<Path> entries = ClasspathEntries.set();

        Path outputFile = Files.createTempFile("runtimeconditions-maven-classpath", ".txt");
        List<String> command = new ArrayList<>();
        command.add(mavenExecutable(root).toString());
        command.add("-q");
        command.add("-DincludeScope=runtime");
        command.add("-Dmdep.outputFile=" + outputFile);
        command.add("process-resources");
        command.add("dependency:build-classpath");

        CommandResult result = commandRunner.run(command, root);
        if (result.exitCode() != 0) {
            throw new IOException("Maven classpath resolution failed with exit code "
                    + result.exitCode()
                    + ": "
                    + commandOutput(result));
        }
        if (Files.isRegularFile(outputFile)) {
            for (Path entry : ClasspathEntries.parse(Files.readString(outputFile), root)) {
                entries.add(entry);
            }
        }
        addMavenOutput(entries, root);
        for (Path module : modules) {
            addMavenOutput(entries, module);
        }
        Files.deleteIfExists(outputFile);
        return ClasspathEntries.sortedInsertionOrder(entries);
    }

    private Path mavenExecutable(Path root) {
        Path wrapper = root.resolve(isWindows() ? "mvnw.cmd" : "mvnw");
        if (Files.isRegularFile(wrapper)) {
            return wrapper;
        }
        return Path.of("mvn");
    }

    private void addMavenOutput(Set<Path> entries, Path project) {
        ClasspathEntries.addIfExists(entries, project.resolve("target/classes"));
        ClasspathEntries.addIfExists(entries, project.resolve("target/test-classes"));
    }

    private boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    private String commandOutput(CommandResult result) {
        String output = (result.stderr() + "\n" + result.stdout()).trim();
        return output.isEmpty() ? "<no output>" : output;
    }
}
