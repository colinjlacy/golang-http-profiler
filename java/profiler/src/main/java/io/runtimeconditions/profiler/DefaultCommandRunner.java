package io.runtimeconditions.profiler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

final class DefaultCommandRunner implements CommandRunner {
    private static final long TIMEOUT_SECONDS = 120;

    @Override
    public CommandResult run(List<String> command, Path workingDirectory) throws IOException {
        Process process = new ProcessBuilder(command)
                .directory(workingDirectory.toFile())
                .start();
        try {
            if (!process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                throw new IOException("command timed out after " + TIMEOUT_SECONDS + "s: " + String.join(" ", command));
            }
            String stdout = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            String stderr = new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
            return new CommandResult(process.exitValue(), stdout, stderr);
        } catch (InterruptedException e) {
            process.destroyForcibly();
            Thread.currentThread().interrupt();
            throw new IOException("interrupted while running command: " + String.join(" ", command), e);
        }
    }
}

