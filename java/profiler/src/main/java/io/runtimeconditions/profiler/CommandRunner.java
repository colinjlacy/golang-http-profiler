package io.runtimeconditions.profiler;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

interface CommandRunner {
    CommandResult run(List<String> command, Path workingDirectory) throws IOException;
}

