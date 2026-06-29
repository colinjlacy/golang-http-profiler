package io.runtimeconditions.profiler;

final class JavaProfileOptions {
    private final String name;
    private final String workloadUri;
    private final String workloadVersion;
    private final DiscoveryOptions discoveryOptions;

    JavaProfileOptions(String name, String workloadUri, String workloadVersion, DiscoveryOptions discoveryOptions) {
        this.name = name;
        this.workloadUri = workloadUri;
        this.workloadVersion = workloadVersion;
        this.discoveryOptions = discoveryOptions;
    }

    String name() {
        return name;
    }

    String workloadUri() {
        return workloadUri;
    }

    String workloadVersion() {
        return workloadVersion;
    }

    DiscoveryOptions discoveryOptions() {
        return discoveryOptions;
    }
}
