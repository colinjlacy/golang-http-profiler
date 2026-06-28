package extensioncheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type javaBindingManifest struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Extension           string `yaml:"extension"`
		ExtensionDefinition string `yaml:"extensionDefinition"`
		Language            string `yaml:"language"`
	} `yaml:"metadata"`
	Java javaBindingSection `yaml:"java"`
}

type javaBindingSection struct {
	Package      string                        `yaml:"package"`
	Class        string                        `yaml:"class"`
	Constants    map[string]string             `yaml:"constants"`
	Declarations []javaBindingDeclarationEntry `yaml:"declarations"`
	Options      []javaBindingOptionEntry      `yaml:"options"`
}

type javaBindingDeclarationEntry struct {
	Class    string                   `yaml:"class"`
	Function string                   `yaml:"function"`
	Options  []javaBindingOptionEntry `yaml:"options"`
}

type javaBindingOptionEntry struct {
	Class    string                   `yaml:"class"`
	Function string                   `yaml:"function"`
	Options  []javaBindingOptionEntry `yaml:"options"`
}

func TestFirstPartyJavaBindingConvention(t *testing.T) {
	tests := []string{
		repoPath(t, "extensions", "common-integrations", "java", goBindingsManifest),
		repoPath(t, "extensions", "env-configuration", "java", goBindingsManifest),
	}
	for _, path := range tests {
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			manifest := readJavaBindingManifest(t, path)
			if manifest.APIVersion != "runtimeconditions.io/v1alpha1" {
				t.Fatalf("apiVersion = %q", manifest.APIVersion)
			}
			if manifest.Kind != "RuntimeConditionsBinding" {
				t.Fatalf("kind = %q", manifest.Kind)
			}
			if manifest.Metadata.Extension == "" {
				t.Fatal("metadata.extension is required")
			}
			if manifest.Metadata.ExtensionDefinition == "" {
				t.Fatal("metadata.extensionDefinition is required for repository-local Java fixtures")
			}
			if manifest.Metadata.Language != "java" {
				t.Fatalf("metadata.language = %q", manifest.Metadata.Language)
			}
			if manifest.Java.Package == "" {
				t.Fatal("java.package is required")
			}
			if manifest.Java.Class != "" {
				t.Fatal("top-level java.class must not be used; Java bindings use per-entry class")
			}
			if len(manifest.Java.Declarations) == 0 && len(manifest.Java.Options) == 0 {
				t.Fatal("java.declarations or java.options must not be empty")
			}
			for constant := range manifest.Java.Constants {
				assertJavaConstantExists(t, manifest, path, constant)
			}
			for _, declaration := range manifest.Java.Declarations {
				assertJavaDeclarationEntry(t, manifest, path, declaration)
			}
			for _, option := range manifest.Java.Options {
				assertJavaOptionEntry(t, manifest, path, option)
			}
		})
	}
}

func TestJavaDeclarationFixtureDocumentsExpectedCallShape(t *testing.T) {
	path := filepath.Join("testdata", "java-declarations", "request-logger", "RequestLogger.java")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	expected := []string{
		"Api.declare(\"todos-api\"",
		"Api.spec(\"openapi\"",
		"Http.get(\"/todos/{id}\"",
		"Http.response(Todo.class)",
		"Cache.declare(\"request-cache\"",
		"Cache.keyValue(Cache.Engine.REDIS)",
		"EnvConfiguration.env(\"baseUrl\", \"TODOS_API_URL\")",
		"EnvConfiguration.envAlternative(EnvConfiguration.env(\"url\", \"REDIS_URL\"))",
		"Datastore.declare(\"primary-store\"",
		"Datastore.relational(Datastore.Engine.POSTGRES)",
	}
	for _, item := range expected {
		if !strings.Contains(source, item) {
			t.Fatalf("%s does not contain %q", path, item)
		}
	}
}

func TestValidateBindingManifestInfersJavaLanguage(t *testing.T) {
	path := repoPath(t, "extensions", "common-integrations", "java", goBindingsManifest)
	if err := ValidateBindingManifest(path, Options{}); err != nil {
		t.Fatal(err)
	}
}

func TestJavaDeclarationFixtureCompilesWhenJavacIsAvailable(t *testing.T) {
	javac, err := exec.LookPath("javac")
	if err != nil {
		t.Skip("javac is not available")
	}
	version := exec.Command(javac, "-version")
	if output, err := version.CombinedOutput(); err != nil {
		if strings.Contains(string(output), "Unable to locate a Java Runtime") {
			t.Skip("javac launcher is available, but no Java runtime is installed")
		}
		t.Fatalf("javac -version failed: %v\n%s", err, output)
	}
	out := t.TempDir()
	sources := []string{
		repoPath(t, "extensions", "common-integrations", "java", "src", "main", "java", "io", "runtimeconditions", "extensions", "commonintegrations", "Api.java"),
		repoPath(t, "extensions", "common-integrations", "java", "src", "main", "java", "io", "runtimeconditions", "extensions", "commonintegrations", "Http.java"),
		repoPath(t, "extensions", "common-integrations", "java", "src", "main", "java", "io", "runtimeconditions", "extensions", "commonintegrations", "Cache.java"),
		repoPath(t, "extensions", "common-integrations", "java", "src", "main", "java", "io", "runtimeconditions", "extensions", "commonintegrations", "Datastore.java"),
		repoPath(t, "extensions", "env-configuration", "java", "src", "main", "java", "io", "runtimeconditions", "extensions", "envconfiguration", "EnvConfiguration.java"),
		filepath.Join("testdata", "java-declarations", "request-logger", "RequestLogger.java"),
	}
	args := append([]string{"-d", out}, sources...)
	cmd := exec.Command(javac, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("javac failed: %v\n%s", err, output)
	}
}

func readJavaBindingManifest(t *testing.T, path string) javaBindingManifest {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest javaBindingManifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func assertJavaDeclarationEntry(t *testing.T, manifest javaBindingManifest, manifestPath string, entry javaBindingDeclarationEntry) {
	t.Helper()
	assertJavaStaticMethodExists(t, manifest, manifestPath, entry.Class, entry.Function)
	for _, option := range entry.Options {
		assertJavaOptionEntry(t, manifest, manifestPath, option)
	}
}

func assertJavaOptionEntry(t *testing.T, manifest javaBindingManifest, manifestPath string, entry javaBindingOptionEntry) {
	t.Helper()
	assertJavaStaticMethodExists(t, manifest, manifestPath, entry.Class, entry.Function)
	for _, option := range entry.Options {
		assertJavaOptionEntry(t, manifest, manifestPath, option)
	}
}

func assertJavaStaticMethodExists(t *testing.T, manifest javaBindingManifest, manifestPath string, className string, function string) {
	t.Helper()
	if className == "" {
		t.Fatalf("%s: Java binding entry for function %q is missing class", manifestPath, function)
	}
	if function == "" {
		t.Fatalf("%s: Java binding entry for class %q is missing function", manifestPath, className)
	}
	source := readJavaClassSource(t, manifest, manifestPath, className)
	pattern := regexp.MustCompile(`public\s+static(?:\s+<[^>]+>)?\s+[\w<>\[\].?]+\s+` + regexp.QuoteMeta(function) + `\s*\(`)
	if !pattern.MatchString(source) {
		t.Fatalf("%s: %s.%s is not declared as a public static method", manifestPath, className, function)
	}
}

func assertJavaConstantExists(t *testing.T, manifest javaBindingManifest, manifestPath string, constant string) {
	t.Helper()
	parts := strings.Split(constant, ".")
	if len(parts) < 2 {
		t.Fatalf("%s: Java constant %q must include class and constant name", manifestPath, constant)
	}
	className := parts[0]
	constantName := parts[len(parts)-1]
	source := readJavaClassSource(t, manifest, manifestPath, className)
	if !regexp.MustCompile(`\b` + regexp.QuoteMeta(constantName) + `\b`).MatchString(source) {
		t.Fatalf("%s: Java constant %s is not declared in %s", manifestPath, constant, className)
	}
}

func readJavaClassSource(t *testing.T, manifest javaBindingManifest, manifestPath string, className string) string {
	t.Helper()
	path := javaClassSourcePath(manifest, manifestPath, className)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func javaClassSourcePath(manifest javaBindingManifest, manifestPath string, className string) string {
	sourceRoot := filepath.Join(filepath.Dir(manifestPath), "src", "main", "java")
	packagePath := filepath.Join(strings.Split(manifest.Java.Package, ".")...)
	return filepath.Join(sourceRoot, packagePath, className+".java")
}
