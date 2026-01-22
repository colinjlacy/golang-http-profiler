package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ObservedBehaviors represents the input format from the profiler
type ObservedBehaviors struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec ObservedBehaviorsSpec `yaml:"spec"`
}

type ObservedBehaviorsSpec struct {
	GeneratedAt        string              `yaml:"generatedAt"`
	ObservationEngines []ObservationEngine `yaml:"observationEngines"`
	Environment        Environment         `yaml:"environment"`
	Workloads          []Workload          `yaml:"workloads"`
	Behaviors          []Behavior          `yaml:"behaviors"`
}

type ObservationEngine struct {
	Ref string `yaml:"ref"`
}

type Environment struct {
	Observed string `yaml:"observed"`
}

type Workload struct {
	ID          string            `yaml:"id"`
	DisplayName string            `yaml:"displayName"`
	Software    WorkloadSoftware  `yaml:"software,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty"`
	Evidence    WorkloadEvidence  `yaml:"evidence"`
}

type WorkloadSoftware struct {
	Image string `yaml:"image,omitempty"`
}

type WorkloadEvidence struct {
	FirstSeen string                  `yaml:"firstSeen"`
	LastSeen  string                  `yaml:"lastSeen"`
	Sources   []ObservationSourceRef `yaml:"sources"`
}

type ObservationSourceRef struct {
	EngineRef string `yaml:"engineRef"`
}

type Behavior struct {
	ID          string             `yaml:"id"`
	SourceRef   string             `yaml:"sourceRef"`
	Destination BehaviorDestination `yaml:"destination"`
	Facets      BehaviorFacets      `yaml:"facets"`
	Evidence    BehaviorEvidence    `yaml:"evidence"`
}

type BehaviorDestination struct {
	WorkloadRef string `yaml:"workloadRef"`
}

type BehaviorFacets struct {
	Protocol  ProtocolFacet   `yaml:"protocol"`
	Network   *NetworkFacet   `yaml:"network,omitempty"`
	Interface *InterfaceFacet `yaml:"interface,omitempty"`
}

type ProtocolFacet struct {
	Name                     string  `yaml:"name"`
	Category                 string  `yaml:"category,omitempty"`
	ClassificationConfidence float64 `yaml:"classificationConfidence,omitempty"`
	ClassificationReason     string  `yaml:"classificationReason,omitempty"`
}

type NetworkFacet struct {
	Transport string `yaml:"transport"`
	Port      int    `yaml:"port"`
}

type InterfaceFacet struct {
	HTTP *HTTPInterface `yaml:"http,omitempty"`
}

type HTTPInterface struct {
	Method         string      `yaml:"method"`
	Path           string      `yaml:"path"`
	RequestSchema  interface{} `yaml:"requestSchema"`
	ResponseSchema interface{} `yaml:"responseSchema"`
}

type BehaviorEvidence struct {
	FirstSeen          string                  `yaml:"firstSeen"`
	LastSeen           string                  `yaml:"lastSeen"`
	Count              int                     `yaml:"count"`
	ObserverConfidence float64                 `yaml:"observerConfidence"`
	Sources            []ObservationSourceRef `yaml:"sources"`
}

// CiliumNetworkPolicy represents the output Cilium policy
type CiliumNetworkPolicy struct {
	APIVersion string                       `yaml:"apiVersion"`
	Kind       string                       `yaml:"kind"`
	Metadata   CiliumPolicyMetadata         `yaml:"metadata"`
	Spec       *CiliumNetworkPolicySpec     `yaml:"spec,omitempty"`
	Specs      []CiliumNetworkPolicySpec    `yaml:"specs,omitempty"`
}

type CiliumPolicyMetadata struct {
	Name        string            `yaml:"name"`
	Labels      map[string]string `yaml:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

type CiliumNetworkPolicySpec struct {
	Description      string                    `yaml:"description,omitempty"`
	EndpointSelector CiliumEndpointSelector    `yaml:"endpointSelector"`
	Ingress          []CiliumIngressRule       `yaml:"ingress,omitempty"`
	Egress           []CiliumEgressRule        `yaml:"egress,omitempty"`
}

type CiliumEndpointSelector struct {
	MatchLabels      map[string]string             `yaml:"matchLabels,omitempty"`
	MatchExpressions []CiliumLabelSelectorReq      `yaml:"matchExpressions,omitempty"`
}

type CiliumLabelSelectorReq struct {
	Key      string   `yaml:"key"`
	Operator string   `yaml:"operator"`
	Values   []string `yaml:"values,omitempty"`
}

type CiliumIngressRule struct {
	FromEndpoints []CiliumEndpointSelector `yaml:"fromEndpoints,omitempty"`
	ToPorts       []CiliumPortRule         `yaml:"toPorts,omitempty"`
}

type CiliumEgressRule struct {
	ToEndpoints []CiliumEndpointSelector `yaml:"toEndpoints,omitempty"`
	ToPorts     []CiliumPortRule         `yaml:"toPorts,omitempty"`
}

type CiliumPortRule struct {
	Ports []CiliumPortProtocol `yaml:"ports,omitempty"`
	Rules *CiliumL7Rules       `yaml:"rules,omitempty"`
}

type CiliumPortProtocol struct {
	Port     string `yaml:"port"`
	Protocol string `yaml:"protocol"`
}

type CiliumL7Rules struct {
	HTTP []CiliumHTTPRule `yaml:"http,omitempty"`
}

type CiliumHTTPRule struct {
	Method string `yaml:"method,omitempty"`
	Path   string `yaml:"path,omitempty"`
}

// Config holds runtime configuration
type Config struct {
	InputPath          string
	OutputPath         string
	OutputMode         string // "combined" or "separate"
	LabelPrefixes      []string
	IncludeInferred    bool
	Namespace          string
}

// PolicyData holds behaviors grouped by workload for policy generation
type PolicyData struct {
	Workload         *Workload
	EgressBehaviors  []Behavior
	IngressBehaviors []Behavior
}

func main() {
	config := loadConfig()
	
	log.Printf("Loading ObservedBehaviors from: %s", config.InputPath)
	observed, err := loadObservedBehaviors(config.InputPath)
	if err != nil {
		log.Fatalf("Failed to load ObservedBehaviors: %v", err)
	}
	
	log.Printf("Loaded %d workloads and %d behaviors", len(observed.Spec.Workloads), len(observed.Spec.Behaviors))
	
	// Generate policies
	policies := generatePolicies(observed, config)
	log.Printf("Generated %d policies", len(policies))
	
	// Write policies
	if err := writePolicies(policies, config); err != nil {
		log.Fatalf("Failed to write policies: %v", err)
	}
	
	log.Printf("Successfully wrote policies to: %s", config.OutputPath)
}

func loadConfig() Config {
	config := Config{
		InputPath:       getEnv("INPUT_PATH", "../../output/ebpf_service_map.yaml"),
		OutputPath:      getEnv("OUTPUT_PATH", "./output"),
		OutputMode:      getEnv("OUTPUT_MODE", "separate"), // "combined" or "separate"
		IncludeInferred: getEnvBool("INCLUDE_INFERRED", false),
		Namespace:       getEnv("NAMESPACE", "default"),
	}
	
	// Parse label prefixes
	labelPrefixesStr := getEnv("LABEL_SELECTOR_PREFIXES", "app.")
	if labelPrefixesStr != "" {
		config.LabelPrefixes = strings.Split(labelPrefixesStr, ",")
		for i := range config.LabelPrefixes {
			config.LabelPrefixes[i] = strings.TrimSpace(config.LabelPrefixes[i])
		}
	}
	
	return config
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return strings.ToLower(value) == "true" || value == "1"
	}
	return defaultValue
}

func loadObservedBehaviors(path string) (*ObservedBehaviors, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	
	var observed ObservedBehaviors
	if err := yaml.Unmarshal(data, &observed); err != nil {
		return nil, fmt.Errorf("unmarshal yaml: %w", err)
	}
	
	return &observed, nil
}

func generatePolicies(observed *ObservedBehaviors, config Config) []CiliumNetworkPolicy {
	// Build workload lookup maps
	workloadsByRef := make(map[string]*Workload)
	inferredWorkloads := make(map[string]bool)
	
	for i := range observed.Spec.Workloads {
		workload := &observed.Spec.Workloads[i]
		workloadsByRef[workload.ID] = workload
		
		// Track inferred workloads (those without the specified label prefixes)
		if !hasMatchingLabels(workload.Labels, config.LabelPrefixes) {
			inferredWorkloads[workload.ID] = true
		}
	}
	
	// Group behaviors by source and destination for bidirectional policy generation
	policyDataMap := make(map[string]*PolicyData)
	
	// Initialize policy data for all non-inferred workloads
	for ref, workload := range workloadsByRef {
		if !config.IncludeInferred && inferredWorkloads[ref] {
			continue
		}
		policyDataMap[ref] = &PolicyData{
			Workload:        workload,
			EgressBehaviors: []Behavior{},
			IngressBehaviors: []Behavior{},
		}
	}
	
	// Assign behaviors to source (egress) and destination (ingress)
	for _, behavior := range observed.Spec.Behaviors {
		sourceRef := behavior.SourceRef
		destRef := behavior.Destination.WorkloadRef
		
		// Add to source's egress
		if data, exists := policyDataMap[sourceRef]; exists {
			data.EgressBehaviors = append(data.EgressBehaviors, behavior)
		}
		
		// Add to destination's ingress (if destination is a tracked workload)
		if data, exists := policyDataMap[destRef]; exists {
			data.IngressBehaviors = append(data.IngressBehaviors, behavior)
		}
	}
	
	// Generate policies
	var policies []CiliumNetworkPolicy
	
	// Sort keys for deterministic output
	var workloadRefs []string
	for ref := range policyDataMap {
		workloadRefs = append(workloadRefs, ref)
	}
	sort.Strings(workloadRefs)
	
	for _, ref := range workloadRefs {
		data := policyDataMap[ref]
		if policy := generateWorkloadPolicy(data, workloadsByRef, config); policy != nil {
			policies = append(policies, *policy)
		}
	}
	
	return policies
}

func hasMatchingLabels(labels map[string]string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return len(labels) > 0
	}
	
	for key := range labels {
		for _, prefix := range prefixes {
			if strings.HasPrefix(key, prefix) {
				return true
			}
		}
	}
	return false
}

func generateWorkloadPolicy(data *PolicyData, workloadsByRef map[string]*Workload, config Config) *CiliumNetworkPolicy {
	workload := data.Workload
	
	// Extract matching labels for selector
	selectorLabels := extractMatchingLabels(workload.Labels, config.LabelPrefixes)
	if len(selectorLabels) == 0 {
		log.Printf("Warning: workload %s has no matching labels for prefixes %v, skipping", workload.DisplayName, config.LabelPrefixes)
		return nil
	}
	
	policy := &CiliumNetworkPolicy{
		APIVersion: "cilium.io/v2",
		Kind:       "CiliumNetworkPolicy",
		Metadata: CiliumPolicyMetadata{
			Name:      fmt.Sprintf("%s-policy", workload.DisplayName),
			Labels: map[string]string{
				"app.kubernetes.io/generated-by": "http-profiler-adapter",
			},
			Annotations: map[string]string{
				"description": fmt.Sprintf("Generated from ObservedBehaviors for workload: %s", workload.DisplayName),
			},
		},
		Spec: &CiliumNetworkPolicySpec{
			Description: fmt.Sprintf("Network policy for %s based on observed behaviors", workload.DisplayName),
			EndpointSelector: CiliumEndpointSelector{
				MatchLabels: selectorLabels,
			},
		},
	}
	
	// Generate egress rules
	if len(data.EgressBehaviors) > 0 {
		policy.Spec.Egress = generateEgressRules(data.EgressBehaviors, workloadsByRef, config)
	}
	
	// Generate ingress rules
	if len(data.IngressBehaviors) > 0 {
		policy.Spec.Ingress = generateIngressRules(data.IngressBehaviors, workloadsByRef, config)
	}
	
	return policy
}

func extractMatchingLabels(labels map[string]string, prefixes []string) map[string]string {
	result := make(map[string]string)
	
	if len(prefixes) == 0 {
		// If no prefixes specified, return all labels
		for k, v := range labels {
			result[k] = v
		}
		return result
	}
	
	for key, value := range labels {
		for _, prefix := range prefixes {
			if strings.HasPrefix(key, prefix) {
				result[key] = value
				break
			}
		}
	}
	
	return result
}

func generateEgressRules(behaviors []Behavior, workloadsByRef map[string]*Workload, config Config) []CiliumEgressRule {
	// Group behaviors by destination
	type DestGroup struct {
		DestWorkload *Workload
		Behaviors    []Behavior
	}
	
	destGroups := make(map[string]*DestGroup)
	
	for _, behavior := range behaviors {
		destRef := behavior.Destination.WorkloadRef
		if _, exists := destGroups[destRef]; !exists {
			destGroups[destRef] = &DestGroup{
				DestWorkload: workloadsByRef[destRef],
				Behaviors:    []Behavior{},
			}
		}
		destGroups[destRef].Behaviors = append(destGroups[destRef].Behaviors, behavior)
	}
	
	var rules []CiliumEgressRule
	
	// Sort destination keys for deterministic output
	var destRefs []string
	for ref := range destGroups {
		destRefs = append(destRefs, ref)
	}
	sort.Strings(destRefs)
	
	for _, destRef := range destRefs {
		group := destGroups[destRef]
		
		// Build endpoint selector for destination
		var toEndpoints []CiliumEndpointSelector
		if group.DestWorkload != nil {
			destLabels := extractMatchingLabels(group.DestWorkload.Labels, config.LabelPrefixes)
			if len(destLabels) > 0 {
				toEndpoints = append(toEndpoints, CiliumEndpointSelector{
					MatchLabels: destLabels,
				})
			}
		}
		
		// Build port rules
		toPorts := buildPortRules(group.Behaviors)
		
		if len(toEndpoints) > 0 || len(toPorts) > 0 {
			rules = append(rules, CiliumEgressRule{
				ToEndpoints: toEndpoints,
				ToPorts:     toPorts,
			})
		}
	}
	
	return rules
}

func generateIngressRules(behaviors []Behavior, workloadsByRef map[string]*Workload, config Config) []CiliumIngressRule {
	// Group behaviors by source
	type SourceGroup struct {
		SourceWorkload *Workload
		Behaviors      []Behavior
	}
	
	sourceGroups := make(map[string]*SourceGroup)
	
	for _, behavior := range behaviors {
		sourceRef := behavior.SourceRef
		if _, exists := sourceGroups[sourceRef]; !exists {
			sourceGroups[sourceRef] = &SourceGroup{
				SourceWorkload: workloadsByRef[sourceRef],
				Behaviors:      []Behavior{},
			}
		}
		sourceGroups[sourceRef].Behaviors = append(sourceGroups[sourceRef].Behaviors, behavior)
	}
	
	var rules []CiliumIngressRule
	
	// Sort source keys for deterministic output
	var sourceRefs []string
	for ref := range sourceGroups {
		sourceRefs = append(sourceRefs, ref)
	}
	sort.Strings(sourceRefs)
	
	for _, sourceRef := range sourceRefs {
		group := sourceGroups[sourceRef]
		
		// Build endpoint selector for source
		var fromEndpoints []CiliumEndpointSelector
		if group.SourceWorkload != nil {
			sourceLabels := extractMatchingLabels(group.SourceWorkload.Labels, config.LabelPrefixes)
			if len(sourceLabels) > 0 {
				fromEndpoints = append(fromEndpoints, CiliumEndpointSelector{
					MatchLabels: sourceLabels,
				})
			}
		}
		
		// Build port rules
		toPorts := buildPortRules(group.Behaviors)
		
		if len(fromEndpoints) > 0 || len(toPorts) > 0 {
			rules = append(rules, CiliumIngressRule{
				FromEndpoints: fromEndpoints,
				ToPorts:       toPorts,
			})
		}
	}
	
	return rules
}

func buildPortRules(behaviors []Behavior) []CiliumPortRule {
	// Group behaviors by protocol and port
	type PortKey struct {
		Protocol string
		Port     string
	}
	
	portGroups := make(map[PortKey][]Behavior)
	
	for _, behavior := range behaviors {
		var key PortKey
		
		if behavior.Facets.Protocol.Name == "http" {
			// HTTP uses port 80 by default (or could be inferred from network facet)
			key = PortKey{Protocol: "TCP", Port: "80"}
			if behavior.Facets.Network != nil && behavior.Facets.Network.Port > 0 {
				key.Port = fmt.Sprintf("%d", behavior.Facets.Network.Port)
			}
		} else if behavior.Facets.Network != nil {
			// Non-HTTP protocols
			key = PortKey{
				Protocol: strings.ToUpper(behavior.Facets.Network.Transport),
				Port:     fmt.Sprintf("%d", behavior.Facets.Network.Port),
			}
		} else {
			continue // Skip if no port information
		}
		
		portGroups[key] = append(portGroups[key], behavior)
	}
	
	var portRules []CiliumPortRule
	
	// Sort port keys for deterministic output
	var portKeys []PortKey
	for key := range portGroups {
		portKeys = append(portKeys, key)
	}
	sort.Slice(portKeys, func(i, j int) bool {
		if portKeys[i].Protocol != portKeys[j].Protocol {
			return portKeys[i].Protocol < portKeys[j].Protocol
		}
		return portKeys[i].Port < portKeys[j].Port
	})
	
	for _, key := range portKeys {
		behaviors := portGroups[key]
		
		portRule := CiliumPortRule{
			Ports: []CiliumPortProtocol{
				{
					Port:     key.Port,
					Protocol: key.Protocol,
				},
			},
		}
		
		// Add L7 HTTP rules if applicable
		var httpRules []CiliumHTTPRule
		for _, behavior := range behaviors {
			if behavior.Facets.Protocol.Name == "http" && behavior.Facets.Interface != nil && behavior.Facets.Interface.HTTP != nil {
				httpRules = append(httpRules, CiliumHTTPRule{
					Method: behavior.Facets.Interface.HTTP.Method,
					Path:   behavior.Facets.Interface.HTTP.Path,
				})
			}
		}
		
		if len(httpRules) > 0 {
			// Sort HTTP rules for deterministic output
			sort.Slice(httpRules, func(i, j int) bool {
				if httpRules[i].Method != httpRules[j].Method {
					return httpRules[i].Method < httpRules[j].Method
				}
				return httpRules[i].Path < httpRules[j].Path
			})
			
			portRule.Rules = &CiliumL7Rules{
				HTTP: httpRules,
			}
		}
		
		portRules = append(portRules, portRule)
	}
	
	return portRules
}

func writePolicies(policies []CiliumNetworkPolicy, config Config) error {
	// Ensure output directory exists
	if err := os.MkdirAll(config.OutputPath, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	
	if config.OutputMode == "combined" {
		return writeCombinedPolicy(policies, config)
	}
	
	return writeSeparatePolicies(policies, config)
}

func writeCombinedPolicy(policies []CiliumNetworkPolicy, config Config) error {
	outputFile := filepath.Join(config.OutputPath, "cilium-policies.yaml")
	
	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer f.Close()
	
	encoder := yaml.NewEncoder(f)
	encoder.SetIndent(2)
	
	for _, policy := range policies {
		if err := encoder.Encode(policy); err != nil {
			return fmt.Errorf("encode policy %s: %w", policy.Metadata.Name, err)
		}
	}
	
	log.Printf("Wrote combined policy file: %s", outputFile)
	return nil
}

func writeSeparatePolicies(policies []CiliumNetworkPolicy, config Config) error {
	for _, policy := range policies {
		filename := fmt.Sprintf("%s.yaml", policy.Metadata.Name)
		outputFile := filepath.Join(config.OutputPath, filename)
		
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("create file %s: %w", filename, err)
		}
		
		encoder := yaml.NewEncoder(f)
		encoder.SetIndent(2)
		
		if err := encoder.Encode(policy); err != nil {
			f.Close()
			return fmt.Errorf("encode policy %s: %w", policy.Metadata.Name, err)
		}
		
		f.Close()
		log.Printf("Wrote policy file: %s", outputFile)
	}
	
	return nil
}
