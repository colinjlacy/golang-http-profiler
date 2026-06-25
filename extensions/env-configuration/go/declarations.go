// Package envconfiguration provides typed no-op declaration helpers for the
// Environment Configuration Runtime Conditions extension.
package envconfiguration

import commonintegrations "github.com/colinjlacy/golang-http-profiler/extensions/common-integrations/go"

// EnvOption configures an environment variable mapping declaration.
type EnvOption interface {
	EnvConfigurationOption()
}

type envOption struct{}

func (envOption) EnvConfigurationOption() {}

// ConditionConfigOption configures workload-facing inputs for a Condition.
type ConditionConfigOption struct{}

func (ConditionConfigOption) CommonIntegrationsAPIOption()       {}
func (ConditionConfigOption) CommonIntegrationsDatastoreOption() {}
func (ConditionConfigOption) CommonIntegrationsCacheOption()     {}

var (
	_ commonintegrations.APIOption       = ConditionConfigOption{}
	_ commonintegrations.DatastoreOption = ConditionConfigOption{}
	_ commonintegrations.CacheOption     = ConditionConfigOption{}
)

// Env declares that a Condition property is supplied through an environment
// variable with the provided name.
func Env(property, name string, options ...EnvOption) ConditionConfigOption {
	return ConditionConfigOption{}
}

// EnvAlternative declares one acceptable set of environment variables for a
// Condition. Platform adapters may choose any complete alternative they can
// satisfy.
func EnvAlternative(inputs ...ConditionConfigOption) ConditionConfigOption {
	return ConditionConfigOption{}
}

// Sensitive marks an environment variable mapping as sensitive.
func Sensitive() EnvOption {
	return envOption{}
}

// Optional marks an environment variable mapping as optional.
func Optional() EnvOption {
	return envOption{}
}
