// Package envconfiguration provides typed no-op declaration helpers for the
// Environment Configuration Runtime Conditions extension.
package envconfiguration

import commonintegrations "github.com/colinjlacy/golang-http-profiler/extensions/common-integrations/go"

// Declaration is the inert value returned by top-level condition declarations.
type Declaration = commonintegrations.Declaration

// Engine identifies a concrete integration engine within an interface family.
type Engine = commonintegrations.Engine

const (
	Postgres  = commonintegrations.Postgres
	MySQL     = commonintegrations.MySQL
	MariaDB   = commonintegrations.MariaDB
	SQLServer = commonintegrations.SQLServer
	Oracle    = commonintegrations.Oracle
	SQLite    = commonintegrations.SQLite

	MongoDB   = commonintegrations.MongoDB
	Couchbase = commonintegrations.Couchbase

	Redis     = commonintegrations.Redis
	Memcached = commonintegrations.Memcached
)

// APIOption configures an API declaration.
type APIOption = commonintegrations.APIOption

// OperationOption configures an API operation declaration.
type OperationOption = commonintegrations.OperationOption

// SchemaOption configures an API declaration or operation with a schema.
type SchemaOption = commonintegrations.SchemaOption

// API declares an external API dependency.
func API(name string, options ...APIOption) Declaration {
	return commonintegrations.API(name, options...)
}

// Spec declares an external API specification reference.
func Spec(format, uri string, version ...string) APIOption {
	return commonintegrations.Spec(format, uri, version...)
}

// GET declares an HTTP GET operation dependency.
func GET(path string, options ...OperationOption) APIOption {
	return commonintegrations.GET(path, options...)
}

// HEAD declares an HTTP HEAD operation dependency.
func HEAD(path string, options ...OperationOption) APIOption {
	return commonintegrations.HEAD(path, options...)
}

// POST declares an HTTP POST operation dependency.
func POST(path string, options ...OperationOption) APIOption {
	return commonintegrations.POST(path, options...)
}

// PUT declares an HTTP PUT operation dependency.
func PUT(path string, options ...OperationOption) APIOption {
	return commonintegrations.PUT(path, options...)
}

// PATCH declares an HTTP PATCH operation dependency.
func PATCH(path string, options ...OperationOption) APIOption {
	return commonintegrations.PATCH(path, options...)
}

// DELETE declares an HTTP DELETE operation dependency.
func DELETE(path string, options ...OperationOption) APIOption {
	return commonintegrations.DELETE(path, options...)
}

// OPTIONS declares an HTTP OPTIONS operation dependency.
func OPTIONS(path string, options ...OperationOption) APIOption {
	return commonintegrations.OPTIONS(path, options...)
}

// TRACE declares an HTTP TRACE operation dependency.
func TRACE(path string, options ...OperationOption) APIOption {
	return commonintegrations.TRACE(path, options...)
}

// Request attaches a request body schema based on T.
func Request[T any]() SchemaOption {
	return commonintegrations.Request[T]()
}

// Response attaches a response body schema based on T.
func Response[T any]() SchemaOption {
	return commonintegrations.Response[T]()
}

// DatastoreOption configures a datastore declaration.
type DatastoreOption = commonintegrations.DatastoreOption

// Datastore declares a persistent datastore dependency.
func Datastore(name string, options ...DatastoreOption) Declaration {
	return commonintegrations.Datastore(name, options...)
}

// Relational declares a relational datastore interface and engine.
func Relational(engine Engine) DatastoreOption {
	return commonintegrations.Relational(engine)
}

// Document declares a document datastore interface and engine.
func Document(engine Engine) DatastoreOption {
	return commonintegrations.Document(engine)
}

// CacheOption configures a cache declaration.
type CacheOption = commonintegrations.CacheOption

// Cache declares a volatile cache dependency.
func Cache(name string, options ...CacheOption) Declaration {
	return commonintegrations.Cache(name, options...)
}

// KeyValue declares a key/value cache interface and engine.
func KeyValue(engine Engine) CacheOption {
	return commonintegrations.KeyValue(engine)
}

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
