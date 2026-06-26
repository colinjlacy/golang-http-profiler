module github.com/colinjlacy/runtime-conditions-profiles/demos/apps/request-logger-http

go 1.25.0

require (
	github.com/colinjlacy/runtime-conditions-profiles/extensions/common-integrations/go v0.0.0
	github.com/colinjlacy/runtime-conditions-profiles/extensions/env-configuration/go v0.0.0
)

replace github.com/colinjlacy/runtime-conditions-profiles/extensions/common-integrations/go => ../../../extensions/common-integrations/go

replace github.com/colinjlacy/runtime-conditions-profiles/extensions/env-configuration/go => ../../../extensions/env-configuration/go
