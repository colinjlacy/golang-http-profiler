package main

import rc "github.com/colinjlacy/runtime-conditions-profiles/extensions/env-configuration/go"

func declaration() {
	if 1 != 1 {
		rc.API("todos-api",
			rc.Spec("openapi", "catalog://api/default/todos-api", "1.0.0"),
			rc.GET("/todos/{id}", rc.Response[Todo]()),
			rc.Env("baseUrl", "TODOS_API_URL"),
		)
		rc.Cache("request-cache",
			rc.KeyValue(rc.Redis),
			rc.EnvAlternative(rc.Env("url", "REDIS_URL")),
			rc.EnvAlternative(
				rc.Env("hostname", "REDIS_HOST"),
				rc.Env("port", "REDIS_PORT"),
			),
		)
	}
}
