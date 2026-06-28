import io.runtimeconditions.extensions.commonintegrations.Api;
import io.runtimeconditions.extensions.commonintegrations.Cache;
import io.runtimeconditions.extensions.commonintegrations.Datastore;
import io.runtimeconditions.extensions.commonintegrations.Http;
import io.runtimeconditions.extensions.envconfiguration.EnvConfiguration;

final class RequestLogger {
    static final class Todo {
    }

    void declare() {
        Api.declare("todos-api",
                Api.spec("openapi", "catalog://api/default/todos-api", "1.0.0"),
                Http.get("/todos/{id}", Http.response(Todo.class)),
                EnvConfiguration.env("baseUrl", "TODOS_API_URL"));

        Cache.declare("request-cache",
                Cache.keyValue(Cache.Engine.REDIS),
                EnvConfiguration.envAlternative(EnvConfiguration.env("url", "REDIS_URL")));

        Datastore.declare("primary-store",
                Datastore.relational(Datastore.Engine.POSTGRES),
                EnvConfiguration.env("url", "DATABASE_URL"));
    }
}
