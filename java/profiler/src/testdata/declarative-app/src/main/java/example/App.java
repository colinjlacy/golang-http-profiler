package example;

import io.runtimeconditions.extensions.commonintegrations.Api;
import io.runtimeconditions.extensions.commonintegrations.Datastore;
import io.runtimeconditions.extensions.commonintegrations.Http;
import io.runtimeconditions.extensions.envconfiguration.EnvConfiguration;

final class App {
    private static final String USERS_PATH = "/users";
    private static final String AUTH_TOKEN = "AUTH_TOKEN";

    static final class UserRequest {
        String name;
        int count;
        boolean active;
    }

    static final class UserResponse {
        String id;
        boolean active;
    }

    void declarations() {
        Api.declare(
                "users-api",
                Api.spec("openapi", "https://example.com/openapi.yaml", "1.0"),
                Http.get(USERS_PATH, Http.response(UserResponse.class)),
                Http.post("/users", Http.request(UserRequest.class), Http.response(UserResponse.class)),
                EnvConfiguration.env("token", AUTH_TOKEN, EnvConfiguration.sensitive(), EnvConfiguration.optional()));

        Datastore.declare(
                "users-db",
                Datastore.relational(Datastore.Engine.POSTGRES),
                EnvConfiguration.envAlternative(
                        EnvConfiguration.env("url", "DATABASE_URL", EnvConfiguration.sensitive()),
                        EnvConfiguration.env("url", "READ_DATABASE_URL", EnvConfiguration.optional())));
    }
}
