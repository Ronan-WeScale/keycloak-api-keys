package com.mi.keycloak.apikeys.rest;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class ApiKeyResourceProviderFactory implements RealmResourceProviderFactory {

    // URL: /realms/{realm}/api-keys
    public static final String ID = "api-keys";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public ApiKeyResourceProvider create(KeycloakSession session) {
        return new ApiKeyResourceProvider(session);
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}
}
