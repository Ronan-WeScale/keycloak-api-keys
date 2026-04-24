package com.mi.keycloak.apikeys.rest;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class ApiKeyResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public ApiKeyResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new ApiKeyResource(session);
    }

    @Override
    public void close() {}
}
