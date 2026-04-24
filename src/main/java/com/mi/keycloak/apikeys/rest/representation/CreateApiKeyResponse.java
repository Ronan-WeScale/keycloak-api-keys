package com.mi.keycloak.apikeys.rest.representation;

public class CreateApiKeyResponse {
    public ApiKeyRepresentation key;
    public String rawKey; // retourné une seule fois à la création
}
