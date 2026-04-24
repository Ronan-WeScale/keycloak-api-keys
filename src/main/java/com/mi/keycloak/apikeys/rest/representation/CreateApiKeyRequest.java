package com.mi.keycloak.apikeys.rest.representation;

public class CreateApiKeyRequest {
    public String name;
    public Long expiresAt; // epoch ms, null = never expires
}
