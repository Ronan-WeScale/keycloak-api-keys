package com.mi.keycloak.apikeys.rest.representation;

import com.mi.keycloak.apikeys.credential.ApiKeyCredentialModel;

import java.util.List;

public class ApiKeyRepresentation {
    public String id;
    public String name;
    public String prefix;
    public Long createdAt;
    public Long expiresAt;
    public Long lastUsed;
    public List<String> roles; // null = unrestricted

    public static ApiKeyRepresentation from(ApiKeyCredentialModel model) {
        ApiKeyRepresentation r = new ApiKeyRepresentation();
        r.id = model.getId();
        ApiKeyCredentialModel.CredentialData cd = model.getApiKeyCredentialData();
        r.name = cd.name;
        r.prefix = cd.prefix + "...";
        r.createdAt = cd.createdAt;
        r.expiresAt = cd.expiresAt;
        r.lastUsed = cd.lastUsed;
        r.roles = cd.roles;
        return r;
    }
}
