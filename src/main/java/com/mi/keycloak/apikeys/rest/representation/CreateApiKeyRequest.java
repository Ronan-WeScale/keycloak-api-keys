package com.mi.keycloak.apikeys.rest.representation;

import java.util.List;

public class CreateApiKeyRequest {
    public String name;
    public Long expiresAt;   // epoch ms, null = never expires
    public List<String> roles; // null = no restriction (all user roles at verify time)
}
