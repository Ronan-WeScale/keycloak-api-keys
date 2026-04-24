package com.mi.keycloak.apikeys.rest.representation;

import java.util.List;

public class VerifyApiKeyResponse {
    public boolean valid;
    public String userId;
    public String username;
    public String email;
    public List<String> roles; // rôles effectifs de la clé (intersection scopes stockés ∩ rôles actuels)
}
