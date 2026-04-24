package com.mi.keycloak.apikeys.rest.representation;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

// Réponse conforme RFC 7662 (OAuth 2.0 Token Introspection)
// Compatible avec tout client OIDC qui appelle /token/introspect
@JsonInclude(JsonInclude.Include.NON_NULL)
public class VerifyApiKeyResponse {

    // RFC 7662 — champ obligatoire
    public boolean active;

    // RFC 7662 — champs standard (absents si active=false)
    public String sub;              // user ID
    public String username;
    public String email;
    public Long exp;                // expiration en secondes (epoch), null = pas d'expiration
    public Long iat;                // issued at en secondes (epoch)

    // Keycloak-style roles
    @JsonProperty("realm_access")
    public RealmAccess realmAccess;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class RealmAccess {
        public List<String> roles;

        public RealmAccess(List<String> roles) {
            this.roles = roles;
        }
    }
}
