package com.mi.keycloak.apikeys.credential;

import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;

public class ApiKeyCredentialProviderFactory implements CredentialProviderFactory<ApiKeyCredentialProvider> {

    public static final String PROVIDER_ID = "api-key";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public ApiKeyCredentialProvider create(KeycloakSession session) {
        return new ApiKeyCredentialProvider(session);
    }
}
