package com.mi.keycloak.apikeys.credential;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.credential.CredentialModel;

public class ApiKeyCredentialModel extends CredentialModel {

    public static final String TYPE = "api-key";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private CredentialData credentialData;
    private SecretData secretData;

    public static ApiKeyCredentialModel create(String name, String hashedKey, String prefix, Long expiresAt, java.util.List<String> roles) {
        ApiKeyCredentialModel model = new ApiKeyCredentialModel();
        model.setType(TYPE);
        model.setUserLabel(name);
        model.setCreatedDate(System.currentTimeMillis());

        CredentialData cd = new CredentialData();
        cd.name = name;
        cd.prefix = prefix;
        cd.createdAt = System.currentTimeMillis();
        cd.expiresAt = expiresAt;
        cd.roles = (roles != null && !roles.isEmpty()) ? roles : null;

        SecretData sd = new SecretData();
        sd.hashedKey = hashedKey;

        try {
            model.setCredentialData(MAPPER.writeValueAsString(cd));
            model.setSecretData(MAPPER.writeValueAsString(sd));
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize API key", e);
        }

        model.credentialData = cd;
        model.secretData = sd;
        return model;
    }

    public static ApiKeyCredentialModel from(CredentialModel model) {
        ApiKeyCredentialModel m = new ApiKeyCredentialModel();
        m.setId(model.getId());
        m.setType(model.getType());
        m.setUserLabel(model.getUserLabel());
        m.setCreatedDate(model.getCreatedDate());
        m.setCredentialData(model.getCredentialData());
        m.setSecretData(model.getSecretData());

        try {
            m.credentialData = MAPPER.readValue(model.getCredentialData(), CredentialData.class);
            m.secretData = MAPPER.readValue(model.getSecretData(), SecretData.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to deserialize API key", e);
        }
        return m;
    }

    public CredentialData getApiKeyCredentialData() { return credentialData; }
    public SecretData getApiKeySecretData() { return secretData; }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class CredentialData {
        public String name;
        public String prefix;
        public Long createdAt;
        public Long expiresAt;
        public Long lastUsed;
        public java.util.List<String> roles; // null = unrestricted
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class SecretData {
        public String hashedKey;
    }
}
