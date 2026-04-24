package com.mi.keycloak.apikeys.credential;

import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class ApiKeyCredentialProvider implements CredentialProvider<ApiKeyCredentialModel> {

    static final String PREFIX_ATTR_PREFIX = "_apk_";
    private static final int KEY_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final KeycloakSession session;

    public ApiKeyCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String getType() {
        return ApiKeyCredentialModel.TYPE;
    }

    @Override
    public ApiKeyCredentialModel getCredentialFromModel(CredentialModel model) {
        return ApiKeyCredentialModel.from(model);
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, ApiKeyCredentialModel model) {
        CredentialModel stored = user.credentialManager().createStoredCredential(model);
        // Index prefix → user for reverse lookup on verify
        String prefix = model.getApiKeyCredentialData().prefix;
        user.setAttribute(PREFIX_ATTR_PREFIX + prefix, List.of("1"));
        return stored;
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        // Remove prefix index attribute before deleting
        user.credentialManager()
            .getStoredCredentialsByTypeStream(ApiKeyCredentialModel.TYPE)
            .map(ApiKeyCredentialModel::from)
            .filter(k -> credentialId.equals(k.getId()))
            .findFirst()
            .ifPresent(k -> user.removeAttribute(PREFIX_ATTR_PREFIX + k.getApiKeyCredentialData().prefix));

        return user.credentialManager().removeStoredCredentialById(credentialId);
    }

    public record CreatedKey(ApiKeyCredentialModel model, String rawKey) {}

    public CreatedKey generateKey(RealmModel realm, UserModel user, String name, Long expiresAt) {
        byte[] bytes = new byte[KEY_BYTES];
        RANDOM.nextBytes(bytes);
        String rawKey = "mk_" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        String prefix = rawKey.substring(3, 11); // 8 chars after "mk_"

        ApiKeyCredentialModel model = ApiKeyCredentialModel.create(name, hash(rawKey), prefix, expiresAt);
        CredentialModel stored = createCredential(realm, user, model);
        return new CreatedKey(ApiKeyCredentialModel.from(stored), rawKey);
    }

    public List<ApiKeyCredentialModel> listKeys(UserModel user) {
        return user.credentialManager()
            .getStoredCredentialsByTypeStream(ApiKeyCredentialModel.TYPE)
            .map(ApiKeyCredentialModel::from)
            .collect(Collectors.toList());
    }

    public Optional<UserModel> verifyKey(RealmModel realm, String rawKey) {
        if (rawKey == null || !rawKey.startsWith("mk_") || rawKey.length() < 11) {
            return Optional.empty();
        }

        String prefix = rawKey.substring(3, 11);
        String hashed = hash(rawKey);

        return session.users()
            .searchForUserByUserAttributeStream(realm, PREFIX_ATTR_PREFIX + prefix, "1")
            .filter(user -> matchesCredential(user, hashed))
            .findFirst();
    }

    private boolean matchesCredential(UserModel user, String hashed) {
        return user.credentialManager()
            .getStoredCredentialsByTypeStream(ApiKeyCredentialModel.TYPE)
            .map(ApiKeyCredentialModel::from)
            .anyMatch(k -> {
                if (!hashed.equals(k.getApiKeySecretData().hashedKey)) return false;
                Long exp = k.getApiKeyCredentialData().expiresAt;
                return exp == null || exp > System.currentTimeMillis();
            });
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext ctx) {
        return CredentialTypeMetadata.builder()
            .type(getType())
            .category(CredentialTypeMetadata.Category.PASSWORDLESS)
            .displayName("API Key")
            .helpText("Long-lived opaque API key for programmatic access")
            .removeable(true)
            .build(session);
    }

    public static String hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getEncoder().encodeToString(
                digest.digest(input.getBytes(StandardCharsets.UTF_8))
            );
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
