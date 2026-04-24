package com.mi.keycloak.apikeys.credential;

import jakarta.ws.rs.BadRequestException;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
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
        String prefix = model.getApiKeyCredentialData().prefix;
        user.setAttribute(PREFIX_ATTR_PREFIX + prefix, List.of("1"));
        return stored;
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        user.credentialManager()
            .getStoredCredentialsByTypeStream(ApiKeyCredentialModel.TYPE)
            .map(ApiKeyCredentialModel::from)
            .filter(k -> credentialId.equals(k.getId()))
            .findFirst()
            .ifPresent(k -> user.removeAttribute(PREFIX_ATTR_PREFIX + k.getApiKeyCredentialData().prefix));

        return user.credentialManager().removeStoredCredentialById(credentialId);
    }

    public record CreatedKey(ApiKeyCredentialModel model, String rawKey) {}

    public record VerifyResult(UserModel user, ApiKeyCredentialModel credential) {}

    public CreatedKey generateKey(RealmModel realm, UserModel user, String name, Long expiresAt, List<String> roles) {
        if (roles != null && !roles.isEmpty()) {
            Set<String> userRoles = user.getRoleMappingsStream()
                .map(RoleModel::getName)
                .collect(Collectors.toSet());
            List<String> missing = roles.stream()
                .filter(r -> !userRoles.contains(r))
                .toList();
            if (!missing.isEmpty()) {
                throw new BadRequestException("User does not have roles: " + missing);
            }
        }

        byte[] bytes = new byte[KEY_BYTES];
        RANDOM.nextBytes(bytes);
        String rawKey = "mk_" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        String prefix = rawKey.substring(3, 11);

        ApiKeyCredentialModel model = ApiKeyCredentialModel.create(name, hash(rawKey), prefix, expiresAt, roles);
        CredentialModel stored = createCredential(realm, user, model);
        return new CreatedKey(ApiKeyCredentialModel.from(stored), rawKey);
    }

    public List<ApiKeyCredentialModel> listKeys(UserModel user) {
        return user.credentialManager()
            .getStoredCredentialsByTypeStream(ApiKeyCredentialModel.TYPE)
            .map(ApiKeyCredentialModel::from)
            .collect(Collectors.toList());
    }

    public Optional<VerifyResult> verifyKey(RealmModel realm, String rawKey) {
        if (rawKey == null || !rawKey.startsWith("mk_") || rawKey.length() < 11) {
            return Optional.empty();
        }

        String prefix = rawKey.substring(3, 11);
        String hashed = hash(rawKey);

        return session.users()
            .searchForUserByUserAttributeStream(realm, PREFIX_ATTR_PREFIX + prefix, "1")
            .flatMap(user -> findMatchingCredential(user, hashed)
                .map(cred -> new VerifyResult(user, cred))
                .stream())
            .findFirst();
    }

    private Optional<ApiKeyCredentialModel> findMatchingCredential(UserModel user, String hashed) {
        return user.credentialManager()
            .getStoredCredentialsByTypeStream(ApiKeyCredentialModel.TYPE)
            .map(ApiKeyCredentialModel::from)
            .filter(k -> {
                if (!hashed.equals(k.getApiKeySecretData().hashedKey)) return false;
                Long exp = k.getApiKeyCredentialData().expiresAt;
                return exp == null || exp > System.currentTimeMillis();
            })
            .findFirst();
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
