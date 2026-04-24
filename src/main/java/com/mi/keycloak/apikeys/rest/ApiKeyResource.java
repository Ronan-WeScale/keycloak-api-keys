package com.mi.keycloak.apikeys.rest;

import com.mi.keycloak.apikeys.credential.ApiKeyCredentialProvider;
import com.mi.keycloak.apikeys.credential.ApiKeyCredentialProviderFactory;
import com.mi.keycloak.apikeys.credential.ApiKeyCredentialModel;
import com.mi.keycloak.apikeys.rest.representation.*;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.TokenVerifier;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class ApiKeyResource {

    private static final Logger LOG = Logger.getLogger(ApiKeyResource.class);

    private final KeycloakSession session;
    private final RealmModel realm;

    public ApiKeyResource(KeycloakSession session) {
        this.session = session;
        this.realm = session.getContext().getRealm();
    }

    // -------------------------------------------------------------------------
    // Endpoints utilisateur (requièrent un JWT Keycloak valide)
    // -------------------------------------------------------------------------

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response listKeys() {
        UserModel user = authenticate();
        List<ApiKeyRepresentation> keys = provider().listKeys(user)
            .stream()
            .map(ApiKeyRepresentation::from)
            .toList();
        return Response.ok(keys).build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createKey(CreateApiKeyRequest req) {
        if (req == null || req.name == null || req.name.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity("{\"error\":\"name is required\"}").build();
        }

        UserModel user = authenticate();
        ApiKeyCredentialProvider.CreatedKey created = provider()
            .generateKey(realm, user, req.name.trim(), req.expiresAt, req.roles);

        CreateApiKeyResponse resp = new CreateApiKeyResponse();
        resp.key = ApiKeyRepresentation.from(created.model());
        resp.rawKey = created.rawKey();

        LOG.infof("API key created for user %s (name=%s)", user.getId(), req.name);
        return Response.status(Response.Status.CREATED).entity(resp).build();
    }

    @DELETE
    @Path("/{id}")
    public Response deleteKey(@PathParam("id") String id) {
        UserModel user = authenticate();
        boolean deleted = provider().deleteCredential(realm, user, id);
        if (!deleted) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        LOG.infof("API key %s deleted by user %s", id, user.getId());
        return Response.noContent().build();
    }

    // -------------------------------------------------------------------------
    // Endpoint d'introspection unifié — RFC 7662 compatible
    // Accepte à la fois les JWT Keycloak et les API keys (mk_...)
    // Même interface que /protocol/openid-connect/token/introspect
    // -------------------------------------------------------------------------

    @POST
    @Path("/verify")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response introspect(
            @FormParam("client_id") String clientId,
            @FormParam("client_secret") String clientSecret,
            @FormParam("token") String token) {

        authenticateClient(clientId, clientSecret);

        if (token == null || token.isBlank()) {
            return Response.ok(inactive()).build();
        }

        // Détection du type de token par le préfixe
        if (token.startsWith("mk_")) {
            return introspectApiKey(token.trim());
        } else {
            return introspectJwt(token.trim());
        }
    }

    // -------------------------------------------------------------------------

    private Response introspectApiKey(String rawKey) {
        Optional<ApiKeyCredentialProvider.VerifyResult> match = provider().verifyKey(realm, rawKey);
        if (match.isEmpty()) {
            return Response.ok(inactive()).build();
        }

        UserModel user = match.get().user();
        ApiKeyCredentialModel credential = match.get().credential();

        Set<String> userRoles = user.getRoleMappingsStream()
            .map(RoleModel::getName)
            .collect(Collectors.toSet());

        List<String> storedRoles = credential.getApiKeyCredentialData().roles;
        List<String> effectiveRoles = (storedRoles == null || storedRoles.isEmpty())
            ? userRoles.stream().sorted().toList()
            : storedRoles.stream().filter(userRoles::contains).sorted().toList();

        Long expiresAt = credential.getApiKeyCredentialData().expiresAt;
        Long createdAt = credential.getApiKeyCredentialData().createdAt;

        VerifyApiKeyResponse resp = new VerifyApiKeyResponse();
        resp.active = true;
        resp.sub = user.getId();
        resp.username = user.getUsername();
        resp.email = user.getEmail();
        resp.iat = createdAt != null ? createdAt / 1000 : null;
        resp.exp = expiresAt != null ? expiresAt / 1000 : null;
        resp.realmAccess = new VerifyApiKeyResponse.RealmAccess(effectiveRoles);
        return Response.ok(resp).build();
    }

    private Response introspectJwt(String rawToken) {
        try {
            TokenVerifier<AccessToken> verifier = TokenVerifier.create(rawToken, AccessToken.class);
            String kid = verifier.getHeader().getKeyId();
            String algorithm = verifier.getHeader().getAlgorithm().name();

            KeyWrapper key = session.keys().getKey(realm, kid, KeyUse.SIG, algorithm);
            if (key == null) return Response.ok(inactive()).build();

            AccessToken accessToken = verifier
                .publicKey((PublicKey) key.getPublicKey())
                .verify()
                .getToken();

            if (!accessToken.isActive()) return Response.ok(inactive()).build();

            VerifyApiKeyResponse resp = new VerifyApiKeyResponse();
            resp.active = true;
            resp.sub = accessToken.getSubject();
            resp.username = accessToken.getPreferredUsername();
            resp.email = accessToken.getEmail();
            resp.exp = accessToken.getExp();
            resp.iat = accessToken.getIat();
            if (accessToken.getRealmAccess() != null) {
                resp.realmAccess = new VerifyApiKeyResponse.RealmAccess(
                    new ArrayList<>(accessToken.getRealmAccess().getRoles()));
            }
            return Response.ok(resp).build();
        } catch (VerificationException e) {
            return Response.ok(inactive()).build();
        }
    }

    private static VerifyApiKeyResponse inactive() {
        return new VerifyApiKeyResponse(); // active = false par défaut
    }

    // -------------------------------------------------------------------------

    private UserModel authenticate() {
        AuthenticationManager.AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(session)
            .setRealm(realm)
            .authenticate();
        if (auth == null || auth.getUser() == null) {
            throw new NotAuthorizedException("Bearer token required");
        }
        return auth.getUser();
    }

    private void authenticateClient(String clientId, String clientSecret) {
        // Support aussi Basic Auth en fallback (RFC 6749 §2.3)
        if (clientId == null || clientId.isBlank()) {
            String authHeader = session.getContext().getHttpRequest()
                .getHttpHeaders().getHeaderString(HttpHeaders.AUTHORIZATION);
            if (authHeader != null && authHeader.startsWith("Basic ")) {
                try {
                    String decoded = new String(Base64.getDecoder().decode(authHeader.substring(6)), StandardCharsets.UTF_8);
                    int colon = decoded.indexOf(':');
                    if (colon > 0) {
                        clientId = decoded.substring(0, colon);
                        clientSecret = decoded.substring(colon + 1);
                    }
                } catch (IllegalArgumentException ignored) {}
            }
        }

        if (clientId == null || clientId.isBlank() || clientSecret == null) {
            throw new NotAuthorizedException("client_id and client_secret are required");
        }

        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null || !client.isEnabled() || client.isPublicClient()) {
            throw new NotAuthorizedException("Invalid client");
        }
        if (!MessageDigest.isEqual(
                clientSecret.getBytes(StandardCharsets.UTF_8),
                client.getSecret().getBytes(StandardCharsets.UTF_8))) {
            throw new NotAuthorizedException("Invalid client credentials");
        }
    }

    private ApiKeyCredentialProvider provider() {
        return (ApiKeyCredentialProvider) session.getProvider(
            org.keycloak.credential.CredentialProvider.class,
            ApiKeyCredentialProviderFactory.PROVIDER_ID
        );
    }
}
