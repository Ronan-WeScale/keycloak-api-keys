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
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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
    // Endpoint de vérification — protégé par client credentials (Basic Auth)
    // -------------------------------------------------------------------------

    @POST
    @Path("/verify")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response verifyKey(VerifyApiKeyRequest req) {
        authenticateClient();

        if (req == null || req.key == null || req.key.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity("{\"error\":\"key is required\"}").build();
        }

        VerifyApiKeyResponse resp = new VerifyApiKeyResponse();

        Optional<ApiKeyCredentialProvider.VerifyResult> match = provider().verifyKey(realm, req.key.trim());
        if (match.isPresent()) {
            UserModel user = match.get().user();
            ApiKeyCredentialModel credential = match.get().credential();

            Set<String> userRoles = user.getRoleMappingsStream()
                .map(RoleModel::getName)
                .collect(Collectors.toSet());

            List<String> storedRoles = credential.getApiKeyCredentialData().roles;
            List<String> effectiveRoles = (storedRoles == null || storedRoles.isEmpty())
                ? userRoles.stream().sorted().toList()
                : storedRoles.stream().filter(userRoles::contains).sorted().toList();

            resp.valid = true;
            resp.userId = user.getId();
            resp.username = user.getUsername();
            resp.email = user.getEmail();
            resp.roles = effectiveRoles;
        } else {
            resp.valid = false;
        }

        return Response.ok(resp).build();
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

    private void authenticateClient() {
        String authHeader = session.getContext().getHttpRequest()
            .getHttpHeaders().getHeaderString(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Basic ")) {
            throw new NotAuthorizedException("Basic realm=\"keycloak\"");
        }

        String clientId;
        String clientSecret;
        try {
            String decoded = new String(Base64.getDecoder().decode(authHeader.substring(6)), StandardCharsets.UTF_8);
            int colon = decoded.indexOf(':');
            if (colon <= 0) throw new IllegalArgumentException();
            clientId = decoded.substring(0, colon);
            clientSecret = decoded.substring(colon + 1);
        } catch (IllegalArgumentException e) {
            throw new NotAuthorizedException("Basic realm=\"keycloak\"");
        }

        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null || !client.isEnabled() || client.isPublicClient()) {
            throw new NotAuthorizedException("Basic realm=\"keycloak\"");
        }
        if (!MessageDigest.isEqual(
                clientSecret.getBytes(StandardCharsets.UTF_8),
                client.getSecret().getBytes(StandardCharsets.UTF_8))) {
            throw new NotAuthorizedException("Basic realm=\"keycloak\"");
        }
    }

    private ApiKeyCredentialProvider provider() {
        return (ApiKeyCredentialProvider) session.getProvider(
            org.keycloak.credential.CredentialProvider.class,
            ApiKeyCredentialProviderFactory.PROVIDER_ID
        );
    }
}
