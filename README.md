# keycloak-api-keys

Keycloak plugin for managing opaque API keys (GitHub PAT-style) tied to Keycloak users.

## Compatibility

<!-- COMPAT_TABLE_START -->
| Plugin     | Keycloak  |
|------------|-----------|
| 1.3.1      | 26.0.x   |
| 1.3.0      | 26.0.x   |
| 1.2.1      | 26.0.x   |
| 1.2.0      | 26.0.x   |
| 1.1.1      | 26.0.x   |
| 1.1.0      | 26.0.x   |
| 1.0.0      | 26.0.x   |
<!-- COMPAT_TABLE_END -->

## Build

```bash
mvn package -DskipTests
# → target/keycloak-api-keys-1.3.0.jar
```

## Installation

Copy the JAR into Keycloak's `providers/` directory and rebuild:

```bash
cp target/keycloak-api-keys-1.3.0.jar /opt/keycloak/providers/
/opt/keycloak/bin/kc.sh build
/opt/keycloak/bin/kc.sh start
```

On Kubernetes, the JAR can be mounted via an `initContainer`. The target path remains `/opt/keycloak/providers/`.

## Endpoints

All endpoints are under `/realms/{realm}/api-keys`.

### List keys

```http
GET /realms/{realm}/api-keys
Authorization: Bearer <keycloak_jwt>
```

### Create a key

```http
POST /realms/{realm}/api-keys
Authorization: Bearer <keycloak_jwt>
Content-Type: application/json

{
  "name": "CI pipeline",
  "expiresAt": null,
  "roles": ["read", "deploy"]
}
```

- `expiresAt` — epoch milliseconds, `null` means no expiration
- `roles` — optional scope restriction; `null` means the key inherits all user roles at introspection time

Response (`rawKey` is returned only once):

```json
{
  "key": {
    "id": "abc123",
    "name": "CI pipeline",
    "prefix": "mk_Ab3xYz12...",
    "createdAt": 1714000000000,
    "expiresAt": null,
    "lastUsed": null,
    "roles": ["read", "deploy"]
  },
  "rawKey": "mk_Ab3xYz12..."
}
```

### Revoke a key

```http
DELETE /realms/{realm}/api-keys/{id}
Authorization: Bearer <keycloak_jwt>
```

### Introspect a token (RFC 7662)

Accepts both Keycloak JWTs and API keys (`mk_...`). Requires a confidential client credential (Basic auth or form params).

```http
POST /realms/{realm}/api-keys/introspect
Authorization: Basic <base64(client_id:client_secret)>
Content-Type: application/x-www-form-urlencoded

token=mk_Ab3xYz12...
```

Response for an active API key:

```json
{
  "active": true,
  "sub": "user-uuid",
  "username": "john",
  "email": "john@example.com",
  "iat": 1714000000,
  "exp": null,
  "realm_access": {
    "roles": ["read", "deploy"]
  }
}
```

Response for an inactive or unknown token:

```json
{ "active": false }
```

### UMA token endpoint

Compatible with `authz-keycloak` and any UMA2 client. When called with an API key as the bearer token and `grant_type=urn:ietf:params:oauth:grant-type:uma-ticket`, the plugin validates the key and returns a direct authorization decision. Any other grant type is proxied transparently to the real Keycloak token endpoint.

```http
POST /realms/{realm}/api-keys/token
Authorization: Bearer mk_Ab3xYz12...
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Auma-ticket&response_mode=decision
```

Response:

```json
{ "result": true }
```

### UMA2 discovery

Returns the standard `uma2-configuration` document with `token_endpoint` and `introspection_endpoint` overridden to point to this plugin's endpoints.

```http
GET /realms/{realm}/api-keys/uma2-configuration
```

## Usage from API clients

Pass the API key as a Bearer token:

```
Authorization: Bearer mk_Ab3xYz12...
```

The backend service calls `/realms/{realm}/api-keys/introspect` with the extracted key to validate the request and retrieve the user identity and roles.

## Changelog

See [CHANGELOG.md](./CHANGELOG.md) or the [GitHub releases](../../releases).
