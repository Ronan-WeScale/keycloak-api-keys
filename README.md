# keycloak-api-keys

Plugin Keycloak pour la gestion de clés d'API opaques (style GitHub PAT) liées aux utilisateurs Keycloak.

## Compatibilité

<!-- COMPAT_TABLE_START -->
| Plugin     | Keycloak  |
|------------|-----------|
| 1.1.0      | 26.0.x   |
| 1.0.0      | 26.0.x   |
<!-- COMPAT_TABLE_END -->

## Build

```bash
mvn package -DskipTests
# → target/keycloak-api-keys-1.0.0.jar
```

## Installation

Copier le JAR dans le répertoire `providers/` de Keycloak puis relancer le build :

```bash
cp target/keycloak-api-keys-1.0.0.jar /opt/keycloak/providers/
/opt/keycloak/bin/kc.sh build
/opt/keycloak/bin/kc.sh start
```

Sur Kubernetes, le JAR peut être monté via un `initContainer` ou un `ConfigMap` de type binaire. L'emplacement reste `/opt/keycloak/providers/`.

## Endpoints

Tous les endpoints sont sous `/realms/{realm}/api-keys`.

### Lister ses clés

```http
GET /realms/{realm}/api-keys
Authorization: Bearer <jwt_keycloak>
```

### Créer une clé

```http
POST /realms/{realm}/api-keys
Authorization: Bearer <jwt_keycloak>
Content-Type: application/json

{
  "name": "CI pipeline",
  "expiresAt": null
}
```

Réponse (la `rawKey` n'est retournée qu'une seule fois) :

```json
{
  "key": {
    "id": "abc123",
    "name": "CI pipeline",
    "prefix": "mk_Ab3xYz12...",
    "createdAt": 1714000000000,
    "expiresAt": null,
    "lastUsed": null
  },
  "rawKey": "mk_Ab3xYz12..."
}
```

### Révoquer une clé

```http
DELETE /realms/{realm}/api-keys/{id}
Authorization: Bearer <jwt_keycloak>
```

### Vérifier une clé (appelé par les services backend)

```http
POST /realms/{realm}/api-keys/verify
Content-Type: application/json

{ "key": "mk_Ab3xYz12..." }
```

```json
{ "valid": true, "userId": "...", "username": "john", "email": "john@example.com" }
```

Cet endpoint n'exige pas de JWT — il doit être protégé au niveau réseau (non exposé publiquement) ou restreint à un réseau interne.

## Utilisation côté API

```
Authorization: Bearer mk_Ab3xYz12...
```

Le service backend appelle `/realms/{realm}/api-keys/verify` avec la clé extraite du header pour valider la requête et récupérer l'identité de l'utilisateur.

## Changelog

Voir [CHANGELOG.md](./CHANGELOG.md) ou les [releases GitHub](../../releases).
