# Technical specification: `json-rpc-2-oauth2`

[Ukrainian version](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/task.md)

This specification describes the implemented authentication, authorization,
profile, storage, OAuth2-provider, and Cargo feature contract for the
[`json-rpc-2-oauth2` crate](https://github.com/vsvictor/JSON-RPC-2-OAuth2),
which integrates with the
[`JSON-RPC-2` Rust server](https://github.com/vsvictor/JSON-RPC-2).

## 1. Integration and dependency policy

The crate is an optional application dependency; it is not a feature or a
reverse dependency of `json-rpc-2-server`. The OAuth2 crate itself depends on
the server crate, so adding it back into that same crate would create a Cargo
dependency cycle. An application can make the integration optional by
declaring the crate from GitHub and forwarding Cargo features:

```toml
[dependencies]
json-rpc-2-oauth2 = { git = "https://github.com/vsvictor/JSON-RPC-2-OAuth2", default-features = false, optional = true }

[features]
auth-google-sqlite = [
    "dep:json-rpc-2-oauth2",
    "json-rpc-2-oauth2/sqlite",
    "json-rpc-2-oauth2/oauth-google",
]
```

No local `path` dependency is permitted. The crate's
[`Cargo.toml`](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/Cargo.toml)
references JSON-RPC-2 through its GitHub repository and a pinned revision.
Register RPC authentication, profile, and RBAC handlers on an application
`RpcServer` with `register_auth_methods`.

Default features preserve the complete existing build:

| Feature | Effect |
|---|---|
| `all-storages` | Enables MongoDB, SQLite, SQLx (PostgreSQL/MySQL/SQLite), Redis, Oracle, MS SQL Server, Cassandra, and HBase adapters. |
| `all-oauth-providers` / `oauth2` | Enables all supported OAuth/OIDC providers and Firebase ID-token verification. |
| `mongodb`, `sqlite`, `sqlx`, `redis`, `oracle`, `mssql`, `cassandra`, `hbase` | Enables the corresponding storage implementation(s). `postgres` and `mysql` are aliases for `sqlx`. |
| `oauth-google`, `oauth-firebase-authentication`, `oauth-apple`, `oauth-microsoft`, `oauth-facebook`, `oauth-x`, `oauth-linkedin`, `oauth-slack`, `oauth-github`, `oauth-gitlab`, `oauth-bitbucket`, `oauth-discord`, `oauth-twitch`, `oauth-spotify`, `oauth-auth0`, `oauth-okta` | Enables the named identity provider. A provider whose feature is disabled returns an explicit configuration error. |

Use `default-features = false` and select only the storage and provider features
needed by the application. The SQLx adapter is shared by PostgreSQL and MySQL;
the separate SQLite adapter uses SQLx's SQLite driver.

## 2. Authentication and authorization

The public server contract is `JsonRpcAuthServer`. It covers database
configuration (`set_db_host`, `set_db_name`, `set_db_user`,
`set_db_password`), storage initialization, profile schema configuration,
password registration/login, token refresh, external identity login/linking,
and RBAC operations. Concrete adapters are `MongoAuthServer`,
`SqliteAuthServer`, `SqlxAuthServer`, `RedisAuthServer`, `OracleAuthServer`,
`MssqlAuthServer`, `CassandraAuthServer`, and `HbaseAuthServer`.

Access and refresh tokens use PASETO v4.local. `TokenConfig` sets the issuer
and token lifetimes (15 minutes for access and 30 days for refresh by default).
The encoded `k4.local` key must be shared by service instances that validate
the same tokens. Access-token claims include issuer, subject, expiry, roles,
permissions, and token use; access and refresh tokens are not interchangeable.
Password storage uses Argon2.

`register_auth_methods` installs the following application RPC methods:

- `auth.register`, `auth.login`, `auth.refresh`, and `auth.updateProfile`.
- `rbac.addRoleToUser` / `rbac.removeRoleFromUser`, requiring
  `rbac.users.write`.
- `rbac.addPermissionToRole` / `rbac.removePermissionFromRole`, requiring
  `rbac.roles.write`.

The built-in OAuth methods are library APIs, not registered browser redirect
RPC methods. The host application owns its HTTP redirect/callback routes and
browser-session state. Until the upstream transport exposes authorization
headers through its request context, protected RPC handlers accept
`access_token` or `authorization` parameters; applications may instead call
`authenticate_access_token` and `require_permission` in middleware.

## 3. Dynamic user profiles

Applications define profile fields in code as a map of field names to
`ProfileFieldType`: `Text`, `Integer` (signed 64-bit), `Float` (finite),
`Boolean`, `DateTime` (RFC 3339), and `Blob` (standard Base64 on JSON-RPC).
Values are validated before storage. Unknown fields, invalid values, and
unsafe field names are rejected. The common abstract types map to PostgreSQL,
MySQL, Oracle, MS SQL Server, SQLite, MongoDB, Redis, Cassandra, and HBase
representations without exposing backend-specific profile types to callers.

## 4. Storage adapters

| Adapter | Configuration and implementation notes |
|---|---|
| MongoDB | `db_host` accepts a MongoDB URI; users, profiles, roles, permissions, and external identities are persisted in collections with required uniqueness constraints. |
| SQLite | `db_host` is a file path or SQLite URI; `database_name` is a fallback path. Separate database username/password settings are rejected. |
| PostgreSQL / MySQL | `SqlxAuthServer` uses `SqlDatabase::{PostgreSql, MySql}`. SQL profile values are validated and serialized as JSON. |
| Redis | `db_host` accepts host/port or `redis://` / `rediss://`; `database_name` selects the logical DB. Records use the `auth:` key prefix. |
| Oracle | `db_host` accepts EZConnect host/port and optional service path; profile JSON is stored in a CLOB. |
| MS SQL Server | The target database must exist; server-certificate validation is enabled by default. |
| Cassandra | `database_name` is the CQL keyspace. A missing keyspace is created for development with `SimpleStrategy` and replication factor 1; production deployments should provision an appropriate strategy. |
| HBase | Uses the Thrift v1 gateway with `host:port` (default 9090). Thrift v1 has no authentication; database username/password are rejected. |

All implemented adapters persist external identities by the unique
`(provider, subject)` pair.

## 5. OAuth2 and external identities

The authorization-code flow is available through
`provider_authorization` and `handle_provider_callback`. The library creates
the authorization URL with a random `state` and PKCE S256 challenge, exchanges
the code, retrieves provider identity data, and returns local PASETO tokens.
The host application must store state and the PKCE verifier in a server-side
session and restore them on callback; never trust callback-supplied
`expected_state` or expose client secrets/verifiers to the browser.

Supported authorization-code / OIDC providers are Google, Apple, Microsoft,
Facebook (Meta), X, LinkedIn, Slack, GitHub, GitLab, Bitbucket, Discord, Twitch,
Spotify, Auth0, and Okta. Microsoft, GitLab, Auth0, and Okta require a trusted
OIDC issuer URL. Microsoft issuer URLs must use `login.microsoftonline.com`.
OIDC discovery validates issuer and endpoint origins; Microsoft Graph is
allowed for Microsoft userinfo. Apple ID tokens are verified using Apple's
JWKS, issuer, audience, and expiry.

Firebase Authentication has a separate `handle_firebase_id_token` flow. The
client obtains a Firebase ID token with Firebase Authentication SDK; the
server verifies its RS256 signature via Secure Token JWKS and validates
issuer, audience, subject, and expiry against the configured project ID.
Firebase is not an authorization-code redirect provider in this API.

External account rules:

1. A previously linked `(provider, subject)` can sign in without an email.
2. A new local account may be provisioned only when the provider supplies an
   email explicitly marked verified.
3. Matching an existing local email never links or merges accounts; the
   library returns `AccountLinkRequired`.
4. Link a provider only after the application has authenticated the existing
   local user. `handle_provider_link` and `link_firebase_id_token` do not
   authenticate that user themselves.
5. OAuth tokens and provider credentials are not used as the service's local
   access tokens.

See the
[bilingual provider-flow index](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/README.md)
and the separate guides for
[Google](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/google.md),
[Firebase Authentication](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/firebase-authentication.md),
[Apple](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/apple.md),
[Microsoft](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/microsoft.md),
[Facebook](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/facebook.md),
[X](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/x.md),
[LinkedIn](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/linkedin.md),
[Slack](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/slack.md),
[GitHub](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/github.md),
[GitLab](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/gitlab.md),
[Bitbucket](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/bitbucket.md),
[Discord](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/discord.md),
[Twitch](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/twitch.md),
[Spotify](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/spotify.md),
[Auth0](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/auth0.md),
and [Okta](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/okta.md).

## 6. Acceptance and verification

- The crate builds with default features and with a minimal selected feature
  set using `default-features = false`.
- A disabled storage or provider does not require its optional runtime
  dependency and is not exported as an available adapter/API.
- Password, token, profile, RBAC, and external identity operations are tested.
- [`examples/`](https://github.com/vsvictor/JSON-RPC-2-OAuth2/tree/master/examples)
  contains a bilingual index and SQLite/RPC, MongoDB, and Google OAuth2 examples
  that compile with their required minimal Cargo features.
- Additional client examples demonstrate JSON-RPC calls from
  [Kotlin Multiplatform](https://github.com/vsvictor/JSON-RPC-2-OAuth2/tree/master/examples/kotlin-multiplatform)
  and [Flutter](https://github.com/vsvictor/JSON-RPC-2-OAuth2/tree/master/examples/flutter);
  Flutter uses BLoC for state management and secure token storage.
- Integration tests exercise configured database adapters with test
  containers where supported by the test environment.
- OAuth callback integration against real provider accounts is deployment
  configuration dependent and is not implied by unit or storage tests.
- Validation and authorization failures map to JSON-RPC errors; database,
  crypto, or serialization failures are not reported as successful operations.

Project source and current documentation:
[OAuth2 crate on GitHub](https://github.com/vsvictor/JSON-RPC-2-OAuth2) ·
[JSON-RPC-2 on GitHub](https://github.com/vsvictor/JSON-RPC-2).
