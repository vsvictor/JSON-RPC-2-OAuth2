# json-rpc-2-oauth2

[Українська версія / Ukrainian version](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/README.uk.md) ·
[Technical specification / Технічне завдання](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/task.md) ·
[English specification](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/task.en.md) ·
[OAuth provider flows](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/README.md) ·
[Examples](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/examples/README.md)

OAuth 2.0 password-grant authentication, PASETO v4.local access/refresh tokens,
dynamic user profiles and role-based authorization for the `json-rpc-2` server.

## Storage implementations

Client integration examples for [Kotlin Multiplatform](https://github.com/vsvictor/JSON-RPC-2-OAuth2/tree/master/examples/kotlin-multiplatform)
and [Flutter](https://github.com/vsvictor/JSON-RPC-2-OAuth2/tree/master/examples/flutter)
are available under the examples directory.

Implemented storage backends are `MongoAuthServer`, `SqliteAuthServer`,
`SqlxAuthServer`, `RedisAuthServer`, `OracleAuthServer`, `MssqlAuthServer` and
`CassandraAuthServer` and `HbaseAuthServer`. `SqlxAuthServer` supports PostgreSQL and MySQL through
`SqlDatabase::{PostgreSql, MySql}`. The common `JsonRpcAuthServer` contract and
`register_auth_methods` RPC wiring are shared by all backends.

HBase uses the Thrift v1 gateway: `db_host` is `host:port` (default port 9090),
`database_name` prefixes the four tables (`auth_{name}_users`, `_emails`,
`_user_roles`, `_role_permissions`). Thrift v1 has no authentication, so
database username/password are rejected. Email uniqueness is enforced with an
atomic counter reservation.

SQLite uses `db_host` as a file path (for example `./auth.sqlite` or
`:memory:`); `database_name` is a fallback path. SQLite has no separate
username/password configuration, so those settings are rejected during
initialization.

PostgreSQL and MySQL usage:

```rust,no_run
use json_rpc_2_oauth2::{JsonRpcAuthServer, SqlDatabase, SqlxAuthServer, TokenConfig};

async fn connect(key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut auth = SqlxAuthServer::new(
        SqlDatabase::PostgreSql,
        key,
        TokenConfig::new("my-service"),
    )?;
    auth.set_db_host("db.example.test:5432");
    auth.set_db_name("my_service");
    auth.set_db_user("service_user");
    auth.set_db_password(std::env::var("DATABASE_PASSWORD")?.as_str());
    auth.initialize_storage().await?;
    Ok(())
}
```

For MySQL, select `SqlDatabase::MySql` and provide its host, database name and
credentials. SQL backends store validated profile values as JSON in
`user_profiles.profile_json`; profile field schema is still enforced by the
crate before writes.

Redis usage:

```rust,no_run
use json_rpc_2_oauth2::{JsonRpcAuthServer, RedisAuthServer, TokenConfig};

async fn connect(key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut auth = RedisAuthServer::new(key, TokenConfig::new("my-service"))?;
    auth.set_db_host("redis.example.test:6379");
    auth.set_db_name("0");
    auth.set_db_user("service_user");
    auth.set_db_password(std::env::var("REDIS_PASSWORD")?.as_str());
    auth.initialize_storage().await?;
    Ok(())
}
```

For Redis, `db_host` accepts a host/port or a `redis://`/`rediss://` URL;
`database_name` selects the Redis logical database number (default `0`).
Authentication records use the `auth:` key prefix. Provision Redis ACL access
to that prefix for the configured user.

Oracle usage:

```rust,no_run
use json_rpc_2_oauth2::{JsonRpcAuthServer, OracleAuthServer, TokenConfig};

async fn connect(key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut auth = OracleAuthServer::new(key, TokenConfig::new("my-service"))?;
    auth.set_db_host("oracle.example.test:1521");
    auth.set_db_name("FREEPDB1");
    auth.set_db_user("service_user");
    auth.set_db_password(std::env::var("ORACLE_PASSWORD")?.as_str());
    auth.initialize_storage().await?;
    Ok(())
}
```

Oracle `db_host` accepts an EZConnect host/port, optionally including its
service path; if omitted, `database_name` is used as the service name. The
backend uses Oracle tables for users and normalized RBAC relationships, with
profile JSON stored in a CLOB.

Microsoft SQL Server usage:

```rust,no_run
use json_rpc_2_oauth2::{JsonRpcAuthServer, MssqlAuthServer, TokenConfig};

async fn connect(key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut auth = MssqlAuthServer::new(key, TokenConfig::new("my-service"))?;
    auth.set_db_host("sqlserver.example.test:1433");
    auth.set_db_name("auth_service");
    auth.set_db_user("service_user");
    auth.set_db_password(std::env::var("MSSQL_PASSWORD")?.as_str());
    auth.initialize_storage().await?;
    Ok(())
}
```

The configured SQL Server database must already exist and be accessible to the
login. The backend creates its `dbo` tables and stores validated profile values
as JSON in `user_profiles.profile_json`. Server certificate verification is
enabled by default; `set_trust_server_certificate(true)` is only suitable for
local development or self-signed test servers.

Cassandra usage:

```rust,no_run
use json_rpc_2_oauth2::{CassandraAuthServer, JsonRpcAuthServer, TokenConfig};

async fn connect(key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut auth = CassandraAuthServer::new(key, TokenConfig::new("my-service"))?;
    auth.set_db_host("cassandra.example.test:9042");
    auth.set_db_name("auth_service");
    auth.set_db_user("service_user");
    auth.set_db_password(std::env::var("CASSANDRA_PASSWORD")?.as_str());
    auth.initialize_storage().await?;
    Ok(())
}
```

The Cassandra backend uses `database_name` as its CQL keyspace. If the keyspace
does not exist, initialization creates it with `SimpleStrategy` and replication
factor `1` for development/single-node use; production clusters should create
the keyspace beforehand with an appropriate replication strategy. The adapter
uses the Scylla Rust driver, which is Cassandra-protocol compatible. By default,
the driver connects to each node at the address it advertises. For a single-node
deployment behind NAT or a TCP proxy, call
`set_translate_peers_to_contact_point(true)` to route discovered node addresses
through the configured contact point; do not enable this for a multi-node
cluster unless that endpoint is a proxy for the cluster.

## Configure and register methods

```rust,no_run
use json_rpc_2_oauth2::{
    JsonRpcAuthServer, MongoAuthServer, ProfileFieldType, TokenConfig,
};
use json_rpc_2_server::RpcServer;
use std::collections::HashMap;

async fn configure(paserk_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut auth = MongoAuthServer::new(paserk_key, TokenConfig::new("my-service"))?;
    auth.set_db_host("mongodb://localhost:27017");
    auth.set_db_name("my_service");
    auth.set_db_user("service_user");
    auth.set_db_password(std::env::var("MONGODB_PASSWORD")?.as_str());
    auth.set_profile_schema(HashMap::from([
        ("display_name".to_owned(), ProfileFieldType::Text),
        ("joined_at".to_owned(), ProfileFieldType::DateTime),
        ("avatar".to_owned(), ProfileFieldType::Blob),
    ]))?;
    auth.initialize_storage().await?;

    let rpc = RpcServer::new();
    auth.register_auth_methods(&rpc)?;
    Ok(())
}
```

The key must be a PASERK-encoded `k4.local` key; generate it once using
`pasetors::keys::SymmetricKey::<pasetors::version4::V4>::generate()` and store
the encoded value in a secret manager. All instances that validate the same
tokens must use the same key.

## Cargo feature selection

The crate is an optional dependency of the application that owns the
`JSON-RPC-2` server; it is not a feature of `json-rpc-2-server` itself because
this crate depends on that server crate. Use the GitHub dependency and forward
features from the application:

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

Default features enable all storage backends and all providers. Set
`default-features = false` and select from `mongodb`, `sqlite`, `sqlx`
(PostgreSQL/MySQL), `redis`, `oracle`, `mssql`, `cassandra`, `hbase`, and
provider features such as `oauth-google`, `oauth-github`, or
`oauth-firebase-authentication`. `all-storages`, `all-oauth-providers`, and
`oauth2` are aggregate features. A call to a provider whose feature is disabled
returns a configuration error. The SQLx backend is shared by PostgreSQL and
MySQL; `postgres` and `mysql` are aliases for `sqlx`.

The app configures and initializes a selected auth storage, then calls
`register_auth_methods` with its `RpcServer`. The OAuth HTTP redirect/callback
routes remain application-owned.

## OAuth2 identity providers

`JsonRpcAuthServer` provides `provider_authorization` and
`handle_provider_callback` for OAuth2 authorization-code flows. Supported
providers are Google, Apple, Microsoft, Facebook, X, LinkedIn, Slack, GitHub,
GitLab, Bitbucket, Discord, Twitch, Spotify, Auth0, and Okta. Microsoft, GitLab,
Auth0, and Okta require a trusted OIDC issuer URL; Microsoft issuers must use
`login.microsoftonline.com`. Apple ID tokens are signature-checked against
Apple's JWKS and validated for issuer and audience.

Firebase Authentication uses its separate
`handle_firebase_id_token(project_id, id_token)` method because Firebase clients
obtain ID tokens through the Firebase SDK rather than this crate's
authorization-code redirect. The server validates the token signature, issuer,
audience, and expiry.

New local accounts are provisioned only when the provider supplies an email
explicitly marked verified. A previously linked identity can still sign in
without a verified email, but matching emails never link accounts
automatically. Use `handle_provider_link` or `link_firebase_id_token` only
after your application has authenticated the local user to whom the identity
will be linked. Keep OAuth client secrets, callback state, and PKCE verifiers
server-side; never trust a callback's `expected_state` parameter from the
browser. Provider credentials are not exposed through JSON-RPC methods.
See the [bilingual provider-flow guides](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/README.md).

```rust,no_run
use json_rpc_2_oauth2::{
    AuthError, JsonRpcAuthServer, OAuth2Provider, ProviderAuthorizationRequest,
    ProviderCallbackRequest,
};

async fn provider_login(
    auth: &impl JsonRpcAuthServer<StorageError = AuthError>,
    client_id: String,
    client_secret: String,
    callback_uri: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let flow = auth.provider_authorization(ProviderAuthorizationRequest {
        provider: OAuth2Provider::Google,
        client_id: client_id.clone(),
        redirect_uri: callback_uri.clone(),
        scopes: Vec::new(),
        issuer_url: None,
    }).await?;

    // Redirect the user to flow.authorization_url. Persist the returned state
    // and PKCE verifier in a server-side session keyed to the browser.
    let _tokens = auth.handle_provider_callback(ProviderCallbackRequest {
        provider: OAuth2Provider::Google,
        client_id,
        client_secret,
        redirect_uri: callback_uri,
        code: "authorization-code-from-callback".to_owned(),
        state: flow.state.clone(),
        expected_state: flow.state,
        pkce_verifier: flow.pkce_verifier,
        issuer_url: None,
    }).await?;
    Ok(())
}
```

In a real callback, take `state` and `code` from the provider response and
compare state with the value saved in the server-side session; never take
`expected_state` from the callback request. Keep the PKCE verifier and client
secret on the server. For Apple, `client_secret` must be the provider-issued
client-secret JWT. The code example illustrates the API; a production callback
must restore state and PKCE data from the server-side session and must not
re-use state across browser sessions.

## RPC methods

- `auth.register`: accepts `email`, `password`, and optional string-valued
  `profile`.
- `auth.login`: accepts `email`, `password`, and `grant_type: "password"`.
- `auth.refresh`: accepts `refresh_token`.
- `auth.updateProfile`: accepts `profile` plus a bearer token.
- `rbac.addRoleToUser` / `rbac.removeRoleFromUser`: require
  `rbac.users.write`.
- `rbac.addPermissionToRole` / `rbac.removePermissionFromRole`: require
  `rbac.roles.write`.

Until the upstream JSON-RPC transport exposes authorization headers through
`TransportContext`, protected RPC methods accept either `access_token` or
`authorization: "Bearer <token>"` in params. Applications with transport-level
bearer headers can use `authenticate_access_token` or `require_permission` in
their own middleware instead. The first administrative role and permissions
must be provisioned out of band.

Dynamic profile values are accepted as strings and validated/cast according to
`ProfileFieldType`: text, signed 64-bit integer, finite float, boolean, RFC 3339
datetime, or standard Base64-encoded binary. Profile field names are restricted
to ASCII identifiers to prevent MongoDB dotted-path/operator injection.
