use crate::{
    AccessTokenClaims, AuthError, DbConfig, ExternalIdentity, JsonRpcAuthServer, LoginRequest,
    ProfileFieldType, RegisterRequest, TokenConfig, TokenResponse, UserResponse,
    token::TokenService,
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use async_trait::async_trait;
use scylla::{
    client::{session::Session, session_builder::SessionBuilder},
    errors::TranslationError,
    policies::address_translator::{AddressTranslator, UntranslatedPeer},
    response::query_result::QueryRowsResult,
};
use serde_json::Value;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
};
use tokio::sync::OnceCell;

struct Inner {
    config: RwLock<DbConfig>,
    profile_schema: RwLock<HashMap<String, ProfileFieldType>>,
    translate_peers_to_contact_point: RwLock<bool>,
    session: OnceCell<Arc<Session>>,
    keyspace: OnceCell<String>,
    tokens: TokenService,
}

/// Cassandra-compatible backend implemented with the Scylla Rust driver.
#[derive(Clone)]
pub struct CassandraAuthServer {
    inner: Arc<Inner>,
}

impl CassandraAuthServer {
    /// Create a Cassandra authentication service using a PASERK-encoded v4.local key.
    pub fn new(paserk_key: &str, token_config: TokenConfig) -> Result<Self, AuthError> {
        Ok(Self {
            inner: Arc::new(Inner {
                config: RwLock::new(DbConfig::default()),
                profile_schema: RwLock::new(HashMap::new()),
                translate_peers_to_contact_point: RwLock::new(false),
                session: OnceCell::new(),
                keyspace: OnceCell::new(),
                tokens: TokenService::new(paserk_key, token_config)?,
            }),
        })
    }

    pub fn set_profile_schema(
        &mut self,
        schema: HashMap<String, ProfileFieldType>,
    ) -> Result<(), AuthError> {
        for name in schema.keys() {
            if !valid_identifier(name) {
                return Err(AuthError::InvalidConfiguration(format!(
                    "invalid profile field name `{name}`"
                )));
            }
        }
        *self
            .inner
            .profile_schema
            .write()
            .expect("schema lock poisoned") = schema;
        Ok(())
    }

    /// Route every discovered Cassandra node through the configured contact point.
    ///
    /// Enable this only for single-node deployments or TCP proxies/NAT setups where
    /// advertised node addresses are not reachable from this process.
    pub fn set_translate_peers_to_contact_point(&mut self, enabled: bool) {
        *self
            .inner
            .translate_peers_to_contact_point
            .write()
            .expect("address translation lock poisoned") = enabled;
    }

    pub fn authenticate_access_token(&self, token: &str) -> Result<AccessTokenClaims, AuthError> {
        self.inner.tokens.verify_access_token(token)
    }

    pub fn require_permission(
        &self,
        token: &str,
        permission: &str,
    ) -> Result<AccessTokenClaims, AuthError> {
        let claims = self.authenticate_access_token(token)?;
        if claims
            .permissions
            .iter()
            .any(|granted| granted == permission || granted == "*")
        {
            Ok(claims)
        } else {
            Err(AuthError::Forbidden)
        }
    }

    pub fn register_auth_methods(
        &self,
        server: &json_rpc_2_server::RpcServer,
    ) -> Result<(), json_rpc_2_server::RegistrationError> {
        crate::register_auth_methods(self.clone(), server)
    }

    fn config(&self) -> DbConfig {
        self.inner
            .config
            .read()
            .expect("config lock poisoned")
            .clone()
    }

    fn schema(&self) -> HashMap<String, ProfileFieldType> {
        self.inner
            .profile_schema
            .read()
            .expect("schema lock poisoned")
            .clone()
    }

    fn session(&self) -> Result<Arc<Session>, AuthError> {
        self.inner
            .session
            .get()
            .cloned()
            .ok_or(AuthError::StorageNotInitialized)
    }

    fn qualified_table(&self, table: &str) -> Result<String, AuthError> {
        let keyspace = self
            .inner
            .keyspace
            .get()
            .ok_or(AuthError::StorageNotInitialized)?;
        Ok(format!("{keyspace}.{table}"))
    }

    async fn roles_for_user(&self, user_id: &str) -> Result<Vec<String>, AuthError> {
        let table = self.qualified_table("user_roles")?;
        let rows = select_rows(
            &self.session()?,
            &format!("SELECT role_name FROM {table} WHERE user_id = ?"),
            (user_id,),
        )
        .await?;
        let mut roles = rows
            .rows::<(String,)>()
            .map_err(cassandra_error)?
            .map(|row| row.map(|(role,)| role).map_err(cassandra_error))
            .collect::<Result<Vec<_>, _>>()?;
        roles.sort();
        Ok(roles)
    }

    async fn permissions_for_roles(&self, roles: &[String]) -> Result<Vec<String>, AuthError> {
        let table = self.qualified_table("role_permissions")?;
        let session = self.session()?;
        let mut permissions = Vec::new();
        for role in roles {
            let rows = select_rows(
                &session,
                &format!("SELECT permission_name FROM {table} WHERE role_name = ?"),
                (role.as_str(),),
            )
            .await?;
            permissions.extend(
                rows.rows::<(String,)>()
                    .map_err(cassandra_error)?
                    .map(|row| row.map(|(permission,)| permission).map_err(cassandra_error))
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        permissions.sort();
        permissions.dedup();
        Ok(permissions)
    }

    async fn load_user(&self, user_id: &str) -> Result<UserResponse, AuthError> {
        let table = self.qualified_table("users_by_id")?;
        let rows = select_rows(
            &self.session()?,
            &format!("SELECT email, created_at, profile_json FROM {table} WHERE user_id = ?"),
            (user_id,),
        )
        .await?;
        let (email, created_at, profile_json) = rows
            .maybe_first_row::<(String, String, String)>()
            .map_err(cassandra_error)?
            .ok_or_else(|| AuthError::InvalidParams("user not found".to_owned()))?;
        Ok(UserResponse {
            id: user_id.to_owned(),
            email,
            created_at,
            roles: self.roles_for_user(user_id).await?,
            profile: serde_json::from_str(&profile_json)?,
        })
    }
}

#[async_trait]
impl JsonRpcAuthServer for CassandraAuthServer {
    type StorageError = AuthError;

    fn set_db_host(&mut self, host: &str) {
        self.inner
            .config
            .write()
            .expect("config lock poisoned")
            .host = host.to_owned();
    }

    fn set_db_name(&mut self, name: &str) {
        self.inner
            .config
            .write()
            .expect("config lock poisoned")
            .database_name = name.to_owned();
    }

    fn set_db_user(&mut self, user: &str) {
        self.inner
            .config
            .write()
            .expect("config lock poisoned")
            .db_user = Some(user.to_owned());
    }

    fn set_db_password(&mut self, password: &str) {
        self.inner
            .config
            .write()
            .expect("config lock poisoned")
            .db_password = Some(password.to_owned());
    }

    fn get_db_config(&self) -> DbConfig {
        self.config()
    }

    fn define_profile_schema(&mut self, schema: HashMap<String, ProfileFieldType>) {
        *self
            .inner
            .profile_schema
            .write()
            .expect("schema lock poisoned") = schema;
    }

    fn get_profile_schema(&self) -> HashMap<String, ProfileFieldType> {
        self.schema()
    }

    async fn initialize_storage(&self) -> Result<(), Self::StorageError> {
        if self.inner.session.get().is_some() {
            return Ok(());
        }
        let config = self.config();
        let host = config.host.trim();
        if host.is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "Cassandra contact point is required".to_owned(),
            ));
        }
        let keyspace = config.database_name.trim();
        if !valid_identifier(keyspace) {
            return Err(AuthError::InvalidConfiguration(
                "Cassandra database_name must be a CQL identifier".to_owned(),
            ));
        }
        if config.db_user.is_some() != config.db_password.is_some() {
            return Err(AuthError::InvalidConfiguration(
                "Cassandra username and password must be configured together".to_owned(),
            ));
        }
        let mut builder = SessionBuilder::new().known_node(host);
        if *self
            .inner
            .translate_peers_to_contact_point
            .read()
            .expect("address translation lock poisoned")
        {
            let contact_point = resolve_contact_point(host).await?;
            builder = builder.address_translator(Arc::new(ContactPointTranslator {
                address: contact_point,
            }));
        }
        if let (Some(user), Some(password)) = (&config.db_user, &config.db_password) {
            builder = builder.user(user, password);
        }
        let session = Arc::new(builder.build().await.map_err(cassandra_error)?);
        session
            .query_unpaged(
                format!(
                    "CREATE KEYSPACE IF NOT EXISTS {keyspace} WITH REPLICATION = \
                     {{'class': 'SimpleStrategy', 'replication_factor': 1}}"
                ),
                (),
            )
            .await
            .map_err(cassandra_error)?;
        session
            .use_keyspace(keyspace, false)
            .await
            .map_err(cassandra_error)?;
        for statement in [
            "CREATE TABLE IF NOT EXISTS users_by_email (email text PRIMARY KEY, user_id text, password_hash text, created_at text)",
            "CREATE TABLE IF NOT EXISTS users_by_id (user_id text PRIMARY KEY, email text, created_at text, profile_json text)",
            "CREATE TABLE IF NOT EXISTS user_roles (user_id text, role_name text, PRIMARY KEY (user_id, role_name))",
            "CREATE TABLE IF NOT EXISTS role_permissions (role_name text, permission_name text, PRIMARY KEY (role_name, permission_name))",
            "CREATE TABLE IF NOT EXISTS external_identities (provider text, subject text, user_id text, PRIMARY KEY ((provider, subject)))",
        ] {
            session
                .query_unpaged(statement, ())
                .await
                .map_err(cassandra_error)?;
        }
        let _ = self.inner.keyspace.set(keyspace.to_owned());
        let _ = self.inner.session.set(session);
        Ok(())
    }

    fn authenticate_access_token(&self, token: &str) -> Result<AccessTokenClaims, AuthError> {
        CassandraAuthServer::authenticate_access_token(self, token)
    }

    fn require_permission(
        &self,
        token: &str,
        permission: &str,
    ) -> Result<AccessTokenClaims, AuthError> {
        CassandraAuthServer::require_permission(self, token, permission)
    }

    async fn handle_refresh(
        &self,
        refresh_token: &str,
    ) -> Result<TokenResponse, Self::StorageError> {
        let user_id = self.inner.tokens.verify_refresh_token(refresh_token)?;
        let table = self.qualified_table("users_by_id")?;
        let rows = select_rows(
            &self.session()?,
            &format!("SELECT user_id FROM {table} WHERE user_id = ?"),
            (user_id.as_str(),),
        )
        .await?;
        if rows.rows_num() == 0 {
            return Err(AuthError::Unauthorized);
        }
        let roles = self.roles_for_user(&user_id).await?;
        let permissions = self.permissions_for_roles(&roles).await?;
        self.inner
            .tokens
            .refresh_pair(refresh_token, &roles, &permissions)
    }

    async fn handle_register(
        &self,
        req: RegisterRequest,
    ) -> Result<UserResponse, Self::StorageError> {
        let email = normalize_email(&req.email)?;
        if req.password.chars().count() < 8 {
            return Err(AuthError::InvalidParams(
                "password must contain at least 8 characters".to_owned(),
            ));
        }
        let profile = crate::profile_values::parse_profile(&self.schema(), &req.profile)?;
        let profile_json = serde_json::to_string(&profile)?;
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(req.password.as_bytes(), &salt)
            .map_err(|error| AuthError::PasswordHash(error.to_string()))?
            .to_string();
        let user_id = uuid::Uuid::new_v4().to_string();
        let created_at = chrono::Utc::now().to_rfc3339();
        let email_table = self.qualified_table("users_by_email")?;
        let id_table = self.qualified_table("users_by_id")?;
        let session = self.session()?;
        session
            .query_unpaged(
                format!(
                    "INSERT INTO {email_table} (email, user_id, password_hash, created_at) \
                     VALUES (?, ?, ?, ?) IF NOT EXISTS"
                ),
                (
                    email.as_str(),
                    user_id.as_str(),
                    password_hash.as_str(),
                    created_at.as_str(),
                ),
            )
            .await
            .map_err(cassandra_error)?;
        let rows = select_rows(
            &session,
            &format!("SELECT user_id FROM {email_table} WHERE email = ?"),
            (email.as_str(),),
        )
        .await?;
        let (stored_id,) = rows
            .maybe_first_row::<(String,)>()
            .map_err(cassandra_error)?
            .ok_or_else(|| {
                AuthError::Cassandra("conditional email insert produced no readable row".to_owned())
            })?;
        if stored_id != user_id {
            return Err(AuthError::DuplicateEmail);
        }
        let result = session
            .query_unpaged(
                format!(
                    "INSERT INTO {id_table} (user_id, email, created_at, profile_json) \
                     VALUES (?, ?, ?, ?)"
                ),
                (
                    user_id.as_str(),
                    email.as_str(),
                    created_at.as_str(),
                    profile_json.as_str(),
                ),
            )
            .await
            .map_err(cassandra_error);
        if let Err(error) = result {
            let cleanup = session
                .query_unpaged(
                    format!("DELETE FROM {email_table} WHERE email = ? IF user_id = ?"),
                    (email.as_str(), user_id.as_str()),
                )
                .await;
            if let Err(cleanup_error) = cleanup {
                return Err(AuthError::Cassandra(format!(
                    "{error}; additionally failed to remove reserved email: {cleanup_error}"
                )));
            }
            return Err(error);
        }
        self.load_user(&user_id).await
    }

    async fn handle_login(&self, req: LoginRequest) -> Result<TokenResponse, Self::StorageError> {
        if req.grant_type != "password" {
            return Err(AuthError::InvalidParams(
                "grant_type must be `password`".to_owned(),
            ));
        }
        let email = normalize_email(&req.email)?;
        let table = self.qualified_table("users_by_email")?;
        let rows = select_rows(
            &self.session()?,
            &format!("SELECT user_id, password_hash FROM {table} WHERE email = ?"),
            (email.as_str(),),
        )
        .await?;
        let (user_id, stored_hash) = rows
            .maybe_first_row::<(String, String)>()
            .map_err(cassandra_error)?
            .ok_or(AuthError::Unauthorized)?;
        let parsed_hash = PasswordHash::new(&stored_hash).map_err(|_| AuthError::Unauthorized)?;
        Argon2::default()
            .verify_password(req.password.as_bytes(), &parsed_hash)
            .map_err(|_| AuthError::Unauthorized)?;
        let roles = self.roles_for_user(&user_id).await?;
        let permissions = self.permissions_for_roles(&roles).await?;
        self.inner.tokens.issue_pair(&user_id, &roles, &permissions)
    }

    async fn handle_external_login(
        &self,
        identity: ExternalIdentity,
    ) -> Result<TokenResponse, AuthError> {
        if identity.subject.trim().is_empty() {
            return Err(AuthError::Unauthorized);
        }
        let session = self.session()?;
        let table = self.qualified_table("external_identities")?;
        let provider = identity.provider.storage_key();
        let rows = select_rows(
            &session,
            &format!("SELECT user_id FROM {table} WHERE provider = ? AND subject = ?"),
            (provider, identity.subject.as_str()),
        )
        .await?;
        let existing = rows
            .maybe_first_row::<(String,)>()
            .map_err(cassandra_error)?
            .map(|(id,)| id);
        let user_id = if let Some(user_id) = existing {
            user_id
        } else {
            if !identity.email_verified {
                return Err(AuthError::Unauthorized);
            }
            let email = identity.email.ok_or(AuthError::Unauthorized)?;
            let password = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
            let user = match self
                .handle_register(RegisterRequest {
                    email: email.clone(),
                    password,
                    profile: HashMap::new(),
                })
                .await
            {
                Ok(user) => user,
                Err(AuthError::DuplicateEmail) => return Err(AuthError::AccountLinkRequired),
                Err(error) => return Err(error),
            };
            session
                .query_unpaged(
                    format!(
                        "INSERT INTO {table} (provider, subject, user_id) VALUES (?, ?, ?) IF NOT EXISTS"
                    ),
                    (provider, identity.subject.as_str(), user.id.as_str()),
                )
                .await
                .map_err(cassandra_error)?;
            let rows = select_rows(
                &session,
                &format!("SELECT user_id FROM {table} WHERE provider = ? AND subject = ?"),
                (provider, identity.subject.as_str()),
            )
            .await?;
            let (stored_id,) = rows
                .maybe_first_row::<(String,)>()
                .map_err(cassandra_error)?
                .ok_or(AuthError::Unauthorized)?;
            if stored_id != user.id {
                let email_table = self.qualified_table("users_by_email")?;
                let id_table = self.qualified_table("users_by_id")?;
                session
                    .query_unpaged(
                        format!("DELETE FROM {email_table} WHERE email = ? IF user_id = ?"),
                        (email.as_str(), user.id.as_str()),
                    )
                    .await
                    .map_err(cassandra_error)?;
                session
                    .query_unpaged(
                        format!("DELETE FROM {id_table} WHERE user_id = ?"),
                        (user.id.as_str(),),
                    )
                    .await
                    .map_err(cassandra_error)?;
                return Err(AuthError::Unauthorized);
            }
            user.id
        };
        let roles = self.roles_for_user(&user_id).await?;
        let permissions = self.permissions_for_roles(&roles).await?;
        self.inner.tokens.issue_pair(&user_id, &roles, &permissions)
    }

    async fn link_external_identity(
        &self,
        user_id: String,
        identity: ExternalIdentity,
    ) -> Result<(), AuthError> {
        if identity.subject.trim().is_empty() {
            return Err(AuthError::Unauthorized);
        }
        let session = self.session()?;
        let users = self.qualified_table("users_by_id")?;
        let user = select_rows(
            &session,
            &format!("SELECT user_id FROM {users} WHERE user_id = ?"),
            (user_id.as_str(),),
        )
        .await?;
        if user.rows_num() == 0 {
            return Err(AuthError::InvalidParams("user not found".to_owned()));
        }
        let table = self.qualified_table("external_identities")?;
        session
            .query_unpaged(
                format!(
                    "INSERT INTO {table} (provider, subject, user_id) VALUES (?, ?, ?) IF NOT EXISTS"
                ),
                (
                    identity.provider.storage_key(),
                    identity.subject.as_str(),
                    user_id.as_str(),
                ),
            )
            .await
            .map_err(cassandra_error)?;
        let rows = select_rows(
            &session,
            &format!("SELECT user_id FROM {table} WHERE provider = ? AND subject = ?"),
            (identity.provider.storage_key(), identity.subject.as_str()),
        )
        .await?;
        let (stored_id,) = rows
            .maybe_first_row::<(String,)>()
            .map_err(cassandra_error)?
            .ok_or(AuthError::Unauthorized)?;
        if stored_id != user_id {
            return Err(AuthError::AccountLinkRequired);
        }
        Ok(())
    }

    async fn handle_update_profile(
        &self,
        user_id: String,
        profile_data: HashMap<String, String>,
    ) -> Result<UserResponse, Self::StorageError> {
        let updates = crate::profile_values::parse_profile(&self.schema(), &profile_data)?;
        let table = self.qualified_table("users_by_id")?;
        let session = self.session()?;
        let rows = select_rows(
            &session,
            &format!("SELECT profile_json FROM {table} WHERE user_id = ?"),
            (user_id.as_str(),),
        )
        .await?;
        let (current_json,) = rows
            .maybe_first_row::<(String,)>()
            .map_err(cassandra_error)?
            .ok_or_else(|| AuthError::InvalidParams("user not found".to_owned()))?;
        let mut profile: HashMap<String, Value> = serde_json::from_str(&current_json)?;
        profile.extend(updates);
        let updated_json = serde_json::to_string(&profile)?;
        session
            .query_unpaged(
                format!(
                    "UPDATE {table} SET profile_json = ? WHERE user_id = ? \
                     IF profile_json = ?"
                ),
                (
                    updated_json.as_str(),
                    user_id.as_str(),
                    current_json.as_str(),
                ),
            )
            .await
            .map_err(cassandra_error)?;
        self.load_user(&user_id).await
    }

    async fn handle_add_role(
        &self,
        user_id: String,
        role_name: String,
    ) -> Result<(), Self::StorageError> {
        validate_name("role", &role_name)?;
        let users = self.qualified_table("users_by_id")?;
        let rows = select_rows(
            &self.session()?,
            &format!("SELECT user_id FROM {users} WHERE user_id = ?"),
            (user_id.as_str(),),
        )
        .await?;
        if rows.rows_num() == 0 {
            return Err(AuthError::InvalidParams("user not found".to_owned()));
        }
        let roles = self.qualified_table("user_roles")?;
        self.session()?
            .query_unpaged(
                format!("INSERT INTO {roles} (user_id, role_name) VALUES (?, ?)"),
                (user_id.as_str(), role_name.as_str()),
            )
            .await
            .map_err(cassandra_error)?;
        Ok(())
    }

    async fn handle_remove_role(
        &self,
        user_id: String,
        role_name: String,
    ) -> Result<(), Self::StorageError> {
        let table = self.qualified_table("user_roles")?;
        let rows = select_rows(
            &self.session()?,
            &format!("SELECT role_name FROM {table} WHERE user_id = ? AND role_name = ?"),
            (user_id.as_str(), role_name.as_str()),
        )
        .await?;
        if rows.rows_num() == 0 {
            return Err(AuthError::InvalidParams(
                "user role assignment not found".to_owned(),
            ));
        }
        self.session()?
            .query_unpaged(
                format!("DELETE FROM {table} WHERE user_id = ? AND role_name = ?"),
                (user_id.as_str(), role_name.as_str()),
            )
            .await
            .map_err(cassandra_error)?;
        Ok(())
    }

    async fn handle_add_permission(
        &self,
        role_name: String,
        permission_name: String,
    ) -> Result<(), Self::StorageError> {
        validate_name("role", &role_name)?;
        validate_name("permission", &permission_name)?;
        let table = self.qualified_table("role_permissions")?;
        self.session()?
            .query_unpaged(
                format!("INSERT INTO {table} (role_name, permission_name) VALUES (?, ?)"),
                (role_name.as_str(), permission_name.as_str()),
            )
            .await
            .map_err(cassandra_error)?;
        Ok(())
    }

    async fn handle_remove_permission(
        &self,
        role_name: String,
        permission_name: String,
    ) -> Result<(), Self::StorageError> {
        let table = self.qualified_table("role_permissions")?;
        let rows = select_rows(
            &self.session()?,
            &format!(
                "SELECT permission_name FROM {table} WHERE role_name = ? AND permission_name = ?"
            ),
            (role_name.as_str(), permission_name.as_str()),
        )
        .await?;
        if rows.rows_num() == 0 {
            return Err(AuthError::InvalidParams(
                "role permission assignment not found".to_owned(),
            ));
        }
        self.session()?
            .query_unpaged(
                format!("DELETE FROM {table} WHERE role_name = ? AND permission_name = ?"),
                (role_name.as_str(), permission_name.as_str()),
            )
            .await
            .map_err(cassandra_error)?;
        Ok(())
    }
}

struct ContactPointTranslator {
    address: SocketAddr,
}

#[async_trait]
impl AddressTranslator for ContactPointTranslator {
    async fn translate_address(
        &self,
        _untranslated_peer: &UntranslatedPeer,
    ) -> Result<SocketAddr, TranslationError> {
        Ok(self.address)
    }
}

async fn resolve_contact_point(host: &str) -> Result<SocketAddr, AuthError> {
    let addresses = tokio::net::lookup_host(host)
        .await
        .map_err(cassandra_error)?;
    for address in addresses {
        if tokio::net::TcpStream::connect(address).await.is_ok() {
            return Ok(address);
        }
    }
    Err(AuthError::InvalidConfiguration(format!(
        "Cassandra contact point `{host}` is not reachable"
    )))
}

async fn select_rows(
    session: &Arc<Session>,
    statement: &str,
    values: impl scylla::serialize::row::SerializeRow,
) -> Result<QueryRowsResult, AuthError> {
    session
        .query_unpaged(statement, values)
        .await
        .map_err(cassandra_error)?
        .into_rows_result()
        .map_err(cassandra_error)
}

fn normalize_email(email: &str) -> Result<String, AuthError> {
    let email = email.trim().to_ascii_lowercase();
    let mut parts = email.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    if email.len() > 254
        || local.is_empty()
        || domain.is_empty()
        || parts.next().is_some()
        || !domain.contains('.')
        || email.chars().any(char::is_whitespace)
    {
        return Err(AuthError::InvalidParams("email is invalid".to_owned()));
    }
    Ok(email)
}

fn validate_name(kind: &str, value: &str) -> Result<(), AuthError> {
    if value.trim().is_empty() || value.len() > 128 {
        return Err(AuthError::InvalidParams(format!("invalid {kind} name")));
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_lowercase())
        && chars.all(|c| c == '_' || c.is_ascii_lowercase() || c.is_ascii_digit())
}

fn cassandra_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::Cassandra(error.to_string())
}
