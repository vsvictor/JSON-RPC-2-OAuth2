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
use oracle_rs::{Connection, Value as OracleValue};
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tokio::sync::{Mutex, OnceCell};

struct Inner {
    config: RwLock<DbConfig>,
    profile_schema: RwLock<HashMap<String, ProfileFieldType>>,
    connection: OnceCell<Arc<Mutex<Connection>>>,
    tokens: TokenService,
}

/// Oracle Database implementation of the shared authentication and RBAC contract.
#[derive(Clone)]
pub struct OracleAuthServer {
    inner: Arc<Inner>,
}

impl OracleAuthServer {
    /// Create an Oracle authentication service using a PASERK-encoded v4.local key.
    pub fn new(paserk_key: &str, token_config: TokenConfig) -> Result<Self, AuthError> {
        Ok(Self {
            inner: Arc::new(Inner {
                config: RwLock::new(DbConfig::default()),
                profile_schema: RwLock::new(HashMap::new()),
                connection: OnceCell::new(),
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

    fn connection(&self) -> Result<Arc<Mutex<Connection>>, AuthError> {
        self.inner
            .connection
            .get()
            .cloned()
            .ok_or(AuthError::StorageNotInitialized)
    }

    async fn roles_for_user(&self, user_id: &str) -> Result<Vec<String>, AuthError> {
        let connection = self.connection()?;
        let connection = connection.lock().await;
        let result = connection
            .query(
                "SELECT role_name FROM user_roles WHERE user_id = :1 ORDER BY role_name",
                &[user_id.into()],
            )
            .await
            .map_err(oracle_error)?;
        result.rows.iter().map(|row| row_string(row, 0)).collect()
    }

    async fn permissions_for_roles(&self, roles: &[String]) -> Result<Vec<String>, AuthError> {
        if roles.is_empty() {
            return Ok(Vec::new());
        }
        let connection = self.connection()?;
        let connection = connection.lock().await;
        let mut permissions = Vec::new();
        for role in roles {
            let result = connection
                .query(
                    "SELECT permission_name FROM role_permissions WHERE role_name = :1 ORDER BY permission_name",
                    &[role.as_str().into()],
                )
                .await
                .map_err(oracle_error)?;
            permissions.extend(
                result
                    .rows
                    .iter()
                    .map(|row| row_string(row, 0))
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        permissions.sort();
        permissions.dedup();
        Ok(permissions)
    }

    async fn load_user(&self, user_id: &str) -> Result<UserResponse, AuthError> {
        let connection = self.connection()?;
        let (id, email, created_at, profile) = {
            let connection = connection.lock().await;
            let result = connection
                .query(
                    "SELECT id, email, created_at FROM users WHERE id = :1",
                    &[user_id.into()],
                )
                .await
                .map_err(oracle_error)?;
            let row = result
                .rows
                .first()
                .ok_or_else(|| AuthError::InvalidParams("user not found".to_owned()))?;
            let id = row_string(row, 0)?;
            let email = row_string(row, 1)?;
            let created_at = row_string(row, 2)?;

            let profile_result = connection
                .query(
                    "SELECT profile_json FROM user_profiles WHERE user_id = :1",
                    &[id.as_str().into()],
                )
                .await
                .map_err(oracle_error)?;
            let profile = match profile_result.rows.first() {
                Some(row) => {
                    let json = row_lob_string(&connection, row, 0).await?;
                    serde_json::from_str(&json)?
                }
                None => HashMap::new(),
            };
            (id, email, created_at, profile)
        };
        Ok(UserResponse {
            id: id.clone(),
            email,
            created_at,
            roles: self.roles_for_user(&id).await?,
            profile,
        })
    }
}

#[async_trait]
impl JsonRpcAuthServer for OracleAuthServer {
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
        if self.inner.connection.get().is_some() {
            return Ok(());
        }
        let config = self.config();
        let host = config.host.trim();
        if host.is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "Oracle host is required".to_owned(),
            ));
        }
        let username = config.db_user.as_deref().ok_or_else(|| {
            AuthError::InvalidConfiguration("Oracle database user is required".to_owned())
        })?;
        let password = config.db_password.as_deref().ok_or_else(|| {
            AuthError::InvalidConfiguration("Oracle database password is required".to_owned())
        })?;
        let connect_string = make_connect_string(host, &config.database_name)?;
        let connection = Connection::connect(&connect_string, username, password)
            .await
            .map_err(oracle_error)?;
        let connection = Arc::new(Mutex::new(connection));
        {
            let connection = connection.lock().await;
            for statement in [
                "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE users (id VARCHAR2(36) PRIMARY KEY NOT NULL, email VARCHAR2(254) NOT NULL UNIQUE, password_hash VARCHAR2(255) NOT NULL, created_at VARCHAR2(40) NOT NULL)'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
                "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE roles (name VARCHAR2(128) PRIMARY KEY NOT NULL)'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
                "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE user_roles (user_id VARCHAR2(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE, role_name VARCHAR2(128) NOT NULL REFERENCES roles(name) ON DELETE CASCADE, PRIMARY KEY (user_id, role_name))'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
                "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE role_permissions (role_name VARCHAR2(128) NOT NULL REFERENCES roles(name) ON DELETE CASCADE, permission_name VARCHAR2(128) NOT NULL, PRIMARY KEY (role_name, permission_name))'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
                "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE user_profiles (user_id VARCHAR2(36) PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE, profile_json CLOB NOT NULL)'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
                "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE external_identities (provider VARCHAR2(64) NOT NULL, subject VARCHAR2(512) NOT NULL, user_id VARCHAR2(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE, CONSTRAINT PK_AUTH_EXTERNAL_IDS PRIMARY KEY (provider, subject))'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;",
            ] {
                connection
                    .execute_dml_sql(statement, &[])
                    .await
                    .map_err(oracle_error)?;
            }
            connection.commit().await.map_err(oracle_error)?;
        }
        let _ = self.inner.connection.set(connection);
        Ok(())
    }

    fn authenticate_access_token(&self, token: &str) -> Result<AccessTokenClaims, AuthError> {
        OracleAuthServer::authenticate_access_token(self, token)
    }

    fn require_permission(
        &self,
        token: &str,
        permission: &str,
    ) -> Result<AccessTokenClaims, AuthError> {
        OracleAuthServer::require_permission(self, token, permission)
    }

    async fn handle_refresh(
        &self,
        refresh_token: &str,
    ) -> Result<TokenResponse, Self::StorageError> {
        let subject = self.inner.tokens.verify_refresh_token(refresh_token)?;
        let connection = self.connection()?;
        let connection = connection.lock().await;
        let result = connection
            .query(
                "SELECT id FROM users WHERE id = :1",
                &[subject.as_str().into()],
            )
            .await
            .map_err(oracle_error)?;
        if result.rows.is_empty() {
            return Err(AuthError::Unauthorized);
        }
        drop(connection);
        let roles = self.roles_for_user(&subject).await?;
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
        let id = uuid::Uuid::new_v4().to_string();
        let created_at = chrono::Utc::now().to_rfc3339();
        let connection = self.connection()?;
        let connection = connection.lock().await;
        let result = async {
            connection
                .execute_dml_sql(
                    "INSERT INTO users (id, email, password_hash, created_at) VALUES (:1, :2, :3, :4)",
                    &[
                        id.as_str().into(),
                        email.as_str().into(),
                        password_hash.as_str().into(),
                        created_at.as_str().into(),
                    ],
                )
                .await
                .map_err(oracle_error)?;
            connection
                .execute_dml_sql(
                    "INSERT INTO user_profiles (user_id, profile_json) VALUES (:1, :2)",
                    &[id.as_str().into(), profile_json.into()],
                )
                .await
                .map_err(oracle_error)?;
            connection.commit().await.map_err(oracle_error)?;
            Ok::<(), AuthError>(())
        }
        .await;
        if let Err(error) = result {
            let _ = connection.rollback().await;
            if is_duplicate_email(&error) {
                return Err(AuthError::DuplicateEmail);
            }
            return Err(error);
        }
        drop(connection);
        self.load_user(&id).await
    }

    async fn handle_login(&self, req: LoginRequest) -> Result<TokenResponse, Self::StorageError> {
        if req.grant_type != "password" {
            return Err(AuthError::InvalidParams(
                "grant_type must be `password`".to_owned(),
            ));
        }
        let email = normalize_email(&req.email)?;
        let connection = self.connection()?;
        let connection = connection.lock().await;
        let result = connection
            .query(
                "SELECT id, password_hash FROM users WHERE email = :1",
                &[email.as_str().into()],
            )
            .await
            .map_err(oracle_error)?;
        let row = result.rows.first().ok_or(AuthError::Unauthorized)?;
        let id = row_string(row, 0)?;
        let stored_hash = row_string(row, 1)?;
        let parsed_hash = PasswordHash::new(&stored_hash).map_err(|_| AuthError::Unauthorized)?;
        Argon2::default()
            .verify_password(req.password.as_bytes(), &parsed_hash)
            .map_err(|_| AuthError::Unauthorized)?;
        drop(connection);
        let roles = self.roles_for_user(&id).await?;
        let permissions = self.permissions_for_roles(&roles).await?;
        self.inner.tokens.issue_pair(&id, &roles, &permissions)
    }

    async fn handle_external_login(
        &self,
        identity: ExternalIdentity,
    ) -> Result<TokenResponse, AuthError> {
        if identity.subject.trim().is_empty() {
            return Err(AuthError::Unauthorized);
        }
        let provider = identity.provider.storage_key();
        let connection = self.connection()?;
        let connection = connection.lock().await;
        let rows = connection
            .query(
                "SELECT user_id FROM external_identities WHERE provider = :1 AND subject = :2",
                &[provider.into(), identity.subject.as_str().into()],
            )
            .await
            .map_err(oracle_error)?;
        let linked_id = rows
            .rows
            .first()
            .map(|row| row_string(row, 0))
            .transpose()?;
        drop(connection);
        let user_id = if let Some(user_id) = linked_id {
            user_id
        } else {
            if !identity.email_verified {
                return Err(AuthError::Unauthorized);
            }
            let email = identity.email.ok_or(AuthError::Unauthorized)?;
            let user = match self
                .handle_register(RegisterRequest {
                    email: email.clone(),
                    password: format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4()),
                    profile: HashMap::new(),
                })
                .await
            {
                Ok(user) => user,
                Err(AuthError::DuplicateEmail) => return Err(AuthError::AccountLinkRequired),
                Err(error) => return Err(error),
            };
            let connection = self.connection()?;
            let connection = connection.lock().await;
            if let Err(error) = connection
                .execute_dml_sql(
                    "INSERT INTO external_identities (provider, subject, user_id) VALUES (:1, :2, :3)",
                    &[provider.into(), identity.subject.as_str().into(), user.id.as_str().into()],
                )
                .await
            {
                let _ = connection
                    .execute_dml_sql(
                        "DELETE FROM users WHERE id = :1",
                        &[user.id.as_str().into()],
                    )
                    .await;
                let message = error.to_string();
                if message.contains("ORA-00001") {
                    return Err(AuthError::Unauthorized);
                }
                return Err(oracle_error(error));
            }
            connection.commit().await.map_err(oracle_error)?;
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
        let connection = self.connection()?;
        let connection = connection.lock().await;
        let user = connection
            .query(
                "SELECT id FROM users WHERE id = :1",
                &[user_id.as_str().into()],
            )
            .await
            .map_err(oracle_error)?;
        if user.rows.is_empty() {
            return Err(AuthError::InvalidParams("user not found".to_owned()));
        }
        let provider = identity.provider.storage_key();
        connection
            .execute_dml_sql(
                "INSERT INTO external_identities (provider, subject, user_id) VALUES (:1, :2, :3)",
                &[
                    provider.into(),
                    identity.subject.as_str().into(),
                    user_id.as_str().into(),
                ],
            )
            .await
            .map_err(|error| {
                if error.to_string().contains("ORA-00001") {
                    AuthError::AccountLinkRequired
                } else {
                    oracle_error(error)
                }
            })?;
        connection.commit().await.map_err(oracle_error)
    }

    async fn handle_update_profile(
        &self,
        user_id: String,
        profile_data: HashMap<String, String>,
    ) -> Result<UserResponse, Self::StorageError> {
        let updates = crate::profile_values::parse_profile(&self.schema(), &profile_data)?;
        let connection = self.connection()?;
        let connection = connection.lock().await;
        let result = connection
            .query(
                "SELECT profile_json FROM user_profiles WHERE user_id = :1",
                &[user_id.as_str().into()],
            )
            .await
            .map_err(oracle_error)?;
        let row = result
            .rows
            .first()
            .ok_or_else(|| AuthError::InvalidParams("user not found".to_owned()))?;
        let existing = row_lob_string(&connection, row, 0).await?;
        let mut profile: HashMap<String, Value> = serde_json::from_str(&existing)?;
        profile.extend(updates);
        let updated_json = serde_json::to_string(&profile)?;
        connection
            .execute_dml_sql(
                "UPDATE user_profiles SET profile_json = :1 WHERE user_id = :2",
                &[updated_json.into(), user_id.as_str().into()],
            )
            .await
            .map_err(oracle_error)?;
        connection.commit().await.map_err(oracle_error)?;
        drop(connection);
        self.load_user(&user_id).await
    }

    async fn handle_add_role(
        &self,
        user_id: String,
        role_name: String,
    ) -> Result<(), Self::StorageError> {
        validate_name("role", &role_name)?;
        let connection = self.connection()?;
        let connection = connection.lock().await;
        let result = async {
            let user = connection
                .query(
                    "SELECT id FROM users WHERE id = :1",
                    &[user_id.as_str().into()],
                )
                .await
                .map_err(oracle_error)?;
            if user.rows.is_empty() {
                return Err(AuthError::InvalidParams("user not found".to_owned()));
            }
            connection
                .execute_dml_sql(
                    "MERGE INTO roles target USING (SELECT :1 name FROM dual) source ON (target.name = source.name) WHEN NOT MATCHED THEN INSERT (name) VALUES (source.name)",
                    &[role_name.as_str().into()],
                )
                .await
                .map_err(oracle_error)?;
            connection
                .execute_dml_sql(
                    "MERGE INTO user_roles target USING (SELECT :1 user_id, :2 role_name FROM dual) source ON (target.user_id = source.user_id AND target.role_name = source.role_name) WHEN NOT MATCHED THEN INSERT (user_id, role_name) VALUES (source.user_id, source.role_name)",
                    &[user_id.as_str().into(), role_name.as_str().into()],
                )
                .await
                .map_err(oracle_error)?;
            connection.commit().await.map_err(oracle_error)
        }
        .await;
        if result.is_err() {
            let _ = connection.rollback().await;
        }
        result
    }

    async fn handle_remove_role(
        &self,
        user_id: String,
        role_name: String,
    ) -> Result<(), Self::StorageError> {
        let connection = self.connection()?;
        let connection = connection.lock().await;
        let result = connection
            .execute_dml_sql(
                "DELETE FROM user_roles WHERE user_id = :1 AND role_name = :2",
                &[user_id.as_str().into(), role_name.as_str().into()],
            )
            .await
            .map_err(oracle_error)?;
        if result == 0 {
            return Err(AuthError::InvalidParams(
                "user role assignment not found".to_owned(),
            ));
        }
        connection.commit().await.map_err(oracle_error)?;
        Ok(())
    }

    async fn handle_add_permission(
        &self,
        role_name: String,
        permission_name: String,
    ) -> Result<(), Self::StorageError> {
        validate_name("role", &role_name)?;
        validate_name("permission", &permission_name)?;
        let connection = self.connection()?;
        let connection = connection.lock().await;
        let result = async {
            connection
                .execute_dml_sql(
                    "MERGE INTO roles target USING (SELECT :1 name FROM dual) source ON (target.name = source.name) WHEN NOT MATCHED THEN INSERT (name) VALUES (source.name)",
                    &[role_name.as_str().into()],
                )
                .await
                .map_err(oracle_error)?;
            connection
                .execute_dml_sql(
                    "MERGE INTO role_permissions target USING (SELECT :1 role_name, :2 permission_name FROM dual) source ON (target.role_name = source.role_name AND target.permission_name = source.permission_name) WHEN NOT MATCHED THEN INSERT (role_name, permission_name) VALUES (source.role_name, source.permission_name)",
                    &[role_name.as_str().into(), permission_name.as_str().into()],
                )
                .await
                .map_err(oracle_error)?;
            connection.commit().await.map_err(oracle_error)
        }
        .await;
        if result.is_err() {
            let _ = connection.rollback().await;
        }
        result
    }

    async fn handle_remove_permission(
        &self,
        role_name: String,
        permission_name: String,
    ) -> Result<(), Self::StorageError> {
        let connection = self.connection()?;
        let connection = connection.lock().await;
        let result = connection
            .execute_dml_sql(
                "DELETE FROM role_permissions WHERE role_name = :1 AND permission_name = :2",
                &[role_name.as_str().into(), permission_name.as_str().into()],
            )
            .await
            .map_err(oracle_error)?;
        if result == 0 {
            return Err(AuthError::InvalidParams(
                "role permission assignment not found".to_owned(),
            ));
        }
        connection.commit().await.map_err(oracle_error)?;
        Ok(())
    }
}

fn make_connect_string(host: &str, database_name: &str) -> Result<String, AuthError> {
    let host = host.strip_prefix("oracle://").unwrap_or(host);
    if host.contains('/') {
        return Ok(host.to_owned());
    }
    let service = database_name.trim();
    if service.is_empty() {
        return Err(AuthError::InvalidConfiguration(
            "Oracle database_name (service name) is required when host has no service".to_owned(),
        ));
    }
    Ok(format!("{host}/{service}"))
}

fn row_string(row: &oracle_rs::Row, index: usize) -> Result<String, AuthError> {
    row.get(index)
        .and_then(OracleValue::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            AuthError::InvalidConfiguration(format!(
                "Oracle result column at index {index} is missing or not text"
            ))
        })
}

async fn row_lob_string(
    connection: &Connection,
    row: &oracle_rs::Row,
    index: usize,
) -> Result<String, AuthError> {
    match row.get(index) {
        Some(OracleValue::String(value)) => Ok(value.clone()),
        Some(OracleValue::Lob(lob)) => {
            if let Some(value) = lob.as_inline() {
                return Ok(String::from_utf8_lossy(value).into_owned());
            }
            if lob.is_empty() {
                return Ok(String::new());
            }
            let locator = lob.as_locator().ok_or_else(|| {
                AuthError::InvalidConfiguration(format!(
                    "Oracle CLOB column at index {index} could not be read"
                ))
            })?;
            connection.read_clob(locator).await.map_err(oracle_error)
        }
        _ => Err(AuthError::InvalidConfiguration(format!(
            "Oracle CLOB column at index {index} is missing or has an invalid type"
        ))),
    }
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
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn oracle_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::Oracle(error.to_string())
}

fn is_duplicate_email(error: &AuthError) -> bool {
    matches!(error, AuthError::Oracle(message) if message.contains("ORA-00001"))
}
