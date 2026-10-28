use crate::profile_values::parse_profile;
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
use chrono::Utc;
use serde_json::Value;
use sqlx::{
    AnyPool, Row,
    any::{AnyPoolOptions, install_default_drivers},
};
use std::{
    collections::HashMap,
    sync::{Arc, Once, RwLock},
};
use tokio::sync::OnceCell;
use url::Url;

static INSTALL_DRIVERS: Once = Once::new();

macro_rules! with_sql {
    ($server:expr, $statement:expr, $builder:path, $query:ident => $body:expr) => {{
        let statement = $server.sql_statement($statement);
        let $query = $builder(&statement);
        $body.await
    }};
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SqlDatabase {
    PostgreSql,
    MySql,
    Sqlite,
}

impl SqlDatabase {
    fn scheme(self) -> &'static str {
        match self {
            Self::PostgreSql => "postgres",
            Self::MySql => "mysql",
            Self::Sqlite => "sqlite",
        }
    }

    fn is_mysql(self) -> bool {
        matches!(self, Self::MySql)
    }
}

struct Inner {
    database_kind: SqlDatabase,
    config: RwLock<DbConfig>,
    profile_schema: RwLock<HashMap<String, ProfileFieldType>>,
    pool: OnceCell<AnyPool>,
    tokens: TokenService,
}

/// Shared SQLx implementation for PostgreSQL and MySQL.
///
/// Profile values are validated and serialized as typed JSON in the
/// `user_profiles` table, while user and RBAC relationships remain normalized.
#[derive(Clone)]
pub struct SqlxAuthServer {
    inner: Arc<Inner>,
}

impl SqlxAuthServer {
    pub fn new(
        database_kind: SqlDatabase,
        paserk_key: &str,
        token_config: TokenConfig,
    ) -> Result<Self, AuthError> {
        Ok(Self {
            inner: Arc::new(Inner {
                database_kind,
                config: RwLock::new(DbConfig::default()),
                profile_schema: RwLock::new(HashMap::new()),
                pool: OnceCell::new(),
                tokens: TokenService::new(paserk_key, token_config)?,
            }),
        })
    }

    pub fn set_profile_schema(
        &mut self,
        schema: HashMap<String, ProfileFieldType>,
    ) -> Result<(), AuthError> {
        validate_schema(&schema)?;
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

    fn pool(&self) -> Result<&AnyPool, AuthError> {
        self.inner
            .pool
            .get()
            .ok_or(AuthError::StorageNotInitialized)
    }

    fn duplicate_insert_prefix(&self) -> &'static str {
        if self.inner.database_kind.is_mysql() {
            "INSERT IGNORE "
        } else {
            "INSERT "
        }
    }

    fn conflict_suffix(&self) -> &'static str {
        if self.inner.database_kind.is_mysql() {
            ""
        } else {
            " ON CONFLICT DO NOTHING"
        }
    }

    fn sql_statement(&self, statement: &str) -> String {
        if self.inner.database_kind != SqlDatabase::PostgreSql {
            return statement.to_owned();
        }
        let mut parameter = 0;
        statement
            .chars()
            .map(|character| {
                if character == '?' {
                    parameter += 1;
                    format!("${parameter}")
                } else {
                    character.to_string()
                }
            })
            .collect()
    }

    async fn permissions_for_roles(&self, roles: &[String]) -> Result<Vec<String>, AuthError> {
        if roles.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = (1..=roles.len())
            .map(|index| {
                if self.inner.database_kind == SqlDatabase::PostgreSql {
                    format!("${index}")
                } else {
                    "?".to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        let statement = format!(
            "SELECT DISTINCT permission_name FROM role_permissions WHERE role_name IN ({placeholders}) ORDER BY permission_name"
        );
        let rows = with_sql!(self, &statement, sqlx::query, query => {
            let mut query = query;
            for role in roles {
                query = query.bind(role);
            }
            query.fetch_all(self.pool()?)
        })?;
        rows.iter()
            .map(|row| row.try_get("permission_name").map_err(AuthError::from))
            .collect()
    }

    async fn roles_for_user(&self, user_id: &str) -> Result<Vec<String>, AuthError> {
        let rows = with_sql!(
            self,
            "SELECT role_name FROM user_roles WHERE user_id = ? ORDER BY role_name",
            sqlx::query,
            query => query.bind(user_id).fetch_all(self.pool()?)
        )?;
        rows.iter()
            .map(|row| row.try_get("role_name").map_err(AuthError::from))
            .collect()
    }

    async fn load_user(&self, user_id: &str) -> Result<UserResponse, AuthError> {
        let row = with_sql!(
            self,
            "SELECT id, email, created_at FROM users WHERE id = ?",
            sqlx::query,
            query => query.bind(user_id).fetch_optional(self.pool()?)
        )?
        .ok_or_else(|| AuthError::InvalidParams("user not found".to_owned()))?;
        let id: String = row.try_get("id")?;
        let profile_json = with_sql!(
            self,
            "SELECT profile_json FROM user_profiles WHERE user_id = ?",
            sqlx::query_scalar::<_, String>,
            query => query.bind(&id).fetch_optional(self.pool()?)
        )?;
        let profile = match profile_json {
            Some(json) => serde_json::from_str(&json)?,
            None => HashMap::new(),
        };
        Ok(UserResponse {
            id: id.clone(),
            email: row.try_get("email")?,
            created_at: row.try_get("created_at")?,
            roles: self.roles_for_user(&id).await?,
            profile,
        })
    }
}

#[async_trait]
impl JsonRpcAuthServer for SqlxAuthServer {
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
        if self.inner.pool.get().is_some() {
            return Ok(());
        }
        let config = self.config();
        let uri = make_uri(self.inner.database_kind, &config)?;
        INSTALL_DRIVERS.call_once(install_default_drivers);
        let max_connections = if self.inner.database_kind == SqlDatabase::Sqlite
            && (config.host == ":memory:" || config.host == "sqlite::memory:")
        {
            1
        } else {
            8
        };
        let pool = AnyPoolOptions::new()
            .max_connections(max_connections)
            .connect(uri.as_str())
            .await?;
        for statement in [
            "CREATE TABLE IF NOT EXISTS users (id VARCHAR(36) PRIMARY KEY NOT NULL, email VARCHAR(254) NOT NULL UNIQUE, password_hash VARCHAR(255) NOT NULL, created_at VARCHAR(40) NOT NULL)",
            "CREATE TABLE IF NOT EXISTS roles (name VARCHAR(128) PRIMARY KEY NOT NULL)",
            "CREATE TABLE IF NOT EXISTS user_roles (user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE, role_name VARCHAR(128) NOT NULL REFERENCES roles(name) ON DELETE CASCADE, PRIMARY KEY (user_id, role_name))",
            "CREATE TABLE IF NOT EXISTS role_permissions (role_name VARCHAR(128) NOT NULL REFERENCES roles(name) ON DELETE CASCADE, permission_name VARCHAR(128) NOT NULL, PRIMARY KEY (role_name, permission_name))",
            "CREATE TABLE IF NOT EXISTS user_profiles (user_id VARCHAR(36) PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE, profile_json VARCHAR(16000) NOT NULL)",
            "CREATE TABLE IF NOT EXISTS external_identities (provider VARCHAR(64) NOT NULL, subject VARCHAR(512) NOT NULL, user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY (provider, subject))",
        ] {
            sqlx::query(statement).execute(&pool).await?;
        }
        let _ = self.inner.pool.set(pool);
        Ok(())
    }

    fn authenticate_access_token(&self, token: &str) -> Result<AccessTokenClaims, AuthError> {
        SqlxAuthServer::authenticate_access_token(self, token)
    }

    fn require_permission(
        &self,
        token: &str,
        permission: &str,
    ) -> Result<AccessTokenClaims, AuthError> {
        SqlxAuthServer::require_permission(self, token, permission)
    }

    async fn handle_refresh(
        &self,
        refresh_token: &str,
    ) -> Result<TokenResponse, Self::StorageError> {
        let subject = self.inner.tokens.verify_refresh_token(refresh_token)?;
        let row = with_sql!(
            self,
            "SELECT id FROM users WHERE id = ?",
            sqlx::query,
            query => query.bind(&subject).fetch_optional(self.pool()?)
        )?
        .ok_or(AuthError::Unauthorized)?;
        let id: String = row.try_get("id")?;
        let roles = self.roles_for_user(&id).await?;
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
        let profile = parse_profile(&self.schema(), &req.profile)?;
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(req.password.as_bytes(), &salt)
            .map_err(|error| AuthError::PasswordHash(error.to_string()))?
            .to_string();
        let id = uuid::Uuid::new_v4().to_string();
        let created_at = Utc::now().to_rfc3339();
        let mut transaction = self.pool()?.begin().await?;
        let result = with_sql!(
            self,
            "INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            sqlx::query,
            query => query
                .bind(&id)
                .bind(email)
                .bind(password_hash)
                .bind(created_at)
                .execute(&mut *transaction)
        );
        if let Err(error) = result {
            if is_unique_violation(&error) {
                return Err(AuthError::DuplicateEmail);
            }
            return Err(error.into());
        }
        if self.inner.database_kind.is_mysql()
            && result
                .as_ref()
                .is_ok_and(|result| result.rows_affected() == 0)
        {
            return Err(AuthError::DuplicateEmail);
        }
        let profile = serde_json::to_string(&profile)?;
        with_sql!(
            self,
            "INSERT INTO user_profiles (user_id, profile_json) VALUES (?, ?)",
            sqlx::query,
            query => query
                .bind(&id)
                .bind(profile)
                .execute(&mut *transaction)
        )?;
        transaction.commit().await?;
        self.load_user(&id).await
    }

    async fn handle_login(&self, req: LoginRequest) -> Result<TokenResponse, Self::StorageError> {
        if req.grant_type != "password" {
            return Err(AuthError::InvalidParams(
                "grant_type must be `password`".to_owned(),
            ));
        }
        let email = normalize_email(&req.email)?;
        let user = with_sql!(
            self,
            "SELECT id, password_hash FROM users WHERE email = ?",
            sqlx::query,
            query => query.bind(email).fetch_optional(self.pool()?)
        )?
        .ok_or(AuthError::Unauthorized)?;
        let id: String = user.try_get("id")?;
        let stored_hash: String = user.try_get("password_hash")?;
        let parsed_hash = PasswordHash::new(&stored_hash).map_err(|_| AuthError::Unauthorized)?;
        Argon2::default()
            .verify_password(req.password.as_bytes(), &parsed_hash)
            .map_err(|_| AuthError::Unauthorized)?;
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
        let existing = with_sql!(
            self,
            "SELECT user_id FROM external_identities WHERE provider = ? AND subject = ?",
            sqlx::query_scalar::<_, String>,
            query => query.bind(provider).bind(&identity.subject).fetch_optional(self.pool()?)
        )?;
        let user_id = if let Some(user_id) = existing {
            user_id
        } else {
            if !identity.email_verified {
                return Err(AuthError::Unauthorized);
            }
            let email = identity
                .email
                .as_deref()
                .ok_or(AuthError::Unauthorized)
                .and_then(normalize_email)?;
            let mut transaction = self.pool()?.begin().await?;
            let email_exists = with_sql!(
                self,
                "SELECT id FROM users WHERE email = ?",
                sqlx::query_scalar::<_, String>,
                query => query.bind(&email).fetch_optional(&mut *transaction)
            )?;
            if email_exists.is_some() {
                return Err(AuthError::AccountLinkRequired);
            }
            let user_id = uuid::Uuid::new_v4().to_string();
            let created_at = Utc::now().to_rfc3339();
            let random_password = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
            let salt = SaltString::generate(&mut OsRng);
            let password_hash = Argon2::default()
                .hash_password(random_password.as_bytes(), &salt)
                .map_err(|error| AuthError::PasswordHash(error.to_string()))?
                .to_string();
            let insert_user = with_sql!(
                self,
                "INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                sqlx::query,
                query => query
                    .bind(&user_id)
                    .bind(&email)
                    .bind(password_hash)
                    .bind(created_at)
                    .execute(&mut *transaction)
            );
            if let Err(error) = insert_user {
                if is_unique_violation(&error) {
                    return Err(AuthError::AccountLinkRequired);
                }
                return Err(error.into());
            }
            with_sql!(
                self,
                "INSERT INTO user_profiles (user_id, profile_json) VALUES (?, ?)",
                sqlx::query,
                query => query
                    .bind(&user_id)
                    .bind("{}")
                    .execute(&mut *transaction)
            )?;
            let result = with_sql!(
                self,
                "INSERT INTO external_identities (provider, subject, user_id) VALUES (?, ?, ?)",
                sqlx::query,
                query => query
                    .bind(provider)
                    .bind(&identity.subject)
                    .bind(&user_id)
                    .execute(&mut *transaction)
            );
            if let Err(error) = result {
                if is_unique_violation(&error) {
                    return Err(AuthError::Unauthorized);
                }
                return Err(error.into());
            }
            transaction.commit().await?;
            user_id
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
        let exists = with_sql!(
            self,
            "SELECT id FROM users WHERE id = ?",
            sqlx::query_scalar::<_, String>,
            query => query.bind(&user_id).fetch_optional(self.pool()?)
        )?;
        if exists.is_none() {
            return Err(AuthError::InvalidParams("user not found".to_owned()));
        }
        let result = with_sql!(
            self,
            "INSERT INTO external_identities (provider, subject, user_id) VALUES (?, ?, ?)",
            sqlx::query,
            query => query
                .bind(identity.provider.storage_key())
                .bind(identity.subject)
                .bind(&user_id)
                .execute(self.pool()?)
        );
        match result {
            Ok(_) => Ok(()),
            Err(error) if is_unique_violation(&error) => Err(AuthError::AccountLinkRequired),
            Err(error) => Err(error.into()),
        }
    }

    async fn handle_update_profile(
        &self,
        user_id: String,
        profile_data: HashMap<String, String>,
    ) -> Result<UserResponse, Self::StorageError> {
        let updates = parse_profile(&self.schema(), &profile_data)?;
        let mut transaction = self.pool()?.begin().await?;
        let existing: Option<String> = with_sql!(
            self,
            "SELECT profile_json FROM user_profiles WHERE user_id = ?",
            sqlx::query_scalar,
            query => query.bind(&user_id).fetch_optional(&mut *transaction)
        )?;
        let Some(existing) = existing else {
            return Err(AuthError::InvalidParams("user not found".to_owned()));
        };
        let mut profile: HashMap<String, Value> = serde_json::from_str(&existing)?;
        profile.extend(updates);
        with_sql!(
            self,
            "UPDATE user_profiles SET profile_json = ? WHERE user_id = ?",
            sqlx::query,
            query => query
                .bind(serde_json::to_string(&profile)?)
                .bind(&user_id)
                .execute(&mut *transaction)
        )?;
        transaction.commit().await?;
        self.load_user(&user_id).await
    }

    async fn handle_add_role(
        &self,
        user_id: String,
        role_name: String,
    ) -> Result<(), Self::StorageError> {
        validate_name("role", &role_name)?;
        let mut transaction = self.pool()?.begin().await?;
        let insert_role = format!(
            "{}INTO roles (name) VALUES (?){}",
            self.duplicate_insert_prefix(),
            self.conflict_suffix()
        );
        with_sql!(self, &insert_role, sqlx::query, query => {
            query.bind(&role_name).execute(&mut *transaction)
        })?;
        let insert_assignment = format!(
            "{}INTO user_roles (user_id, role_name) VALUES (?, ?){}",
            self.duplicate_insert_prefix(),
            self.conflict_suffix()
        );
        with_sql!(self, &insert_assignment, sqlx::query, query => {
            query.bind(&user_id).bind(&role_name).execute(&mut *transaction)
        })?;
        let user_exists: i64 = with_sql!(
            self,
            "SELECT COUNT(*) FROM users WHERE id = ?",
            sqlx::query_scalar,
            query => query.bind(&user_id).fetch_one(&mut *transaction)
        )?;
        if user_exists == 0 {
            return Err(AuthError::InvalidParams("user not found".to_owned()));
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn handle_remove_role(
        &self,
        user_id: String,
        role_name: String,
    ) -> Result<(), Self::StorageError> {
        let result = with_sql!(
            self,
            "DELETE FROM user_roles WHERE user_id = ? AND role_name = ?",
            sqlx::query,
            query => query.bind(user_id).bind(role_name).execute(self.pool()?)
        )?;
        if result.rows_affected() == 0 {
            return Err(AuthError::InvalidParams(
                "user role assignment not found".to_owned(),
            ));
        }
        Ok(())
    }

    async fn handle_add_permission(
        &self,
        role_name: String,
        permission_name: String,
    ) -> Result<(), Self::StorageError> {
        validate_name("role", &role_name)?;
        validate_name("permission", &permission_name)?;
        let mut transaction = self.pool()?.begin().await?;
        let insert_role = format!(
            "{}INTO roles (name) VALUES (?){}",
            self.duplicate_insert_prefix(),
            self.conflict_suffix()
        );
        with_sql!(self, &insert_role, sqlx::query, query => {
            query.bind(&role_name).execute(&mut *transaction)
        })?;
        let insert_permission = format!(
            "{}INTO role_permissions (role_name, permission_name) VALUES (?, ?){}",
            self.duplicate_insert_prefix(),
            self.conflict_suffix()
        );
        with_sql!(self, &insert_permission, sqlx::query, query => {
            query
                .bind(&role_name)
                .bind(&permission_name)
                .execute(&mut *transaction)
        })?;
        transaction.commit().await?;
        Ok(())
    }

    async fn handle_remove_permission(
        &self,
        role_name: String,
        permission_name: String,
    ) -> Result<(), Self::StorageError> {
        let result = with_sql!(
            self,
            "DELETE FROM role_permissions WHERE role_name = ? AND permission_name = ?",
            sqlx::query,
            query => query.bind(role_name).bind(permission_name).execute(self.pool()?)
        )?;
        if result.rows_affected() == 0 {
            return Err(AuthError::InvalidParams(
                "role permission assignment not found".to_owned(),
            ));
        }
        Ok(())
    }
}

fn make_uri(database: SqlDatabase, config: &DbConfig) -> Result<String, AuthError> {
    let host = config.host.trim();
    if host.is_empty() {
        return Err(AuthError::InvalidConfiguration(
            "database host/URL is required".to_owned(),
        ));
    }
    let uri = if host.starts_with("sqlite:") && database == SqlDatabase::Sqlite {
        Url::parse(host).map_err(|error| AuthError::InvalidConfiguration(error.to_string()))?
    } else if host.contains("://") {
        Url::parse(host).map_err(|error| AuthError::InvalidConfiguration(error.to_string()))?
    } else {
        let database_name = config.database_name.trim();
        if database_name.is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "database name is required when host is not a full URL".to_owned(),
            ));
        }
        Url::parse(&format!(
            "{}://{}/{}",
            database.scheme(),
            host,
            database_name
        ))
        .map_err(|error| AuthError::InvalidConfiguration(error.to_string()))?
    };
    if uri.scheme() != database.scheme()
        && !(database == SqlDatabase::PostgreSql && uri.scheme() == "postgresql")
    {
        return Err(AuthError::InvalidConfiguration(format!(
            "URL scheme `{}` does not match selected SQL backend",
            uri.scheme()
        )));
    }
    let mut uri = uri;
    if let Some(user) = &config.db_user {
        uri.set_username(user)
            .map_err(|_| AuthError::InvalidConfiguration("invalid database username".to_owned()))?;
    }
    if let Some(password) = &config.db_password {
        uri.set_password(Some(password))
            .map_err(|_| AuthError::InvalidConfiguration("invalid database password".to_owned()))?;
    }
    if uri.path() == "/" && !config.database_name.trim().is_empty() {
        uri.set_path(config.database_name.trim());
    }
    Ok(uri.to_string())
}

fn validate_schema(schema: &HashMap<String, ProfileFieldType>) -> Result<(), AuthError> {
    for name in schema.keys() {
        if !valid_identifier(name) {
            return Err(AuthError::InvalidConfiguration(format!(
                "invalid profile field name `{name}`"
            )));
        }
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
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

fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|db_error| db_error.is_unique_violation())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pasetors::{
        keys::{Generate, SymmetricKey},
        paserk::FormatAsPaserk,
        version4::V4,
    };

    #[test]
    fn database_urls_preserve_escaped_credentials_and_validate_engine() {
        let config = DbConfig {
            host: "db.example:5432".to_owned(),
            database_name: "auth db".to_owned(),
            db_user: Some("auth user".to_owned()),
            db_password: Some("p@ss/word".to_owned()),
        };
        let uri = make_uri(SqlDatabase::PostgreSql, &config).unwrap();
        let parsed = Url::parse(&uri).unwrap();
        assert_eq!(parsed.scheme(), "postgres");
        assert_eq!(parsed.username(), "auth%20user");
        assert_eq!(parsed.password(), Some("p%40ss%2Fword"));
        assert_eq!(parsed.path(), "/auth%20db");
        assert!(
            make_uri(
                SqlDatabase::MySql,
                &DbConfig {
                    host: "postgres://localhost/db".to_owned(),
                    ..DbConfig::default()
                }
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn sqlx_backend_workflows_run_on_sqlite_any_driver() {
        let key = SymmetricKey::<V4>::generate().unwrap();
        let mut paserk = String::new();
        key.fmt(&mut paserk).unwrap();
        let mut server =
            SqlxAuthServer::new(SqlDatabase::Sqlite, &paserk, TokenConfig::new("any-test"))
                .unwrap();
        server.set_db_host("sqlite::memory:");
        server
            .set_profile_schema(HashMap::from([
                ("joined_at".to_owned(), ProfileFieldType::DateTime),
                ("avatar".to_owned(), ProfileFieldType::Blob),
            ]))
            .unwrap();
        server.initialize_storage().await.unwrap();

        let user = server
            .handle_register(RegisterRequest {
                email: "any@example.test".to_owned(),
                password: "a long secure password".to_owned(),
                profile: HashMap::from([
                    ("joined_at".to_owned(), "2024-01-02T03:04:05Z".to_owned()),
                    ("avatar".to_owned(), "AQID".to_owned()),
                ]),
            })
            .await
            .unwrap();
        assert_eq!(user.profile["avatar"], "AQID");
        server
            .handle_add_role(user.id.clone(), "reader".to_owned())
            .await
            .unwrap();
        server
            .handle_add_permission("reader".to_owned(), "profile.read".to_owned())
            .await
            .unwrap();
        let tokens = server
            .handle_login(LoginRequest {
                email: "any@example.test".to_owned(),
                password: "a long secure password".to_owned(),
                grant_type: "password".to_owned(),
            })
            .await
            .unwrap();
        assert!(
            server
                .require_permission(&tokens.access_token, "profile.read")
                .is_ok()
        );
        let updated = server
            .handle_update_profile(
                user.id,
                HashMap::from([("joined_at".to_owned(), "2025-02-03T04:05:06Z".to_owned())]),
            )
            .await
            .unwrap();
        assert_eq!(updated.profile["joined_at"], "2025-02-03T04:05:06+00:00");
    }
}
