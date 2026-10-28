use crate::{
    AuthError, DbConfig, ExternalIdentity, JsonRpcAuthServer, LoginRequest, ProfileFieldType,
    RegisterRequest, TokenConfig, TokenResponse, UserResponse, token::TokenService,
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde_json::{Number, Value};
use sqlx::{
    QueryBuilder, Row, Sqlite, SqlitePool,
    sqlite::{SqlitePoolOptions, SqliteRow},
};
use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::{Arc, RwLock},
};
use tokio::sync::OnceCell;

struct Inner {
    config: RwLock<DbConfig>,
    profile_schema: RwLock<HashMap<String, ProfileFieldType>>,
    pool: OnceCell<SqlitePool>,
    tokens: TokenService,
}

/// SQLite implementation of the shared authentication and RBAC contract.
#[derive(Clone)]
pub struct SqliteAuthServer {
    inner: Arc<Inner>,
}

impl SqliteAuthServer {
    /// Create an SQLite authentication service using a PASERK-encoded v4.local key.
    pub fn new(paserk_key: &str, token_config: TokenConfig) -> Result<Self, AuthError> {
        Ok(Self {
            inner: Arc::new(Inner {
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
        validate_profile_schema(&schema)?;
        *self
            .inner
            .profile_schema
            .write()
            .expect("schema lock poisoned") = schema;
        Ok(())
    }

    pub fn authenticate_access_token(
        &self,
        token: &str,
    ) -> Result<crate::AccessTokenClaims, AuthError> {
        self.inner.tokens.verify_access_token(token)
    }

    pub fn require_permission(
        &self,
        token: &str,
        permission: &str,
    ) -> Result<crate::AccessTokenClaims, AuthError> {
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

    fn schema(&self) -> HashMap<String, ProfileFieldType> {
        self.inner
            .profile_schema
            .read()
            .expect("schema lock poisoned")
            .clone()
    }

    fn pool(&self) -> Result<&SqlitePool, AuthError> {
        self.inner
            .pool
            .get()
            .ok_or(AuthError::StorageNotInitialized)
    }

    async fn load_user(&self, id: &str) -> Result<UserResponse, AuthError> {
        let row = sqlx::query("SELECT id, email, created_at FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(self.pool()?)
            .await?
            .ok_or_else(|| AuthError::InvalidParams("user not found".to_owned()))?;
        let profile_schema = self.schema();
        let profile_row = sqlx::query("SELECT * FROM user_profiles WHERE user_id = ?")
            .bind(id)
            .fetch_optional(self.pool()?)
            .await?;
        let profile = match profile_row {
            Some(row) => profile_to_json(&row, &profile_schema)?,
            None => HashMap::new(),
        };
        let roles = sqlx::query_scalar::<_, String>(
            "SELECT role_name FROM user_roles WHERE user_id = ? ORDER BY role_name",
        )
        .bind(id)
        .fetch_all(self.pool()?)
        .await?;
        Ok(UserResponse {
            id: row.try_get("id")?,
            email: row.try_get("email")?,
            created_at: row.try_get("created_at")?,
            roles,
            profile,
        })
    }

    async fn permissions_for_roles(&self, roles: &[String]) -> Result<Vec<String>, AuthError> {
        if roles.is_empty() {
            return Ok(Vec::new());
        }
        let mut query = QueryBuilder::<Sqlite>::new(
            "SELECT DISTINCT permission_name FROM role_permissions WHERE role_name IN (",
        );
        {
            let mut separated = query.separated(", ");
            for role in roles {
                separated.push_bind(role);
            }
        }
        query.push(") ORDER BY permission_name");
        Ok(query.build_query_scalar().fetch_all(self.pool()?).await?)
    }
}

#[async_trait]
impl JsonRpcAuthServer for SqliteAuthServer {
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
        self.inner
            .config
            .read()
            .expect("config lock poisoned")
            .clone()
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
        let config = self.get_db_config();
        if config.db_user.is_some() || config.db_password.is_some() {
            return Err(AuthError::InvalidConfiguration(
                "SQLite does not support database username/password authentication".to_owned(),
            ));
        }
        let host = if !config.host.trim().is_empty() {
            config.host
        } else {
            config.database_name
        };
        if host.trim().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "SQLite database path is required in db_host or database_name".to_owned(),
            ));
        }
        let is_memory = host == ":memory:" || host == "sqlite::memory:";
        let uri = match host.as_str() {
            ":memory:" => "sqlite::memory:".to_owned(),
            value if value.starts_with("sqlite:") => value.to_owned(),
            value => format!("sqlite://{value}"),
        };
        let options = sqlx::sqlite::SqliteConnectOptions::from_str(&uri)
            .map_err(|error| AuthError::InvalidConfiguration(error.to_string()))?
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(if is_memory { 1 } else { 5 })
            .connect_with(options)
            .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY NOT NULL,
                email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS roles (
                name TEXT PRIMARY KEY NOT NULL
            )",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS user_roles (
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                role_name TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
                PRIMARY KEY (user_id, role_name)
            )",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS role_permissions (
                role_name TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
                permission_name TEXT NOT NULL,
                PRIMARY KEY (role_name, permission_name)
            )",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS external_identities (
                provider TEXT NOT NULL,
                subject TEXT NOT NULL,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                PRIMARY KEY (provider, subject)
            )",
        )
        .execute(&pool)
        .await?;
        create_profile_table(&pool, &self.schema()).await?;
        let _ = self.inner.pool.set(pool);
        Ok(())
    }

    fn authenticate_access_token(
        &self,
        token: &str,
    ) -> Result<crate::AccessTokenClaims, AuthError> {
        SqliteAuthServer::authenticate_access_token(self, token)
    }

    fn require_permission(
        &self,
        token: &str,
        permission: &str,
    ) -> Result<crate::AccessTokenClaims, AuthError> {
        SqliteAuthServer::require_permission(self, token, permission)
    }

    async fn handle_refresh(
        &self,
        refresh_token: &str,
    ) -> Result<TokenResponse, Self::StorageError> {
        let subject = self.inner.tokens.verify_refresh_token(refresh_token)?;
        let roles = sqlx::query_scalar::<_, String>(
            "SELECT role_name FROM user_roles WHERE user_id = ? ORDER BY role_name",
        )
        .bind(&subject)
        .fetch_all(self.pool()?)
        .await?;
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
        let insert = sqlx::query(
            "INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(email)
        .bind(password_hash)
        .bind(created_at)
        .execute(&mut *transaction)
        .await;
        if let Err(error) = insert {
            if is_unique_violation(&error) {
                return Err(AuthError::DuplicateEmail);
            }
            return Err(error.into());
        }
        insert_profile(&mut transaction, &id, &profile).await?;
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
        let user = sqlx::query("SELECT id, password_hash FROM users WHERE email = ?")
            .bind(email)
            .fetch_optional(self.pool()?)
            .await?
            .ok_or(AuthError::Unauthorized)?;
        let id: String = user.try_get("id")?;
        let stored_hash: String = user.try_get("password_hash")?;
        let parsed_hash = PasswordHash::new(&stored_hash).map_err(|_| AuthError::Unauthorized)?;
        Argon2::default()
            .verify_password(req.password.as_bytes(), &parsed_hash)
            .map_err(|_| AuthError::Unauthorized)?;
        let roles = sqlx::query_scalar::<_, String>(
            "SELECT role_name FROM user_roles WHERE user_id = ? ORDER BY role_name",
        )
        .bind(&id)
        .fetch_all(self.pool()?)
        .await?;
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
        let existing = sqlx::query_scalar::<_, String>(
            "SELECT user_id FROM external_identities WHERE provider = ? AND subject = ?",
        )
        .bind(provider)
        .bind(&identity.subject)
        .fetch_optional(self.pool()?)
        .await?;

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
            let email_exists =
                sqlx::query_scalar::<_, String>("SELECT id FROM users WHERE email = ?")
                    .bind(&email)
                    .fetch_optional(&mut *transaction)
                    .await?;
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
            let insert_user = sqlx::query(
                "INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            )
            .bind(&user_id)
            .bind(email)
            .bind(password_hash)
            .bind(created_at)
            .execute(&mut *transaction)
            .await;
            if let Err(error) = insert_user {
                if is_unique_violation(&error) {
                    return Err(AuthError::AccountLinkRequired);
                }
                return Err(error.into());
            }
            insert_profile(&mut transaction, &user_id, &HashMap::new()).await?;
            sqlx::query(
                "INSERT INTO external_identities (provider, subject, user_id) VALUES (?, ?, ?)",
            )
            .bind(provider)
            .bind(&identity.subject)
            .bind(&user_id)
            .execute(&mut *transaction)
            .await
            .map_err(|error| {
                if is_unique_violation(&error) {
                    AuthError::Unauthorized
                } else {
                    AuthError::from(error)
                }
            })?;
            transaction.commit().await?;
            user_id
        };
        let roles = sqlx::query_scalar::<_, String>(
            "SELECT role_name FROM user_roles WHERE user_id = ? ORDER BY role_name",
        )
        .bind(&user_id)
        .fetch_all(self.pool()?)
        .await?;
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
        let exists = sqlx::query_scalar::<_, String>("SELECT id FROM users WHERE id = ?")
            .bind(&user_id)
            .fetch_optional(self.pool()?)
            .await?;
        if exists.is_none() {
            return Err(AuthError::InvalidParams("user not found".to_owned()));
        }
        let result = sqlx::query(
            "INSERT INTO external_identities (provider, subject, user_id) VALUES (?, ?, ?)",
        )
        .bind(identity.provider.storage_key())
        .bind(identity.subject)
        .bind(&user_id)
        .execute(self.pool()?)
        .await;
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
        let profile = parse_profile(&self.schema(), &profile_data)?;
        if !profile.is_empty() {
            let mut query = QueryBuilder::<Sqlite>::new("UPDATE user_profiles SET ");
            let mut first = true;
            for (name, value) in &profile {
                if !first {
                    query.push(", ");
                }
                first = false;
                query.push(name).push(" = ");
                push_bind(&mut query, value);
            }
            query.push(" WHERE user_id = ").push_bind(&user_id);
            let result = query.build().execute(self.pool()?).await?;
            if result.rows_affected() == 0 {
                return Err(AuthError::InvalidParams("user not found".to_owned()));
            }
        }
        self.load_user(&user_id).await
    }

    async fn handle_add_role(
        &self,
        user_id: String,
        role_name: String,
    ) -> Result<(), Self::StorageError> {
        validate_name("role", &role_name)?;
        let mut transaction = self.pool()?.begin().await?;
        sqlx::query("INSERT INTO roles (name) VALUES (?) ON CONFLICT(name) DO NOTHING")
            .bind(&role_name)
            .execute(&mut *transaction)
            .await?;
        let result = sqlx::query(
            "INSERT INTO user_roles (user_id, role_name) VALUES (?, ?) ON CONFLICT DO NOTHING",
        )
        .bind(&user_id)
        .bind(role_name)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() == 0 {
            let exists =
                sqlx::query_scalar::<_, i64>("SELECT EXISTS(SELECT 1 FROM users WHERE id = ?)")
                    .bind(&user_id)
                    .fetch_one(&mut *transaction)
                    .await?;
            if exists == 0 {
                return Err(AuthError::InvalidParams("user not found".to_owned()));
            }
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn handle_remove_role(
        &self,
        user_id: String,
        role_name: String,
    ) -> Result<(), Self::StorageError> {
        let result = sqlx::query("DELETE FROM user_roles WHERE user_id = ? AND role_name = ?")
            .bind(user_id)
            .bind(role_name)
            .execute(self.pool()?)
            .await?;
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
        sqlx::query("INSERT INTO roles (name) VALUES (?) ON CONFLICT(name) DO NOTHING")
            .bind(&role_name)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "INSERT INTO role_permissions (role_name, permission_name)
             VALUES (?, ?) ON CONFLICT DO NOTHING",
        )
        .bind(role_name)
        .bind(permission_name)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn handle_remove_permission(
        &self,
        role_name: String,
        permission_name: String,
    ) -> Result<(), Self::StorageError> {
        let result =
            sqlx::query("DELETE FROM role_permissions WHERE role_name = ? AND permission_name = ?")
                .bind(role_name)
                .bind(permission_name)
                .execute(self.pool()?)
                .await?;
        if result.rows_affected() == 0 {
            return Err(AuthError::InvalidParams(
                "role permission assignment not found".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
enum ProfileValue {
    Text(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    DateTime(String),
    Blob(Vec<u8>),
}

fn parse_profile(
    schema: &HashMap<String, ProfileFieldType>,
    values: &HashMap<String, String>,
) -> Result<HashMap<String, ProfileValue>, AuthError> {
    values
        .iter()
        .map(|(name, value)| {
            let kind = schema.get(name).ok_or_else(|| {
                AuthError::InvalidParams(format!("profile field `{name}` is not defined"))
            })?;
            let parsed = match kind {
                ProfileFieldType::Text => ProfileValue::Text(value.clone()),
                ProfileFieldType::Integer => {
                    ProfileValue::Integer(value.parse().map_err(|_| {
                        AuthError::InvalidParams(format!(
                            "profile field `{name}` must be an integer"
                        ))
                    })?)
                }
                ProfileFieldType::Float => {
                    let number: f64 = value.parse().map_err(|_| {
                        AuthError::InvalidParams(format!("profile field `{name}` must be a float"))
                    })?;
                    if !number.is_finite() {
                        return Err(AuthError::InvalidParams(format!(
                            "profile field `{name}` must be a finite float"
                        )));
                    }
                    ProfileValue::Float(number)
                }
                ProfileFieldType::Boolean => ProfileValue::Boolean(match value.as_str() {
                    "true" | "TRUE" | "True" => true,
                    "false" | "FALSE" | "False" => false,
                    _ => {
                        return Err(AuthError::InvalidParams(format!(
                            "profile field `{name}` must be true or false"
                        )));
                    }
                }),
                ProfileFieldType::DateTime => {
                    let datetime = DateTime::parse_from_rfc3339(value).map_err(|_| {
                        AuthError::InvalidParams(format!(
                            "profile field `{name}` must be an RFC 3339 timestamp"
                        ))
                    })?;
                    ProfileValue::DateTime(datetime.with_timezone(&Utc).to_rfc3339())
                }
                ProfileFieldType::Blob => {
                    ProfileValue::Blob(STANDARD.decode(value).map_err(|_| {
                        AuthError::InvalidParams(format!("profile field `{name}` must be base64"))
                    })?)
                }
            };
            Ok((name.clone(), parsed))
        })
        .collect()
}

fn validate_profile_schema(schema: &HashMap<String, ProfileFieldType>) -> Result<(), AuthError> {
    for name in schema.keys() {
        if !valid_identifier(name) {
            return Err(AuthError::InvalidConfiguration(format!(
                "invalid profile field name `{name}`"
            )));
        }
    }
    Ok(())
}

async fn create_profile_table(
    pool: &SqlitePool,
    schema: &HashMap<String, ProfileFieldType>,
) -> Result<(), AuthError> {
    validate_profile_schema(schema)?;
    let mut columns = String::from(
        "CREATE TABLE IF NOT EXISTS user_profiles (user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE",
    );
    for (name, kind) in schema {
        columns.push_str(&format!(", {name} {}", sqlite_type(kind)));
    }
    columns.push(')');
    sqlx::query(&columns).execute(pool).await?;
    let existing: HashSet<String> = sqlx::query("PRAGMA table_info(user_profiles)")
        .fetch_all(pool)
        .await?
        .iter()
        .map(|row| row.try_get::<String, _>("name"))
        .collect::<Result<_, _>>()?;
    for (name, kind) in schema {
        if !existing.contains(name) {
            let ddl = format!(
                "ALTER TABLE user_profiles ADD COLUMN {name} {}",
                sqlite_type(kind)
            );
            sqlx::query(&ddl).execute(pool).await?;
        }
    }
    Ok(())
}

async fn insert_profile(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    user_id: &str,
    profile: &HashMap<String, ProfileValue>,
) -> Result<(), AuthError> {
    let mut query = QueryBuilder::<Sqlite>::new("INSERT INTO user_profiles (user_id");
    for name in profile.keys() {
        query.push(", ").push(name);
    }
    query.push(") VALUES (").push_bind(user_id);
    for value in profile.values() {
        query.push(", ");
        push_bind(&mut query, value);
    }
    query.push(")");
    query.build().execute(&mut **transaction).await?;
    Ok(())
}

fn push_bind(query: &mut QueryBuilder<'_, Sqlite>, value: &ProfileValue) {
    match value {
        ProfileValue::Text(value) | ProfileValue::DateTime(value) => {
            query.push_bind(value.clone());
        }
        ProfileValue::Integer(value) => {
            query.push_bind(*value);
        }
        ProfileValue::Float(value) => {
            query.push_bind(*value);
        }
        ProfileValue::Boolean(value) => {
            query.push_bind(*value);
        }
        ProfileValue::Blob(value) => {
            query.push_bind(value.clone());
        }
    }
}

fn sqlite_type(kind: &ProfileFieldType) -> &'static str {
    match kind {
        ProfileFieldType::Text | ProfileFieldType::DateTime => "TEXT",
        ProfileFieldType::Integer | ProfileFieldType::Boolean => "INTEGER",
        ProfileFieldType::Float => "REAL",
        ProfileFieldType::Blob => "BLOB",
    }
}

fn profile_to_json(
    row: &SqliteRow,
    schema: &HashMap<String, ProfileFieldType>,
) -> Result<HashMap<String, Value>, AuthError> {
    schema
        .iter()
        .filter_map(|(name, kind)| {
            let value = match kind {
                ProfileFieldType::Text => row
                    .try_get::<Option<String>, _>(name.as_str())
                    .map(|value| value.map(Value::String)),
                ProfileFieldType::Integer => row
                    .try_get::<Option<i64>, _>(name.as_str())
                    .map(|value| value.map(|number| Value::Number(number.into()))),
                ProfileFieldType::Float => {
                    row.try_get::<Option<f64>, _>(name.as_str())
                        .and_then(|value| {
                            value
                                .map(|number| {
                                    Number::from_f64(number).map(Value::Number).ok_or_else(|| {
                                        sqlx::Error::ColumnDecode {
                                            index: name.clone(),
                                            source: Box::new(std::io::Error::other(
                                                "stored float is not finite",
                                            )),
                                        }
                                    })
                                })
                                .transpose()
                        })
                }
                ProfileFieldType::Boolean => row
                    .try_get::<Option<bool>, _>(name.as_str())
                    .map(|value| value.map(Value::Bool)),
                ProfileFieldType::DateTime => row
                    .try_get::<Option<String>, _>(name.as_str())
                    .map(|value| value.map(Value::String)),
                ProfileFieldType::Blob => row
                    .try_get::<Option<Vec<u8>>, _>(name.as_str())
                    .map(|value| value.map(|bytes| Value::String(STANDARD.encode(bytes)))),
            };
            match value {
                Ok(Some(value)) => Some(Ok((name.clone(), value))),
                Ok(None) => None,
                Err(error) => Some(Err(AuthError::from(error))),
            }
        })
        .collect()
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
        .is_some_and(|error| error.code().as_deref() == Some("2067"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pasetors::{
        keys::{Generate, SymmetricKey},
        paserk::FormatAsPaserk,
        version4::V4,
    };

    #[tokio::test]
    async fn sqlite_auth_profile_and_rbac_round_trip() {
        let key = SymmetricKey::<V4>::generate().unwrap();
        let mut paserk = String::new();
        key.fmt(&mut paserk).unwrap();
        let mut server = SqliteAuthServer::new(&paserk, TokenConfig::new("sqlite-test")).unwrap();
        server.set_db_host(":memory:");
        server
            .set_profile_schema(HashMap::from([
                ("joined_at".to_owned(), ProfileFieldType::DateTime),
                ("avatar".to_owned(), ProfileFieldType::Blob),
                ("active".to_owned(), ProfileFieldType::Boolean),
            ]))
            .unwrap();
        server.initialize_storage().await.unwrap();

        let user = server
            .handle_register(RegisterRequest {
                email: "user@example.test".to_owned(),
                password: "a long secure password".to_owned(),
                profile: HashMap::from([
                    ("joined_at".to_owned(), "2024-01-02T03:04:05Z".to_owned()),
                    ("avatar".to_owned(), "AQID".to_owned()),
                    ("active".to_owned(), "true".to_owned()),
                ]),
            })
            .await
            .unwrap();
        assert_eq!(user.profile["avatar"], "AQID");
        assert_eq!(user.profile["active"], true);
        assert_eq!(user.profile["joined_at"], "2024-01-02T03:04:05+00:00");

        server
            .handle_add_role(user.id.clone(), "administrator".to_owned())
            .await
            .unwrap();
        server
            .handle_add_permission("administrator".to_owned(), "user.read".to_owned())
            .await
            .unwrap();
        let tokens = server
            .handle_login(LoginRequest {
                email: "USER@example.test".to_owned(),
                password: "a long secure password".to_owned(),
                grant_type: "password".to_owned(),
            })
            .await
            .unwrap();
        assert!(
            server
                .require_permission(&tokens.access_token, "user.read")
                .is_ok()
        );
        assert!(matches!(
            server.require_permission(&tokens.access_token, "user.delete"),
            Err(AuthError::Forbidden)
        ));
    }

    #[tokio::test]
    async fn external_identity_login_is_persisted_and_requires_explicit_account_linking() {
        let key = SymmetricKey::<V4>::generate().unwrap();
        let mut paserk = String::new();
        key.fmt(&mut paserk).unwrap();
        let mut server =
            SqliteAuthServer::new(&paserk, TokenConfig::new("sqlite-oauth-test")).unwrap();
        server.set_db_host(":memory:");
        server.initialize_storage().await.unwrap();

        let initial = server
            .handle_external_login(ExternalIdentity {
                provider: crate::OAuth2Provider::Google,
                subject: "google-subject-1".to_owned(),
                email: Some("oauth@example.test".to_owned()),
                email_verified: true,
            })
            .await
            .unwrap();
        let user_id = server
            .authenticate_access_token(&initial.access_token)
            .unwrap()
            .subject;
        let repeat = server
            .handle_external_login(ExternalIdentity {
                provider: crate::OAuth2Provider::Google,
                subject: "google-subject-1".to_owned(),
                email: None,
                email_verified: false,
            })
            .await
            .unwrap();
        assert_eq!(
            server
                .authenticate_access_token(&repeat.access_token)
                .unwrap()
                .subject,
            user_id
        );

        let another_provider = ExternalIdentity {
            provider: crate::OAuth2Provider::GitHub,
            subject: "github-subject-1".to_owned(),
            email: Some("oauth@example.test".to_owned()),
            email_verified: true,
        };
        assert!(matches!(
            server.handle_external_login(another_provider.clone()).await,
            Err(AuthError::AccountLinkRequired)
        ));
        server
            .link_external_identity(user_id.clone(), another_provider.clone())
            .await
            .unwrap();
        let linked = server
            .handle_external_login(ExternalIdentity {
                email: None,
                email_verified: false,
                ..another_provider
            })
            .await
            .unwrap();
        assert_eq!(
            server
                .authenticate_access_token(&linked.access_token)
                .unwrap()
                .subject,
            user_id
        );
    }
}
