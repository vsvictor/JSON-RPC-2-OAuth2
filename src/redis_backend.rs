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
use redis::{Script, aio::ConnectionManager};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tokio::sync::OnceCell;
use url::Url;

struct Inner {
    config: RwLock<DbConfig>,
    profile_schema: RwLock<HashMap<String, ProfileFieldType>>,
    connection: OnceCell<ConnectionManager>,
    tokens: TokenService,
}

#[derive(Clone)]
pub struct RedisAuthServer {
    inner: Arc<Inner>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredUser {
    id: String,
    email: String,
    password_hash: String,
    created_at: String,
}

impl RedisAuthServer {
    /// Create a Redis authentication service using a PASERK-encoded v4.local key.
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

    fn connection(&self) -> Result<ConnectionManager, AuthError> {
        self.inner
            .connection
            .get()
            .cloned()
            .ok_or(AuthError::StorageNotInitialized)
    }

    async fn load_user(&self, id: &str) -> Result<UserResponse, AuthError> {
        let mut connection = self.connection()?;
        let user_json: Option<String> = redis::cmd("GET")
            .arg(user_key(id))
            .query_async(&mut connection)
            .await
            .map_err(redis_error)?;
        let user: StoredUser = serde_json::from_str(
            user_json
                .as_deref()
                .ok_or_else(|| AuthError::InvalidParams("user not found".to_owned()))?,
        )?;
        let profile_json: Option<String> = redis::cmd("GET")
            .arg(profile_key(id))
            .query_async(&mut connection)
            .await
            .map_err(redis_error)?;
        let profile = profile_json
            .map(|json| serde_json::from_str(&json))
            .transpose()?
            .unwrap_or_default();
        let roles = self.roles_for_user(id).await?;
        Ok(UserResponse {
            id: user.id,
            email: user.email,
            created_at: user.created_at,
            roles,
            profile,
        })
    }

    async fn roles_for_user(&self, user_id: &str) -> Result<Vec<String>, AuthError> {
        let mut connection = self.connection()?;
        let mut roles: Vec<String> = redis::cmd("SMEMBERS")
            .arg(user_roles_key(user_id))
            .query_async(&mut connection)
            .await
            .map_err(redis_error)?;
        roles.sort();
        Ok(roles)
    }

    async fn permissions_for_roles(&self, roles: &[String]) -> Result<Vec<String>, AuthError> {
        let mut connection = self.connection()?;
        let mut permissions = Vec::new();
        for role in roles {
            let assigned: Vec<String> = redis::cmd("SMEMBERS")
                .arg(role_permissions_key(role))
                .query_async(&mut connection)
                .await
                .map_err(redis_error)?;
            permissions.extend(assigned);
        }
        permissions.sort();
        permissions.dedup();
        Ok(permissions)
    }
}

#[async_trait]
impl JsonRpcAuthServer for RedisAuthServer {
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
        let uri = make_redis_uri(&config)?;
        let manager = self
            .inner
            .connection
            .get_or_try_init(|| async {
                let client = redis::Client::open(uri).map_err(redis_error)?;
                client.get_connection_manager().await.map_err(redis_error)
            })
            .await?;
        let mut connection = manager.clone();
        redis::cmd("PING")
            .query_async::<String>(&mut connection)
            .await
            .map_err(redis_error)?;
        Ok(())
    }

    fn authenticate_access_token(&self, token: &str) -> Result<AccessTokenClaims, AuthError> {
        RedisAuthServer::authenticate_access_token(self, token)
    }

    fn require_permission(
        &self,
        token: &str,
        permission: &str,
    ) -> Result<AccessTokenClaims, AuthError> {
        RedisAuthServer::require_permission(self, token, permission)
    }

    async fn handle_refresh(
        &self,
        refresh_token: &str,
    ) -> Result<TokenResponse, Self::StorageError> {
        let subject = self.inner.tokens.verify_refresh_token(refresh_token)?;
        let user_json: Option<String> = redis::cmd("GET")
            .arg(user_key(&subject))
            .query_async(&mut self.connection()?)
            .await
            .map_err(redis_error)?;
        if user_json.is_none() {
            return Err(AuthError::Unauthorized);
        }
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
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(req.password.as_bytes(), &salt)
            .map_err(|error| AuthError::PasswordHash(error.to_string()))?
            .to_string();
        let user = StoredUser {
            id: uuid::Uuid::new_v4().to_string(),
            email: email.clone(),
            password_hash,
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        let user_json = serde_json::to_string(&user)?;
        let profile_json = serde_json::to_string(&profile)?;
        let script = Script::new(
            "if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end \
             redis.call('SET', KEYS[1], ARGV[1]) \
             redis.call('SET', KEYS[2], ARGV[2]) \
             redis.call('SET', KEYS[3], ARGV[3]) \
             return 1",
        );
        let result: i32 = script
            .key(email_key(&email))
            .key(user_key(&user.id))
            .key(profile_key(&user.id))
            .arg(&user.id)
            .arg(user_json)
            .arg(profile_json)
            .invoke_async(&mut self.connection()?)
            .await
            .map_err(redis_error)?;
        if result == 0 {
            return Err(AuthError::DuplicateEmail);
        }
        self.load_user(&user.id).await
    }

    async fn handle_login(&self, req: LoginRequest) -> Result<TokenResponse, Self::StorageError> {
        if req.grant_type != "password" {
            return Err(AuthError::InvalidParams(
                "grant_type must be `password`".to_owned(),
            ));
        }
        let email = normalize_email(&req.email)?;
        let mut connection = self.connection()?;
        let user_id: Option<String> = redis::cmd("GET")
            .arg(email_key(&email))
            .query_async(&mut connection)
            .await
            .map_err(redis_error)?;
        let user_json: Option<String> = match user_id {
            Some(id) => redis::cmd("GET")
                .arg(user_key(&id))
                .query_async(&mut connection)
                .await
                .map_err(redis_error)?,
            None => None,
        };
        let user: StoredUser =
            serde_json::from_str(user_json.as_deref().ok_or(AuthError::Unauthorized)?)
                .map_err(|_| AuthError::Unauthorized)?;
        let parsed_hash =
            PasswordHash::new(&user.password_hash).map_err(|_| AuthError::Unauthorized)?;
        Argon2::default()
            .verify_password(req.password.as_bytes(), &parsed_hash)
            .map_err(|_| AuthError::Unauthorized)?;
        let roles = self.roles_for_user(&user.id).await?;
        let permissions = self.permissions_for_roles(&roles).await?;
        self.inner.tokens.issue_pair(&user.id, &roles, &permissions)
    }

    async fn handle_external_login(
        &self,
        identity: ExternalIdentity,
    ) -> Result<TokenResponse, AuthError> {
        if identity.subject.trim().is_empty() {
            return Err(AuthError::Unauthorized);
        }
        let key = external_identity_key(identity.provider.storage_key(), &identity.subject);
        let mut connection = self.connection()?;
        let mut user_id: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut connection)
            .await
            .map_err(redis_error)?;
        if user_id.is_none() {
            if !identity.email_verified {
                return Err(AuthError::Unauthorized);
            }
            let email = identity.email.as_deref().ok_or(AuthError::Unauthorized)?;
            let password = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
            let user = match self
                .handle_register(RegisterRequest {
                    email: email.to_owned(),
                    password,
                    profile: HashMap::new(),
                })
                .await
            {
                Ok(user) => user,
                Err(AuthError::DuplicateEmail) => return Err(AuthError::AccountLinkRequired),
                Err(error) => return Err(error),
            };
            let inserted: bool = redis::cmd("SET")
                .arg(&key)
                .arg(&user.id)
                .arg("NX")
                .query_async(&mut self.connection()?)
                .await
                .map_err(redis_error)?;
            if inserted {
                user_id = Some(user.id);
            } else {
                let mut cleanup = self.connection()?;
                let _: () = redis::cmd("DEL")
                    .arg(email_key(&user.email))
                    .arg(user_key(&user.id))
                    .arg(profile_key(&user.id))
                    .query_async(&mut cleanup)
                    .await
                    .map_err(redis_error)?;
                user_id = redis::cmd("GET")
                    .arg(&key)
                    .query_async(&mut cleanup)
                    .await
                    .map_err(redis_error)?;
            }
        }
        let user_id = user_id.ok_or(AuthError::Unauthorized)?;
        let roles = self.roles_for_user(&user_id).await?;
        let permissions = self.permissions_for_roles(&roles).await?;
        self.inner.tokens.issue_pair(&user_id, &roles, &permissions)
    }

    async fn link_external_identity(
        &self,
        user_id: String,
        identity: ExternalIdentity,
    ) -> Result<(), AuthError> {
        let mut connection = self.connection()?;
        let user_exists: bool = redis::cmd("EXISTS")
            .arg(user_key(&user_id))
            .query_async(&mut connection)
            .await
            .map_err(redis_error)?;
        if !user_exists {
            return Err(AuthError::InvalidParams("user not found".to_owned()));
        }
        let inserted: bool = redis::cmd("SET")
            .arg(external_identity_key(
                identity.provider.storage_key(),
                &identity.subject,
            ))
            .arg(user_id)
            .arg("NX")
            .query_async(&mut connection)
            .await
            .map_err(redis_error)?;
        if inserted {
            Ok(())
        } else {
            Err(AuthError::AccountLinkRequired)
        }
    }

    async fn handle_update_profile(
        &self,
        user_id: String,
        profile_data: HashMap<String, String>,
    ) -> Result<UserResponse, Self::StorageError> {
        let updates = crate::profile_values::parse_profile(&self.schema(), &profile_data)?;
        let mut connection = self.connection()?;
        let existing: Option<String> = redis::cmd("GET")
            .arg(profile_key(&user_id))
            .query_async(&mut connection)
            .await
            .map_err(redis_error)?;
        let mut profile: HashMap<String, Value> = existing
            .as_deref()
            .map(serde_json::from_str)
            .transpose()?
            .ok_or_else(|| AuthError::InvalidParams("user not found".to_owned()))?;
        profile.extend(updates);
        redis::cmd("SET")
            .arg(profile_key(&user_id))
            .arg(serde_json::to_string(&profile)?)
            .query_async::<()>(&mut connection)
            .await
            .map_err(redis_error)?;
        self.load_user(&user_id).await
    }

    async fn handle_add_role(
        &self,
        user_id: String,
        role_name: String,
    ) -> Result<(), Self::StorageError> {
        validate_name("role", &role_name)?;
        let mut connection = self.connection()?;
        let user_json: Option<String> = redis::cmd("GET")
            .arg(user_key(&user_id))
            .query_async(&mut connection)
            .await
            .map_err(redis_error)?;
        if user_json.is_none() {
            return Err(AuthError::InvalidParams("user not found".to_owned()));
        }
        redis::cmd("SADD")
            .arg("auth:roles")
            .arg(&role_name)
            .query_async::<()>(&mut connection)
            .await
            .map_err(redis_error)?;
        redis::cmd("SADD")
            .arg(user_roles_key(&user_id))
            .arg(role_name)
            .query_async::<()>(&mut connection)
            .await
            .map_err(redis_error)?;
        Ok(())
    }

    async fn handle_remove_role(
        &self,
        user_id: String,
        role_name: String,
    ) -> Result<(), Self::StorageError> {
        let removed: i32 = redis::cmd("SREM")
            .arg(user_roles_key(&user_id))
            .arg(role_name)
            .query_async(&mut self.connection()?)
            .await
            .map_err(redis_error)?;
        if removed == 0 {
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
        let mut connection = self.connection()?;
        redis::cmd("SADD")
            .arg("auth:roles")
            .arg(&role_name)
            .query_async::<()>(&mut connection)
            .await
            .map_err(redis_error)?;
        redis::cmd("SADD")
            .arg(role_permissions_key(&role_name))
            .arg(permission_name)
            .query_async::<()>(&mut connection)
            .await
            .map_err(redis_error)?;
        Ok(())
    }

    async fn handle_remove_permission(
        &self,
        role_name: String,
        permission_name: String,
    ) -> Result<(), Self::StorageError> {
        let removed: i32 = redis::cmd("SREM")
            .arg(role_permissions_key(&role_name))
            .arg(permission_name)
            .query_async(&mut self.connection()?)
            .await
            .map_err(redis_error)?;
        if removed == 0 {
            return Err(AuthError::InvalidParams(
                "role permission assignment not found".to_owned(),
            ));
        }
        Ok(())
    }
}

fn make_redis_uri(config: &DbConfig) -> Result<String, AuthError> {
    let host = config.host.trim();
    if host.is_empty() {
        return Err(AuthError::InvalidConfiguration(
            "Redis host or URL is required".to_owned(),
        ));
    }
    let mut uri = if host.contains("://") {
        Url::parse(host).map_err(|error| AuthError::InvalidConfiguration(error.to_string()))?
    } else {
        Url::parse(&format!("redis://{host}/"))
            .map_err(|error| AuthError::InvalidConfiguration(error.to_string()))?
    };
    if !matches!(uri.scheme(), "redis" | "rediss") {
        return Err(AuthError::InvalidConfiguration(
            "Redis URL must use the redis:// or rediss:// scheme".to_owned(),
        ));
    }
    if let Some(user) = &config.db_user {
        uri.set_username(user)
            .map_err(|_| AuthError::InvalidConfiguration("invalid Redis username".to_owned()))?;
    }
    if let Some(password) = &config.db_password {
        uri.set_password(Some(password))
            .map_err(|_| AuthError::InvalidConfiguration("invalid Redis password".to_owned()))?;
    }
    if !config.database_name.trim().is_empty() {
        let database = config.database_name.trim().parse::<u32>().map_err(|_| {
            AuthError::InvalidConfiguration(
                "Redis database_name must be a non-negative logical database number".to_owned(),
            )
        })?;
        uri.set_path(&format!("/{database}"));
    }
    Ok(uri.to_string())
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

fn redis_error(error: redis::RedisError) -> AuthError {
    AuthError::Redis(error.to_string())
}

fn user_key(id: &str) -> String {
    format!("auth:user:{id}")
}

fn email_key(email: &str) -> String {
    format!("auth:email:{email}")
}

fn profile_key(id: &str) -> String {
    format!("auth:profile:{id}")
}

fn external_identity_key(provider: &str, subject: &str) -> String {
    let digest = Sha256::digest(subject.as_bytes());
    let encoded = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("auth:external:{provider}:{encoded}")
}

fn user_roles_key(id: &str) -> String {
    format!("auth:user:{id}:roles")
}

fn role_permissions_key(role: &str) -> String {
    format!("auth:role:{role}:permissions")
}
