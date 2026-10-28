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
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tiberius::{AuthMethod, Client, Config, Query};
use tokio::{net::TcpStream, sync::Mutex};
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};

struct Inner {
    config: RwLock<DbConfig>,
    profile_schema: RwLock<HashMap<String, ProfileFieldType>>,
    trust_server_certificate: RwLock<bool>,
    client: tokio::sync::OnceCell<Arc<Mutex<Client<Compat<TcpStream>>>>>,
    tokens: TokenService,
}

#[derive(Clone)]
pub struct MssqlAuthServer {
    inner: Arc<Inner>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredUser {
    id: String,
    email: String,
    password_hash: String,
    created_at: String,
}

impl MssqlAuthServer {
    /// Create a Microsoft SQL Server authentication service with a v4.local key.
    pub fn new(paserk_key: &str, token_config: TokenConfig) -> Result<Self, AuthError> {
        Ok(Self {
            inner: Arc::new(Inner {
                config: RwLock::new(DbConfig::default()),
                profile_schema: RwLock::new(HashMap::new()),
                trust_server_certificate: RwLock::new(false),
                client: tokio::sync::OnceCell::new(),
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

    /// Disable SQL Server certificate validation.
    ///
    /// This is intended only for local development and self-signed test
    /// servers. Production deployments should leave validation enabled.
    pub fn set_trust_server_certificate(&mut self, trust: bool) {
        *self
            .inner
            .trust_server_certificate
            .write()
            .expect("certificate setting lock poisoned") = trust;
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

    fn client(&self) -> Result<Arc<Mutex<Client<Compat<TcpStream>>>>, AuthError> {
        self.inner
            .client
            .get()
            .cloned()
            .ok_or(AuthError::StorageNotInitialized)
    }

    async fn roles_for_user(&self, user_id: &str) -> Result<Vec<String>, AuthError> {
        let client = self.client()?;
        let mut client = client.lock().await;
        let rows = query(
            &mut client,
            "SELECT role_name FROM user_roles WHERE user_id = @P1 ORDER BY role_name",
            &[user_id],
        )
        .await?;
        rows.iter().map(|row| row_string(row, 0)).collect()
    }

    async fn permissions_for_roles(&self, roles: &[String]) -> Result<Vec<String>, AuthError> {
        let client = self.client()?;
        let mut client = client.lock().await;
        let mut permissions = Vec::new();
        for role in roles {
            let rows = query(
                &mut client,
                "SELECT permission_name FROM role_permissions WHERE role_name = @P1 ORDER BY permission_name",
                &[role],
            )
            .await?;
            permissions.extend(
                rows.iter()
                    .map(|row| row_string(row, 0))
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        permissions.sort();
        permissions.dedup();
        Ok(permissions)
    }

    async fn load_user(&self, user_id: &str) -> Result<UserResponse, AuthError> {
        let client = self.client()?;
        let (user, profile) = {
            let mut client = client.lock().await;
            let rows = query(
                &mut client,
                "SELECT id, email, created_at FROM users WHERE id = @P1",
                &[user_id],
            )
            .await?;
            let row = rows
                .first()
                .ok_or_else(|| AuthError::InvalidParams("user not found".to_owned()))?;
            let user = StoredUser {
                id: row_string(row, 0)?,
                email: row_string(row, 1)?,
                created_at: row_string(row, 2)?,
                password_hash: String::new(),
            };
            let profile_rows = query(
                &mut client,
                "SELECT profile_json FROM user_profiles WHERE user_id = @P1",
                &[&user.id],
            )
            .await?;
            let profile = match profile_rows.first() {
                Some(row) => {
                    let json = row_string(row, 0)?;
                    serde_json::from_str(&json)?
                }
                None => HashMap::new(),
            };
            (user, profile)
        };
        Ok(UserResponse {
            id: user.id.clone(),
            email: user.email,
            created_at: user.created_at,
            roles: self.roles_for_user(&user.id).await?,
            profile,
        })
    }
}

#[async_trait]
impl JsonRpcAuthServer for MssqlAuthServer {
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
        if self.inner.client.get().is_some() {
            return Ok(());
        }
        let config = self.config();
        let (host, port) = parse_host_port(&config.host)?;
        let user = config.db_user.as_deref().ok_or_else(|| {
            AuthError::InvalidConfiguration("SQL Server database user is required".to_owned())
        })?;
        let password = config.db_password.as_deref().ok_or_else(|| {
            AuthError::InvalidConfiguration("SQL Server database password is required".to_owned())
        })?;
        let database = config.database_name.trim();
        if database.is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "SQL Server database name is required".to_owned(),
            ));
        }
        let mut tiberius_config = Config::new();
        tiberius_config.host(host);
        tiberius_config.port(port);
        tiberius_config.database(database);
        tiberius_config.authentication(AuthMethod::sql_server(user, password));
        if *self
            .inner
            .trust_server_certificate
            .read()
            .expect("certificate setting lock poisoned")
        {
            tiberius_config.trust_cert();
        }
        let tcp = TcpStream::connect(tiberius_config.get_addr())
            .await
            .map_err(mssql_error)?;
        tcp.set_nodelay(true).map_err(mssql_error)?;
        let mut client = Client::connect(tiberius_config, tcp.compat_write())
            .await
            .map_err(mssql_error)?;
        for statement in [
            "IF OBJECT_ID(N'dbo.users', N'U') IS NULL CREATE TABLE dbo.users (id NVARCHAR(36) NOT NULL PRIMARY KEY, email NVARCHAR(254) NOT NULL UNIQUE, password_hash NVARCHAR(255) NOT NULL, created_at NVARCHAR(40) NOT NULL)",
            "IF OBJECT_ID(N'dbo.roles', N'U') IS NULL CREATE TABLE dbo.roles (name NVARCHAR(128) NOT NULL PRIMARY KEY)",
            "IF OBJECT_ID(N'dbo.user_roles', N'U') IS NULL CREATE TABLE dbo.user_roles (user_id NVARCHAR(36) NOT NULL REFERENCES dbo.users(id) ON DELETE CASCADE, role_name NVARCHAR(128) NOT NULL REFERENCES dbo.roles(name) ON DELETE CASCADE, CONSTRAINT PK_auth_user_roles PRIMARY KEY (user_id, role_name))",
            "IF OBJECT_ID(N'dbo.role_permissions', N'U') IS NULL CREATE TABLE dbo.role_permissions (role_name NVARCHAR(128) NOT NULL REFERENCES dbo.roles(name) ON DELETE CASCADE, permission_name NVARCHAR(128) NOT NULL, CONSTRAINT PK_auth_role_permissions PRIMARY KEY (role_name, permission_name))",
            "IF OBJECT_ID(N'dbo.user_profiles', N'U') IS NULL CREATE TABLE dbo.user_profiles (user_id NVARCHAR(36) NOT NULL PRIMARY KEY REFERENCES dbo.users(id) ON DELETE CASCADE, profile_json NVARCHAR(MAX) NOT NULL)",
            "IF OBJECT_ID(N'dbo.external_identities', N'U') IS NULL CREATE TABLE dbo.external_identities (provider NVARCHAR(64) NOT NULL, subject NVARCHAR(512) NOT NULL, user_id NVARCHAR(36) NOT NULL REFERENCES dbo.users(id) ON DELETE CASCADE, CONSTRAINT PK_auth_external_identities PRIMARY KEY (provider, subject))",
        ] {
            execute(&mut client, statement, &[]).await?;
        }
        let _ = self.inner.client.set(Arc::new(Mutex::new(client)));
        Ok(())
    }

    fn authenticate_access_token(&self, token: &str) -> Result<AccessTokenClaims, AuthError> {
        MssqlAuthServer::authenticate_access_token(self, token)
    }

    fn require_permission(
        &self,
        token: &str,
        permission: &str,
    ) -> Result<AccessTokenClaims, AuthError> {
        MssqlAuthServer::require_permission(self, token, permission)
    }

    async fn handle_refresh(
        &self,
        refresh_token: &str,
    ) -> Result<TokenResponse, Self::StorageError> {
        let subject = self.inner.tokens.verify_refresh_token(refresh_token)?;
        let client = self.client()?;
        let mut client = client.lock().await;
        let rows = query(
            &mut client,
            "SELECT id FROM users WHERE id = @P1",
            &[&subject],
        )
        .await?;
        if rows.is_empty() {
            return Err(AuthError::Unauthorized);
        }
        drop(client);
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
        let client = self.client()?;
        let mut client = client.lock().await;
        if let Err(error) = execute(
            &mut client,
            "BEGIN TRY BEGIN TRANSACTION; \
             INSERT INTO users (id, email, password_hash, created_at) VALUES (@P1, @P2, @P3, @P4); \
             INSERT INTO user_profiles (user_id, profile_json) VALUES (@P1, @P5); \
             COMMIT TRANSACTION; END TRY BEGIN CATCH \
             IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION; THROW; END CATCH",
            &[&id, &email, &password_hash, &created_at, &profile_json],
        )
        .await
        {
            if is_duplicate_email(&error) {
                return Err(AuthError::DuplicateEmail);
            }
            return Err(error);
        }
        drop(client);
        self.load_user(&id).await
    }

    async fn handle_login(&self, req: LoginRequest) -> Result<TokenResponse, Self::StorageError> {
        if req.grant_type != "password" {
            return Err(AuthError::InvalidParams(
                "grant_type must be `password`".to_owned(),
            ));
        }
        let email = normalize_email(&req.email)?;
        let client = self.client()?;
        let mut client = client.lock().await;
        let rows = query(
            &mut client,
            "SELECT id, password_hash FROM users WHERE email = @P1",
            &[&email],
        )
        .await?;
        let row = rows.first().ok_or(AuthError::Unauthorized)?;
        let id = row_string(row, 0)?;
        let stored_hash = row_string(row, 1)?;
        let parsed_hash = PasswordHash::new(&stored_hash).map_err(|_| AuthError::Unauthorized)?;
        Argon2::default()
            .verify_password(req.password.as_bytes(), &parsed_hash)
            .map_err(|_| AuthError::Unauthorized)?;
        drop(client);
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
        let client = self.client()?;
        let mut client = client.lock().await;
        let rows = query(
            &mut client,
            "SELECT user_id FROM dbo.external_identities WHERE provider = @P1 AND subject = @P2",
            &[provider, &identity.subject],
        )
        .await?;
        let linked_id = rows.first().map(|row| row_string(row, 0)).transpose()?;
        drop(client);

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
            let client = self.client()?;
            let mut client = client.lock().await;
            if let Err(error) = execute(
                &mut client,
                "INSERT INTO dbo.external_identities (provider, subject, user_id) VALUES (@P1, @P2, @P3)",
                &[provider, &identity.subject, &user.id],
            )
            .await
            {
                let _ = execute(&mut client, "DELETE FROM dbo.users WHERE id = @P1", &[&user.id]).await;
                if is_duplicate_email(&error) {
                    return Err(AuthError::Unauthorized);
                }
                return Err(error);
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
        let client = self.client()?;
        let mut client = client.lock().await;
        let users = query(
            &mut client,
            "SELECT id FROM dbo.users WHERE id = @P1",
            &[&user_id],
        )
        .await?;
        if users.is_empty() {
            return Err(AuthError::InvalidParams("user not found".to_owned()));
        }
        let provider = identity.provider.storage_key();
        execute(
            &mut client,
            "INSERT INTO dbo.external_identities (provider, subject, user_id) VALUES (@P1, @P2, @P3)",
            &[provider, &identity.subject, &user_id],
        )
        .await?;
        Ok(())
    }

    async fn handle_update_profile(
        &self,
        user_id: String,
        profile_data: HashMap<String, String>,
    ) -> Result<UserResponse, Self::StorageError> {
        let updates = crate::profile_values::parse_profile(&self.schema(), &profile_data)?;
        let client = self.client()?;
        let mut client = client.lock().await;
        let rows = query(
            &mut client,
            "SELECT profile_json FROM user_profiles WHERE user_id = @P1",
            &[&user_id],
        )
        .await?;
        let row = rows
            .first()
            .ok_or_else(|| AuthError::InvalidParams("user not found".to_owned()))?;
        let existing = row_string(row, 0)?;
        let mut profile: HashMap<String, Value> = serde_json::from_str(&existing)?;
        profile.extend(updates);
        let updated_json = serde_json::to_string(&profile)?;
        execute(
            &mut client,
            "UPDATE user_profiles SET profile_json = @P1 WHERE user_id = @P2",
            &[&updated_json, &user_id],
        )
        .await?;
        drop(client);
        self.load_user(&user_id).await
    }

    async fn handle_add_role(
        &self,
        user_id: String,
        role_name: String,
    ) -> Result<(), Self::StorageError> {
        validate_name("role", &role_name)?;
        let client = self.client()?;
        let mut client = client.lock().await;
        let users = query(
            &mut client,
            "SELECT id FROM users WHERE id = @P1",
            &[&user_id],
        )
        .await?;
        if users.is_empty() {
            return Err(AuthError::InvalidParams("user not found".to_owned()));
        }
        execute(
            &mut client,
            "BEGIN TRY BEGIN TRANSACTION; \
             MERGE dbo.roles WITH (HOLDLOCK) AS target USING (SELECT @P2 AS name) AS source \
             ON target.name = source.name WHEN NOT MATCHED THEN INSERT (name) VALUES (source.name); \
             MERGE dbo.user_roles WITH (HOLDLOCK) AS target \
             USING (SELECT @P1 AS user_id, @P2 AS role_name) AS source \
             ON target.user_id = source.user_id AND target.role_name = source.role_name \
             WHEN NOT MATCHED THEN INSERT (user_id, role_name) VALUES (source.user_id, source.role_name); \
             COMMIT TRANSACTION; END TRY BEGIN CATCH \
             IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION; THROW; END CATCH",
            &[&user_id, &role_name],
        )
        .await?;
        Ok(())
    }

    async fn handle_remove_role(
        &self,
        user_id: String,
        role_name: String,
    ) -> Result<(), Self::StorageError> {
        let client = self.client()?;
        let mut client = client.lock().await;
        let rows = execute(
            &mut client,
            "DELETE FROM user_roles WHERE user_id = @P1 AND role_name = @P2",
            &[&user_id, &role_name],
        )
        .await?;
        if rows == 0 {
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
        let client = self.client()?;
        let mut client = client.lock().await;
        execute(
            &mut client,
            "BEGIN TRY BEGIN TRANSACTION; \
             MERGE dbo.roles WITH (HOLDLOCK) AS target USING (SELECT @P1 AS name) AS source \
             ON target.name = source.name WHEN NOT MATCHED THEN INSERT (name) VALUES (source.name); \
             MERGE dbo.role_permissions WITH (HOLDLOCK) AS target \
             USING (SELECT @P1 AS role_name, @P2 AS permission_name) AS source \
             ON target.role_name = source.role_name AND target.permission_name = source.permission_name \
             WHEN NOT MATCHED THEN INSERT (role_name, permission_name) VALUES (source.role_name, source.permission_name); \
             COMMIT TRANSACTION; END TRY BEGIN CATCH \
             IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION; THROW; END CATCH",
            &[&role_name, &permission_name],
        )
        .await?;
        Ok(())
    }

    async fn handle_remove_permission(
        &self,
        role_name: String,
        permission_name: String,
    ) -> Result<(), Self::StorageError> {
        let client = self.client()?;
        let mut client = client.lock().await;
        let rows = execute(
            &mut client,
            "DELETE FROM role_permissions WHERE role_name = @P1 AND permission_name = @P2",
            &[&role_name, &permission_name],
        )
        .await?;
        if rows == 0 {
            return Err(AuthError::InvalidParams(
                "role permission assignment not found".to_owned(),
            ));
        }
        Ok(())
    }
}

fn parse_host_port(host: &str) -> Result<(String, u16), AuthError> {
    let host = host.trim().strip_prefix("mssql://").unwrap_or(host.trim());
    if let Some((host, port)) = host.rsplit_once(':') {
        let port = port
            .parse::<u16>()
            .map_err(|_| AuthError::InvalidConfiguration("invalid SQL Server port".to_owned()))?;
        return Ok((host.trim_matches(['[', ']']).to_owned(), port));
    }
    if host.is_empty() {
        return Err(AuthError::InvalidConfiguration(
            "SQL Server host is required".to_owned(),
        ));
    }
    Ok((host.to_owned(), 1433))
}

async fn query(
    client: &mut Client<Compat<TcpStream>>,
    sql: &str,
    params: &[&str],
) -> Result<Vec<tiberius::Row>, AuthError> {
    let mut query = Query::new(sql);
    query.bind_iter(params.iter().copied());
    query
        .query(client)
        .await
        .map_err(mssql_error)?
        .into_first_result()
        .await
        .map_err(mssql_error)
}

async fn execute(
    client: &mut Client<Compat<TcpStream>>,
    sql: &str,
    params: &[&str],
) -> Result<u64, AuthError> {
    let mut query = Query::new(sql);
    query.bind_iter(params.iter().copied());
    let result = query.execute(client).await.map_err(mssql_error)?;
    Ok(result.rows_affected().iter().sum())
}

fn row_string(row: &tiberius::Row, index: usize) -> Result<String, AuthError> {
    row.try_get::<&str, _>(index)
        .map_err(mssql_error)?
        .map(str::to_owned)
        .ok_or_else(|| {
            AuthError::InvalidConfiguration(format!(
                "SQL Server result column at index {index} is missing or not text"
            ))
        })
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

fn mssql_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::Mssql(error.to_string())
}

fn is_duplicate_email(error: &AuthError) -> bool {
    matches!(error, AuthError::Mssql(message) if message.contains("2601") || message.contains("2627"))
}
