use crate::{
    AccessTokenClaims, AuthError, DbConfig, ExternalIdentity, JsonRpcAuthServer, LoginRequest,
    ProfileFieldType, RegisterRequest, TokenConfig, TokenResponse, UserResponse,
    profile::{parse_profile, profile_to_json},
    token::TokenService,
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use async_trait::async_trait;
use mongodb::{
    Client, Collection, Database, IndexModel,
    bson::{Bson, DateTime, Document, doc, oid::ObjectId},
    options::ClientOptions,
    options::{Credential, IndexOptions},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};
use tokio::sync::OnceCell;

const USERS: &str = "users";
const ROLES: &str = "roles";

struct Inner {
    config: RwLock<DbConfig>,
    profile_schema: RwLock<HashMap<String, ProfileFieldType>>,
    database: OnceCell<Database>,
    tokens: TokenService,
}

/// MongoDB-backed authentication, dynamic profiles and RBAC service.
#[derive(Clone)]
pub struct MongoAuthServer {
    inner: Arc<Inner>,
}

impl MongoAuthServer {
    /// Create a service using a PASERK-encoded v4.local PASETO key.
    ///
    /// Keep the key outside source control and share it across all server
    /// instances that must validate the same access tokens.
    pub fn new(paserk_key: &str, token_config: TokenConfig) -> Result<Self, AuthError> {
        Ok(Self {
            inner: Arc::new(Inner {
                config: RwLock::new(DbConfig::default()),
                profile_schema: RwLock::new(HashMap::new()),
                database: OnceCell::new(),
                tokens: TokenService::new(paserk_key, token_config)?,
            }),
        })
    }

    /// Configure the profile fields before initializing MongoDB.
    pub fn set_profile_schema(
        &mut self,
        schema: HashMap<String, ProfileFieldType>,
    ) -> Result<(), AuthError> {
        for name in schema.keys() {
            if !valid_field_name(name) {
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

    /// Validate an access token and return its authenticated subject and RBAC claims.
    pub fn authenticate_access_token(&self, token: &str) -> Result<AccessTokenClaims, AuthError> {
        self.inner.tokens.verify_access_token(token)
    }

    /// Validate an access token and require the named permission.
    pub fn require_permission(
        &self,
        token: &str,
        required_permission: &str,
    ) -> Result<AccessTokenClaims, AuthError> {
        let claims = self.authenticate_access_token(token)?;
        if claims
            .permissions
            .iter()
            .any(|permission| permission == required_permission || permission == "*")
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

    /// Register the standard auth and RBAC JSON-RPC methods.
    ///
    /// The JSON-RPC-2 transport context currently has no authorization-header
    /// field. Protected methods therefore accept either `access_token` or
    /// `authorization: "Bearer …"` in their params. Applications can instead
    /// validate a transport-level bearer token with [`Self::require_permission`].
    pub fn register_rpc_methods(
        &self,
        server: &json_rpc_2_server::RpcServer,
    ) -> Result<(), json_rpc_2_server::RegistrationError> {
        let service = self.clone();
        server.register("auth.register", move |params| {
            let service = service.clone();
            async move {
                let request = parse_params(params)?;
                let user = service
                    .handle_register(request)
                    .await
                    .map_err(AuthError::into_rpc_error)?;
                to_value(user)
            }
        })?;

        let service = self.clone();
        server.register("auth.login", move |params| {
            let service = service.clone();
            async move {
                let request = parse_params(params)?;
                let token = service
                    .handle_login(request)
                    .await
                    .map_err(AuthError::into_rpc_error)?;
                to_value(token)
            }
        })?;

        let service = self.clone();
        server.register("auth.refresh", move |params| {
            let service = service.clone();
            async move {
                let request: RefreshParams = parse_params(params)?;
                let tokens = service
                    .refresh_session(&request.refresh_token)
                    .await
                    .map_err(AuthError::into_rpc_error)?;
                to_value(tokens)
            }
        })?;

        let service = self.clone();
        server.register("auth.updateProfile", move |params| {
            let service = service.clone();
            async move {
                let request: AuthenticatedProfileParams = parse_params(params)?;
                let token = request.bearer_token().map_err(AuthError::into_rpc_error)?;
                let claims = service
                    .authenticate_access_token(&token)
                    .map_err(AuthError::into_rpc_error)?;
                let user = service
                    .handle_update_profile(claims.subject, request.profile)
                    .await
                    .map_err(AuthError::into_rpc_error)?;
                to_value(user)
            }
        })?;

        let service = self.clone();
        server.register("rbac.addRoleToUser", move |params| {
            let service = service.clone();
            async move {
                let request: RoleParams = parse_params(params)?;
                let token = request.bearer_token().map_err(AuthError::into_rpc_error)?;
                service
                    .require_permission(&token, "rbac.users.write")
                    .map_err(AuthError::into_rpc_error)?;
                service
                    .handle_add_role(request.user_id, request.role_name)
                    .await
                    .map_err(AuthError::into_rpc_error)?;
                Ok(Value::Null)
            }
        })?;

        let service = self.clone();
        server.register("rbac.removeRoleFromUser", move |params| {
            let service = service.clone();
            async move {
                let request: RoleParams = parse_params(params)?;
                let token = request.bearer_token().map_err(AuthError::into_rpc_error)?;
                service
                    .require_permission(&token, "rbac.users.write")
                    .map_err(AuthError::into_rpc_error)?;
                service
                    .handle_remove_role(request.user_id, request.role_name)
                    .await
                    .map_err(AuthError::into_rpc_error)?;
                Ok(Value::Null)
            }
        })?;

        let service = self.clone();
        server.register("rbac.addPermissionToRole", move |params| {
            let service = service.clone();
            async move {
                let request: PermissionParams = parse_params(params)?;
                let token = request.bearer_token().map_err(AuthError::into_rpc_error)?;
                service
                    .require_permission(&token, "rbac.roles.write")
                    .map_err(AuthError::into_rpc_error)?;
                service
                    .handle_add_permission(request.role_name, request.permission_name)
                    .await
                    .map_err(AuthError::into_rpc_error)?;
                Ok(Value::Null)
            }
        })?;

        let service = self.clone();
        server.register("rbac.removePermissionFromRole", move |params| {
            let service = service.clone();
            async move {
                let request: PermissionParams = parse_params(params)?;
                let token = request.bearer_token().map_err(AuthError::into_rpc_error)?;
                service
                    .require_permission(&token, "rbac.roles.write")
                    .map_err(AuthError::into_rpc_error)?;
                service
                    .handle_remove_permission(request.role_name, request.permission_name)
                    .await
                    .map_err(AuthError::into_rpc_error)?;
                Ok(Value::Null)
            }
        })?;
        Ok(())
    }

    async fn refresh_session(&self, refresh_token: &str) -> Result<TokenResponse, AuthError> {
        let subject = self.inner.tokens.verify_refresh_token(refresh_token)?;
        let user_id = parse_object_id(&subject)?;
        let database = self.database()?;
        let user = users(database)
            .find_one(doc! { "_id": user_id })
            .await?
            .ok_or(AuthError::Unauthorized)?;
        let roles = strings_from_document(&user, "roles")?;
        let permissions = self.permissions_for_roles(&roles).await?;
        self.inner
            .tokens
            .refresh_pair(refresh_token, &roles, &permissions)
    }

    async fn permissions_for_roles(&self, role_names: &[String]) -> Result<Vec<String>, AuthError> {
        if role_names.is_empty() {
            return Ok(Vec::new());
        }
        let mut cursor = self
            .database()?
            .collection::<Document>(ROLES)
            .find(doc! { "name": { "$in": role_names } })
            .await?;
        let mut permissions = HashSet::new();
        while cursor.advance().await? {
            let role = cursor.deserialize_current()?;
            permissions.extend(strings_from_document(&role, "permissions")?);
        }
        let mut permissions: Vec<_> = permissions.into_iter().collect();
        permissions.sort();
        Ok(permissions)
    }

    fn database(&self) -> Result<&Database, AuthError> {
        self.inner
            .database
            .get()
            .ok_or(AuthError::StorageNotInitialized)
    }

    fn schema(&self) -> HashMap<String, ProfileFieldType> {
        self.inner
            .profile_schema
            .read()
            .expect("schema lock poisoned")
            .clone()
    }

    async fn user_response(&self, user: Document) -> Result<UserResponse, AuthError> {
        let object_id = user.get_object_id("_id").map_err(|_| {
            AuthError::InvalidConfiguration("stored user has no valid ObjectId".to_owned())
        })?;
        let email = user
            .get_str("email")
            .map_err(|_| AuthError::InvalidConfiguration("stored user has no email".to_owned()))?
            .to_owned();
        let created_at = user
            .get_datetime("created_at")
            .map_err(|_| {
                AuthError::InvalidConfiguration("stored user has no creation time".to_owned())
            })?
            .timestamp_millis();
        let created_at = chrono::DateTime::from_timestamp_millis(created_at)
            .ok_or_else(|| {
                AuthError::InvalidConfiguration("stored creation time is out of range".to_owned())
            })?
            .to_rfc3339();
        let roles = strings_from_document(&user, "roles")?;
        let profile = user.get_document("profile").cloned().unwrap_or_default();
        Ok(UserResponse {
            id: object_id.to_hex(),
            email,
            created_at,
            roles,
            profile: profile_to_json(&self.schema(), profile)?,
        })
    }
}

#[async_trait]
impl JsonRpcAuthServer for MongoAuthServer {
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
        if self.inner.database.get().is_some() {
            return Ok(());
        }
        let config = self.get_db_config();
        if config.host.trim().is_empty() || config.database_name.trim().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "MongoDB host and database name are required".to_owned(),
            ));
        }
        let uri = if config.host.contains("://") {
            config.host.clone()
        } else {
            format!("mongodb://{}", config.host)
        };
        let mut options = ClientOptions::parse(&uri).await?;
        if config.db_user.is_some() || config.db_password.is_some() {
            let username = config.db_user.ok_or_else(|| {
                AuthError::InvalidConfiguration(
                    "MongoDB username and password must be configured together".to_owned(),
                )
            })?;
            let password = config.db_password.ok_or_else(|| {
                AuthError::InvalidConfiguration(
                    "MongoDB username and password must be configured together".to_owned(),
                )
            })?;
            let credential = options
                .credential
                .get_or_insert_with(|| Credential::builder().build());
            credential.username = Some(username);
            credential.password = Some(password);
        }
        let client = Client::with_options(options)?;
        let database = client.database(&config.database_name);
        database.run_command(doc! { "ping": 1 }).await?;

        users(&database)
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "email": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
            )
            .await?;
        database
            .collection::<Document>("external_identities")
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "provider": 1, "subject": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
            )
            .await?;
        database
            .collection::<Document>(ROLES)
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "name": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
            )
            .await?;
        let _ = self.inner.database.set(database);
        Ok(())
    }

    fn authenticate_access_token(&self, token: &str) -> Result<AccessTokenClaims, AuthError> {
        MongoAuthServer::authenticate_access_token(self, token)
    }

    fn require_permission(
        &self,
        token: &str,
        permission: &str,
    ) -> Result<AccessTokenClaims, AuthError> {
        MongoAuthServer::require_permission(self, token, permission)
    }

    async fn handle_refresh(
        &self,
        refresh_token: &str,
    ) -> Result<TokenResponse, Self::StorageError> {
        self.refresh_session(refresh_token).await
    }

    async fn handle_register(
        &self,
        req: RegisterRequest,
    ) -> Result<UserResponse, Self::StorageError> {
        let email = normalize_email(&req.email)?;
        validate_password(&req.password)?;
        let users = users(self.database()?);
        if users.find_one(doc! { "email": &email }).await?.is_some() {
            return Err(AuthError::DuplicateEmail);
        }

        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(req.password.as_bytes(), &salt)
            .map_err(|error| AuthError::PasswordHash(error.to_string()))?
            .to_string();
        let profile = parse_profile(&self.schema(), &req.profile)?;
        let user = doc! {
            "email": email,
            "password_hash": password_hash,
            "created_at": DateTime::now(),
            "roles": Vec::<String>::new(),
            "profile": profile,
        };
        let mut response = user.clone();
        let result = users.insert_one(user).await?;
        response.insert("_id", result.inserted_id);
        self.user_response(response).await
    }

    async fn handle_login(&self, req: LoginRequest) -> Result<TokenResponse, Self::StorageError> {
        if req.grant_type != "password" {
            return Err(AuthError::InvalidParams(
                "grant_type must be `password`".to_owned(),
            ));
        }
        let email = normalize_email(&req.email)?;
        let user = users(self.database()?)
            .find_one(doc! { "email": email })
            .await?
            .ok_or(AuthError::Unauthorized)?;
        let stored_hash = user.get_str("password_hash").map_err(|_| {
            AuthError::InvalidConfiguration("stored user has no password hash".to_owned())
        })?;
        let parsed_hash = PasswordHash::new(stored_hash).map_err(|_| AuthError::Unauthorized)?;
        Argon2::default()
            .verify_password(req.password.as_bytes(), &parsed_hash)
            .map_err(|_| AuthError::Unauthorized)?;

        let subject = user
            .get_object_id("_id")
            .map_err(|_| {
                AuthError::InvalidConfiguration("stored user has no valid ObjectId".to_owned())
            })?
            .to_hex();
        let roles = strings_from_document(&user, "roles")?;
        let permissions = self.permissions_for_roles(&roles).await?;
        self.inner.tokens.issue_pair(&subject, &roles, &permissions)
    }

    async fn handle_external_login(
        &self,
        identity: ExternalIdentity,
    ) -> Result<TokenResponse, AuthError> {
        if identity.subject.trim().is_empty() {
            return Err(AuthError::Unauthorized);
        }
        let database = self.database()?;
        let identities = database.collection::<Document>("external_identities");
        let provider = identity.provider.storage_key();
        let linked = identities
            .find_one(doc! { "provider": provider, "subject": &identity.subject })
            .await?;

        let user_id = if let Some(linked) = linked {
            linked
                .get_object_id("user_id")
                .map_err(|_| AuthError::Unauthorized)?
        } else {
            if !identity.email_verified {
                return Err(AuthError::Unauthorized);
            }
            let email = identity.email.as_deref().ok_or(AuthError::Unauthorized)?;
            let mut password = uuid::Uuid::new_v4().to_string();
            password.push_str(&uuid::Uuid::new_v4().to_string());
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
            let object_id = parse_object_id(&user.id)?;
            if let Err(error) = identities
                .insert_one(doc! {
                    "provider": provider,
                    "subject": &identity.subject,
                    "user_id": object_id,
                })
                .await
            {
                let _ = users(database).delete_one(doc! { "_id": object_id }).await;
                return Err(if error.to_string().contains("E11000") {
                    AuthError::Unauthorized
                } else {
                    AuthError::from(error)
                });
            }
            object_id
        };
        let user = users(database)
            .find_one(doc! { "_id": user_id })
            .await?
            .ok_or(AuthError::Unauthorized)?;
        let subject = user_id.to_hex();
        let roles = strings_from_document(&user, "roles")?;
        let permissions = self.permissions_for_roles(&roles).await?;
        self.inner.tokens.issue_pair(&subject, &roles, &permissions)
    }

    async fn link_external_identity(
        &self,
        user_id: String,
        identity: ExternalIdentity,
    ) -> Result<(), AuthError> {
        if identity.subject.trim().is_empty() {
            return Err(AuthError::Unauthorized);
        }
        let object_id = parse_object_id(&user_id)?;
        let database = self.database()?;
        if users(database)
            .find_one(doc! { "_id": object_id })
            .await?
            .is_none()
        {
            return Err(AuthError::InvalidParams("user not found".to_owned()));
        }
        database
            .collection::<Document>("external_identities")
            .insert_one(doc! {
                "provider": identity.provider.storage_key(),
                "subject": identity.subject,
                "user_id": object_id,
            })
            .await
            .map_err(|error| {
                if error.to_string().contains("E11000") {
                    AuthError::AccountLinkRequired
                } else {
                    AuthError::from(error)
                }
            })?;
        Ok(())
    }

    async fn handle_update_profile(
        &self,
        user_id: String,
        profile_data: HashMap<String, String>,
    ) -> Result<UserResponse, Self::StorageError> {
        let object_id = parse_object_id(&user_id)?;
        let profile = parse_profile(&self.schema(), &profile_data)?;
        if !profile.is_empty() {
            let updates = profile
                .into_iter()
                .map(|(key, value)| (format!("profile.{key}"), value))
                .collect::<Document>();
            let result = users(self.database()?)
                .update_one(doc! { "_id": object_id }, doc! { "$set": updates })
                .await?;
            if result.matched_count == 0 {
                return Err(AuthError::InvalidParams("user not found".to_owned()));
            }
        }
        let user = users(self.database()?)
            .find_one(doc! { "_id": object_id })
            .await?
            .ok_or_else(|| AuthError::InvalidParams("user not found".to_owned()))?;
        self.user_response(user).await
    }

    async fn handle_add_role(
        &self,
        user_id: String,
        role_name: String,
    ) -> Result<(), Self::StorageError> {
        validate_name("role", &role_name)?;
        let object_id = parse_object_id(&user_id)?;
        let database = self.database()?;
        database
            .collection::<Document>(ROLES)
            .update_one(
                doc! { "name": &role_name },
                doc! { "$setOnInsert": { "name": &role_name, "permissions": [] } },
            )
            .upsert(true)
            .await?;
        let result = users(database)
            .update_one(
                doc! { "_id": object_id },
                doc! { "$addToSet": { "roles": role_name } },
            )
            .await?;
        if result.matched_count == 0 {
            return Err(AuthError::InvalidParams("user not found".to_owned()));
        }
        Ok(())
    }

    async fn handle_remove_role(
        &self,
        user_id: String,
        role_name: String,
    ) -> Result<(), Self::StorageError> {
        let object_id = parse_object_id(&user_id)?;
        let result = users(self.database()?)
            .update_one(
                doc! { "_id": object_id },
                doc! { "$pull": { "roles": role_name } },
            )
            .await?;
        if result.matched_count == 0 {
            return Err(AuthError::InvalidParams("user not found".to_owned()));
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
        self.database()?
            .collection::<Document>(ROLES)
            .update_one(
                doc! { "name": &role_name },
                doc! {
                    "$setOnInsert": { "name": &role_name },
                    "$addToSet": { "permissions": permission_name },
                },
            )
            .upsert(true)
            .await?;
        Ok(())
    }

    async fn handle_remove_permission(
        &self,
        role_name: String,
        permission_name: String,
    ) -> Result<(), Self::StorageError> {
        self.database()?
            .collection::<Document>(ROLES)
            .update_one(
                doc! { "name": role_name },
                doc! { "$pull": { "permissions": permission_name } },
            )
            .await?;
        Ok(())
    }
}

fn users(database: &Database) -> Collection<Document> {
    database.collection(USERS)
}

fn parse_object_id(value: &str) -> Result<ObjectId, AuthError> {
    ObjectId::parse_str(value)
        .map_err(|_| AuthError::InvalidParams("user_id must be a MongoDB ObjectId".to_owned()))
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

fn validate_password(password: &str) -> Result<(), AuthError> {
    if password.chars().count() < 8 {
        return Err(AuthError::InvalidParams(
            "password must contain at least 8 characters".to_owned(),
        ));
    }
    Ok(())
}

fn valid_field_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn validate_name(kind: &str, name: &str) -> Result<(), AuthError> {
    if name.trim().is_empty() || name.len() > 128 || name.starts_with("system.") {
        return Err(AuthError::InvalidParams(format!("invalid {kind} name")));
    }
    Ok(())
}

fn strings_from_document(document: &Document, key: &str) -> Result<Vec<String>, AuthError> {
    match document.get(key) {
        None => Ok(Vec::new()),
        Some(Bson::Array(values)) => values
            .iter()
            .map(|value| {
                value.as_str().map(str::to_owned).ok_or_else(|| {
                    AuthError::InvalidConfiguration(format!("stored `{key}` value is not text"))
                })
            })
            .collect(),
        _ => Err(AuthError::InvalidConfiguration(format!(
            "stored `{key}` field is not an array"
        ))),
    }
}

fn parse_params<T: DeserializeOwned>(params: Value) -> Result<T, json_rpc_2_server::RpcError> {
    serde_json::from_value(params).map_err(|_| json_rpc_2_server::RpcError::invalid_params())
}

fn to_value<T: Serialize>(value: T) -> Result<Value, json_rpc_2_server::RpcError> {
    serde_json::to_value(value).map_err(|_| json_rpc_2_server::RpcError::internal_error())
}

#[derive(Deserialize)]
struct RefreshParams {
    refresh_token: String,
}

#[derive(Deserialize)]
struct AuthenticatedParams {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    authorization: Option<String>,
}

impl AuthenticatedParams {
    fn bearer_token(&self) -> Result<String, AuthError> {
        let value = self
            .access_token
            .as_deref()
            .or(self.authorization.as_deref())
            .ok_or(AuthError::Unauthorized)?;
        Ok(value.strip_prefix("Bearer ").unwrap_or(value).to_owned())
    }
}

#[derive(Deserialize)]
struct AuthenticatedProfileParams {
    #[serde(flatten)]
    auth: AuthenticatedParams,
    profile: HashMap<String, String>,
}

impl AuthenticatedProfileParams {
    fn bearer_token(&self) -> Result<String, AuthError> {
        self.auth.bearer_token()
    }
}

#[derive(Deserialize)]
struct RoleParams {
    #[serde(flatten)]
    auth: AuthenticatedParams,
    user_id: String,
    role_name: String,
}

impl RoleParams {
    fn bearer_token(&self) -> Result<String, AuthError> {
        self.auth.bearer_token()
    }
}

#[derive(Deserialize)]
struct PermissionParams {
    #[serde(flatten)]
    auth: AuthenticatedParams,
    role_name: String,
    permission_name: String,
}

impl PermissionParams {
    fn bearer_token(&self) -> Result<String, AuthError> {
        self.auth.bearer_token()
    }
}
