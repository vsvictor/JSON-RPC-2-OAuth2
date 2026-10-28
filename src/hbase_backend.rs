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
use hbase_thrift::hbase::{ColumnDescriptor, HbaseSyncClient, Mutation, THbaseSyncClient};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, RwLock},
};
use thrift::{
    protocol::{TBinaryInputProtocol, TBinaryOutputProtocol},
    transport::{TBufferedReadTransport, TBufferedWriteTransport, TIoChannel, TTcpChannel},
};

struct Inner {
    config: RwLock<DbConfig>,
    profile_schema: RwLock<HashMap<String, ProfileFieldType>>,
    tokens: TokenService,
}

#[derive(Clone)]
pub struct HbaseAuthServer {
    inner: Arc<Inner>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredUser {
    id: String,
    email: String,
    password_hash: String,
    created_at: String,
}

impl HbaseAuthServer {
    /// Create an HBase authentication service using a PASERK-encoded v4.local key.
    pub fn new(paserk_key: &str, token_config: TokenConfig) -> Result<Self, AuthError> {
        Ok(Self {
            inner: Arc::new(Inner {
                config: RwLock::new(DbConfig::default()),
                profile_schema: RwLock::new(HashMap::new()),
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

    fn tables(&self) -> Result<Tables, AuthError> {
        let name = self.config().database_name;
        if !valid_identifier(&name) || name.len() > 80 {
            return Err(AuthError::InvalidConfiguration(
                "HBase database_name must be an identifier of at most 80 characters".to_owned(),
            ));
        }
        Ok(Tables {
            users: format!("auth_{name}_users").into_bytes(),
            emails: format!("auth_{name}_emails").into_bytes(),
            user_roles: format!("auth_{name}_user_roles").into_bytes(),
            role_permissions: format!("auth_{name}_role_permissions").into_bytes(),
            external_identities: format!("auth_{name}_external_identities").into_bytes(),
        })
    }

    async fn call<T, F>(&self, operation: F) -> Result<T, AuthError>
    where
        T: Send + 'static,
        F: FnOnce(&mut dyn THbaseSyncClient) -> thrift::Result<T> + Send + 'static,
    {
        let host = self.config().host;
        if host.trim().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "HBase Thrift host is required".to_owned(),
            ));
        }
        tokio::task::spawn_blocking(move || {
            let mut channel = TTcpChannel::new();
            channel.open(host.trim())?;
            let (input, output) = channel.split()?;
            let input = TBinaryInputProtocol::new(TBufferedReadTransport::new(input), true);
            let output = TBinaryOutputProtocol::new(TBufferedWriteTransport::new(output), true);
            let mut client = HbaseSyncClient::new(input, output);
            operation(&mut client)
        })
        .await
        .map_err(hbase_error)?
        .map_err(hbase_error)
    }

    async fn get_user_row(&self, id: &str) -> Result<HashMap<String, Vec<u8>>, AuthError> {
        let table = self.tables()?.users;
        let row = id.as_bytes().to_vec();
        self.call(move |client| get_row(client, table, row)).await
    }

    async fn read_fields(
        &self,
        table: Vec<u8>,
        row: Vec<u8>,
    ) -> Result<HashMap<String, Vec<u8>>, AuthError> {
        self.call(move |client| get_row(client, table, row)).await
    }

    async fn roles_for_user(&self, id: &str) -> Result<Vec<String>, AuthError> {
        let fields = self
            .read_fields(self.tables()?.user_roles, id.as_bytes().to_vec())
            .await?;
        let mut roles = fields
            .keys()
            .filter_map(|column| column.strip_prefix("auth:role:").map(str::to_owned))
            .collect::<Vec<_>>();
        roles.sort();
        Ok(roles)
    }

    async fn permissions_for_roles(&self, roles: &[String]) -> Result<Vec<String>, AuthError> {
        let table = self.tables()?.role_permissions;
        let mut permissions = Vec::new();
        for role in roles {
            let fields = self
                .read_fields(table.clone(), role.as_bytes().to_vec())
                .await?;
            permissions.extend(
                fields.keys().filter_map(|column| {
                    column.strip_prefix("auth:permission:").map(str::to_owned)
                }),
            );
        }
        permissions.sort();
        permissions.dedup();
        Ok(permissions)
    }

    async fn load_user(&self, id: &str) -> Result<UserResponse, AuthError> {
        let fields = self.get_user_row(id).await?;
        let required = |name: &str| {
            fields
                .get(&format!("auth:{name}"))
                .ok_or_else(|| AuthError::InvalidParams("user not found".to_owned()))
        };
        let email = decode(required("email")?)?;
        let created_at = decode(required("created_at")?)?;
        let profile_json = decode(required("profile_json")?)?;
        let profile = serde_json::from_str(&profile_json)?;
        Ok(UserResponse {
            id: id.to_owned(),
            email,
            created_at,
            roles: self.roles_for_user(id).await?,
            profile,
        })
    }

    async fn remove_registered_user(&self, id: &str, email: &str) -> Result<(), AuthError> {
        let tables = self.tables()?;
        let user_table = tables.users;
        let user_row = id.as_bytes().to_vec();
        self.call(move |client| client.delete_all_row(user_table, user_row, BTreeMap::new()))
            .await?;
        let email_table = tables.emails;
        let email_row = email.as_bytes().to_vec();
        self.call(move |client| client.delete_all_row(email_table, email_row, BTreeMap::new()))
            .await
    }
}

struct Tables {
    users: Vec<u8>,
    emails: Vec<u8>,
    user_roles: Vec<u8>,
    role_permissions: Vec<u8>,
    external_identities: Vec<u8>,
}

#[async_trait]
impl JsonRpcAuthServer for HbaseAuthServer {
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
        let _ = self.set_profile_schema(schema);
    }

    fn get_profile_schema(&self) -> HashMap<String, ProfileFieldType> {
        self.schema()
    }

    async fn initialize_storage(&self) -> Result<(), Self::StorageError> {
        if self.config().db_user.is_some() || self.config().db_password.is_some() {
            return Err(AuthError::InvalidConfiguration(
                "the HBase Thrift v1 backend does not support database credentials".to_owned(),
            ));
        }
        let tables = self.tables()?;
        self.call(move |client| {
            let existing = client.get_table_names()?.into_iter().collect::<Vec<_>>();
            for table in [
                tables.users,
                tables.emails,
                tables.user_roles,
                tables.role_permissions,
                tables.external_identities,
            ] {
                if !existing.contains(&table) {
                    client.create_table(
                        table,
                        vec![ColumnDescriptor::new(
                            b"auth:".to_vec(),
                            1,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                        )],
                    )?;
                }
            }
            Ok(())
        })
        .await
    }

    fn authenticate_access_token(&self, token: &str) -> Result<AccessTokenClaims, AuthError> {
        HbaseAuthServer::authenticate_access_token(self, token)
    }

    fn require_permission(
        &self,
        token: &str,
        permission: &str,
    ) -> Result<AccessTokenClaims, AuthError> {
        HbaseAuthServer::require_permission(self, token, permission)
    }

    async fn handle_refresh(
        &self,
        refresh_token: &str,
    ) -> Result<TokenResponse, Self::StorageError> {
        let subject = self.inner.tokens.verify_refresh_token(refresh_token)?;
        self.load_user(&subject).await?;
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
        let tables = self.tables()?;
        let email_row = email.as_bytes().to_vec();
        let reservation_table = tables.emails.clone();
        let reservation = self
            .call(move |client| {
                client.atomic_increment(
                    reservation_table,
                    email_row,
                    b"auth:reservation".to_vec(),
                    1,
                )
            })
            .await?;
        if reservation != 1 {
            return Err(AuthError::DuplicateEmail);
        }
        let user_id = user.id.clone();
        let user_json = serde_json::to_string(&profile)?;
        let user_table = tables.users.clone();
        let user_row = user.id.as_bytes().to_vec();
        let user_fields = vec![
            ("auth:id", user.id.as_bytes().to_vec()),
            ("auth:email", user.email.as_bytes().to_vec()),
            ("auth:password_hash", user.password_hash.as_bytes().to_vec()),
            ("auth:created_at", user.created_at.as_bytes().to_vec()),
            ("auth:profile_json", user_json.into_bytes()),
        ];
        let write_user = self
            .call(move |client| put_fields(client, user_table, user_row, user_fields))
            .await;
        if let Err(error) = write_user {
            let email_table = tables.emails.clone();
            let email_row = email.as_bytes().to_vec();
            let _ = self
                .call(move |client| client.delete_all_row(email_table, email_row, BTreeMap::new()))
                .await;
            return Err(error);
        }
        let email_table = tables.emails;
        let email_row = email.as_bytes().to_vec();
        let index_value = user_id.as_bytes().to_vec();
        if let Err(error) = self
            .call(move |client| {
                put_fields(
                    client,
                    email_table,
                    email_row,
                    vec![("auth:id", index_value)],
                )
            })
            .await
        {
            let users = tables.users;
            let user_row = user_id.as_bytes().to_vec();
            let _ = self
                .call(move |client| client.delete_all_row(users, user_row, BTreeMap::new()))
                .await;
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
        let email_table = self.tables()?.emails;
        let index = self
            .read_fields(email_table, email.as_bytes().to_vec())
            .await?;
        let id = decode(index.get("auth:id").ok_or(AuthError::Unauthorized)?)?;
        let fields = self.get_user_row(&id).await?;
        let hash = decode(
            fields
                .get("auth:password_hash")
                .ok_or(AuthError::Unauthorized)?,
        )?;
        let parsed = PasswordHash::new(&hash).map_err(|_| AuthError::Unauthorized)?;
        Argon2::default()
            .verify_password(req.password.as_bytes(), &parsed)
            .map_err(|_| AuthError::Unauthorized)?;
        let roles = self.roles_for_user(&id).await?;
        let permissions = self.permissions_for_roles(&roles).await?;
        self.inner.tokens.issue_pair(&id, &roles, &permissions)
    }

    async fn handle_external_login(
        &self,
        identity: ExternalIdentity,
    ) -> Result<TokenResponse, AuthError> {
        if identity.subject.trim().is_empty() || identity.subject.len() > 512 {
            return Err(AuthError::Unauthorized);
        }
        let tables = self.tables()?;
        let row = external_identity_row(identity.provider.storage_key(), &identity.subject);
        let identity_fields = self
            .read_fields(tables.external_identities.clone(), row.clone())
            .await?;
        let user_id = if let Some(user_id) = identity_fields.get("auth:id") {
            decode(user_id)?
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
            let reservation_table = tables.external_identities.clone();
            let reservation_row = row.clone();
            let reserved = self
                .call(move |client| {
                    client.atomic_increment(
                        reservation_table,
                        reservation_row,
                        b"auth:reservation".to_vec(),
                        1,
                    )
                })
                .await?;
            if reserved != 1 {
                self.remove_registered_user(&user.id, &email).await?;
                return Err(AuthError::Unauthorized);
            }
            let identity_table = tables.external_identities;
            let identity_row = row;
            let id_bytes = user.id.as_bytes().to_vec();
            if let Err(error) = self
                .call(move |client| {
                    put_fields(
                        client,
                        identity_table,
                        identity_row,
                        vec![("auth:id", id_bytes)],
                    )
                })
                .await
            {
                self.remove_registered_user(&user.id, &email).await?;
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
        if identity.subject.trim().is_empty() || identity.subject.len() > 512 {
            return Err(AuthError::Unauthorized);
        }
        self.load_user(&user_id).await?;
        let tables = self.tables()?;
        let row = external_identity_row(identity.provider.storage_key(), &identity.subject);
        let reservation_table = tables.external_identities.clone();
        let reservation_row = row.clone();
        let reserved = self
            .call(move |client| {
                client.atomic_increment(
                    reservation_table,
                    reservation_row,
                    b"auth:reservation".to_vec(),
                    1,
                )
            })
            .await?;
        if reserved != 1 {
            return Err(AuthError::AccountLinkRequired);
        }
        let table = tables.external_identities;
        let id = user_id.into_bytes();
        self.call(move |client| put_fields(client, table, row, vec![("auth:id", id)]))
            .await
    }

    async fn handle_update_profile(
        &self,
        user_id: String,
        profile_data: HashMap<String, String>,
    ) -> Result<UserResponse, Self::StorageError> {
        let updates = crate::profile_values::parse_profile(&self.schema(), &profile_data)?;
        let mut fields = self.get_user_row(&user_id).await?;
        if fields.is_empty() {
            return Err(AuthError::InvalidParams("user not found".to_owned()));
        }
        let current = fields
            .remove("auth:profile_json")
            .ok_or_else(|| AuthError::InvalidParams("user not found".to_owned()))?;
        let mut profile: HashMap<String, Value> = serde_json::from_slice(&current)?;
        profile.extend(updates);
        let value = serde_json::to_vec(&profile)?;
        let table = self.tables()?.users;
        let row = user_id.as_bytes().to_vec();
        self.call(move |client| put_fields(client, table, row, vec![("auth:profile_json", value)]))
            .await?;
        self.load_user(&user_id).await
    }

    async fn handle_add_role(
        &self,
        user_id: String,
        role_name: String,
    ) -> Result<(), Self::StorageError> {
        validate_name("role", &role_name)?;
        if self.get_user_row(&user_id).await?.is_empty() {
            return Err(AuthError::InvalidParams("user not found".to_owned()));
        }
        let table = self.tables()?.user_roles;
        let row = user_id.into_bytes();
        self.call(move |client| {
            put_fields(
                client,
                table,
                row,
                vec![(format!("auth:role:{role_name}"), b"1".to_vec())],
            )
        })
        .await
    }

    async fn handle_remove_role(
        &self,
        user_id: String,
        role_name: String,
    ) -> Result<(), Self::StorageError> {
        let table = self.tables()?.user_roles;
        let column = format!("auth:role:{role_name}");
        let row = user_id.into_bytes();
        let exists = self
            .call({
                let table = table.clone();
                let row = row.clone();
                let column = column.clone();
                move |client| {
                    Ok(!client
                        .get(table, row, column.into_bytes(), BTreeMap::new())?
                        .is_empty())
                }
            })
            .await?;
        if !exists {
            return Err(AuthError::InvalidParams(
                "user role assignment not found".to_owned(),
            ));
        }
        self.call(move |client| {
            client.mutate_row(
                table,
                row,
                vec![Mutation::new(
                    true,
                    column.into_bytes(),
                    Vec::<u8>::new(),
                    true,
                )],
                BTreeMap::new(),
            )
        })
        .await
    }

    async fn handle_add_permission(
        &self,
        role_name: String,
        permission_name: String,
    ) -> Result<(), Self::StorageError> {
        validate_name("role", &role_name)?;
        validate_name("permission", &permission_name)?;
        let table = self.tables()?.role_permissions;
        let row = role_name.into_bytes();
        self.call(move |client| {
            put_fields(
                client,
                table,
                row,
                vec![(format!("auth:permission:{permission_name}"), b"1".to_vec())],
            )
        })
        .await
    }

    async fn handle_remove_permission(
        &self,
        role_name: String,
        permission_name: String,
    ) -> Result<(), Self::StorageError> {
        let table = self.tables()?.role_permissions;
        let row = role_name.into_bytes();
        let column = format!("auth:permission:{permission_name}");
        let exists = self
            .call({
                let table = table.clone();
                let row = row.clone();
                let column = column.clone();
                move |client| {
                    Ok(!client
                        .get(table, row, column.into_bytes(), BTreeMap::new())?
                        .is_empty())
                }
            })
            .await?;
        if !exists {
            return Err(AuthError::InvalidParams(
                "role permission assignment not found".to_owned(),
            ));
        }
        self.call(move |client| {
            client.mutate_row(
                table,
                row,
                vec![Mutation::new(
                    true,
                    column.into_bytes(),
                    Vec::<u8>::new(),
                    true,
                )],
                BTreeMap::new(),
            )
        })
        .await
    }
}

fn get_row(
    client: &mut dyn THbaseSyncClient,
    table: Vec<u8>,
    row: Vec<u8>,
) -> thrift::Result<HashMap<String, Vec<u8>>> {
    let rows = client.get_row(table, row, BTreeMap::new())?;
    let mut fields = HashMap::new();
    for row in rows {
        if let Some(columns) = row.columns {
            for (name, cell) in columns {
                if let (Ok(name), Some(value)) = (String::from_utf8(name), cell.value) {
                    fields.insert(name, value);
                }
            }
        }
    }
    Ok(fields)
}

fn put_fields(
    client: &mut dyn THbaseSyncClient,
    table: Vec<u8>,
    row: Vec<u8>,
    fields: Vec<(impl Into<String>, Vec<u8>)>,
) -> thrift::Result<()> {
    let mutations = fields
        .into_iter()
        .map(|(column, value)| Mutation::new(false, column.into().into_bytes(), value, true))
        .collect();
    client.mutate_row(table, row, mutations, BTreeMap::new())
}

fn decode(value: &[u8]) -> Result<String, AuthError> {
    String::from_utf8(value.to_vec())
        .map_err(|error| AuthError::Hbase(format!("invalid UTF-8 data: {error}")))
}

fn external_identity_row(provider: &str, subject: &str) -> Vec<u8> {
    format!("{provider}:{subject}").into_bytes()
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

fn hbase_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::Hbase(error.to_string())
}
