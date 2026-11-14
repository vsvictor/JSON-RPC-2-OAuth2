use crate::AuthError;
#[cfg(feature = "auth-storage-core")]
use crate::password::{fingerprint as password_fingerprint, hash_new_password};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, error::Error, fmt};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuth2Provider {
    Google,
    FirebaseAuthentication,
    Apple,
    Microsoft,
    Facebook,
    X,
    LinkedIn,
    Slack,
    GitHub,
    GitLab,
    Bitbucket,
    Discord,
    Twitch,
    Spotify,
    Auth0,
    Okta,
}

impl OAuth2Provider {
    #[cfg(feature = "auth-storage-core")]
    pub(crate) fn storage_key(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::FirebaseAuthentication => "firebase_authentication",
            Self::Apple => "apple",
            Self::Microsoft => "microsoft",
            Self::Facebook => "facebook",
            Self::X => "x",
            Self::LinkedIn => "linkedin",
            Self::Slack => "slack",
            Self::GitHub => "github",
            Self::GitLab => "gitlab",
            Self::Bitbucket => "bitbucket",
            Self::Discord => "discord",
            Self::Twitch => "twitch",
            Self::Spotify => "spotify",
            Self::Auth0 => "auth0",
            Self::Okta => "okta",
        }
    }
}

#[derive(Clone)]
pub struct ProviderAuthorization {
    pub authorization_url: String,
    pub state: String,
    pub pkce_verifier: String,
}

#[derive(Clone)]
pub struct ProviderAuthorizationRequest {
    pub provider: OAuth2Provider,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub issuer_url: Option<String>,
}

#[derive(Clone)]
pub struct ProviderCallbackRequest {
    pub provider: OAuth2Provider,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub code: String,
    pub state: String,
    pub expected_state: String,
    pub pkce_verifier: String,
    pub issuer_url: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ExternalIdentity {
    pub provider: OAuth2Provider,
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProfileFieldType {
    Text,
    Integer,
    Float,
    Boolean,
    DateTime,
    Blob,
    /// Validated array of [`crate::ProfileContact`]; built in as `contacts`.
    Contacts,
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct DbConfig {
    pub host: String,
    pub database_name: String,
    pub db_user: Option<String>,
    pub db_password: Option<String>,
}

impl fmt::Debug for DbConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DbConfig")
            .field("host", &self.host)
            .field("database_name", &self.database_name)
            .field("db_user", &self.db_user)
            .field(
                "db_password",
                &self.db_password.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    /// Scalar fields remain strings. JSON accepts a native `contacts` array;
    /// direct Rust callers supply its JSON encoding as the map's string value.
    #[serde(
        default,
        deserialize_with = "crate::contacts::deserialize_profile",
        serialize_with = "crate::contacts::serialize_profile"
    )]
    pub profile: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub grant_type: String,
}

/// Client device that opens a session. Every `(user, device)` pair is its own
/// session, so signing in to one account from two devices yields two sessions.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct DeviceInfo {
    #[serde(rename = "deviceId", alias = "device_id")]
    pub device_id: String,
    /// Operating system of the device, e.g. `{ "name": "iOS", "version": "18.2" }`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<OsInfo>,
}

/// Operating system name (`Android`, `iOS`, ...) and version of a device.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct OsInfo {
    pub name: String,
    pub version: String,
}

impl OsInfo {
    fn validate(&self) -> Result<(), AuthError> {
        let name_ok = (1..=32).contains(&self.name.len())
            && self
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-'));
        let version_ok = (1..=64).contains(&self.version.len())
            && self.version.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-' | '+' | '(' | ')')
            });
        if name_ok && version_ok {
            Ok(())
        } else {
            Err(AuthError::InvalidParams(
                "device.os.name (1-32) and device.os.version (1-64) contain unsupported characters"
                    .to_owned(),
            ))
        }
    }
}

impl DeviceInfo {
    const MAX_ID_LEN: usize = 128;

    /// Accepts 1..=128 characters from `[A-Za-z0-9._:-]` and a valid optional `os`.
    pub fn validate(&self) -> Result<(), AuthError> {
        let id = &self.device_id;
        let valid = !id.is_empty()
            && id.len() <= Self::MAX_ID_LEN
            && id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'));
        if !valid {
            return Err(AuthError::InvalidParams(
                "device.deviceId must be 1-128 characters of [A-Za-z0-9._:-]".to_owned(),
            ));
        }
        match &self.os {
            Some(os) => os.validate(),
            None => Ok(()),
        }
    }

    pub fn os_name(&self) -> Option<&str> {
        self.os.as_ref().map(|os| os.name.as_str())
    }

    pub fn os_version(&self) -> Option<&str> {
        self.os.as_ref().map(|os| os.version.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub created_at: String,
    pub roles: Vec<String>,
    pub profile: HashMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

#[async_trait]
pub trait JsonRpcAuthServer: Send + Sync {
    type StorageError: Error + Send + Sync + 'static;

    fn set_db_host(&mut self, host: &str);
    fn set_db_name(&mut self, name: &str);
    fn set_db_user(&mut self, user: &str);
    fn set_db_password(&mut self, password: &str);
    fn get_db_config(&self) -> DbConfig;

    fn define_profile_schema(&mut self, schema: HashMap<String, ProfileFieldType>);
    fn get_profile_schema(&self) -> HashMap<String, ProfileFieldType>;

    async fn initialize_storage(&self) -> Result<(), Self::StorageError>;
    #[cfg(feature = "oauth-provider-core")]
    async fn provider_authorization(
        &self,
        req: ProviderAuthorizationRequest,
    ) -> Result<ProviderAuthorization, AuthError> {
        crate::oauth2_providers::authorization(req).await
    }
    fn authenticate_access_token(
        &self,
        token: &str,
    ) -> Result<crate::AccessTokenClaims, crate::AuthError>;
    fn require_permission(
        &self,
        token: &str,
        permission: &str,
    ) -> Result<crate::AccessTokenClaims, crate::AuthError>;
    async fn handle_refresh(
        &self,
        refresh_token: &str,
    ) -> Result<TokenResponse, Self::StorageError>;
    async fn handle_register(
        &self,
        req: RegisterRequest,
    ) -> Result<UserResponse, Self::StorageError>;
    async fn handle_login(&self, req: LoginRequest) -> Result<TokenResponse, Self::StorageError>;

    /// Login that also records the signing-in device as a separate session.
    /// Backends without session storage ignore the device.
    async fn handle_login_with_device(
        &self,
        req: LoginRequest,
        device: Option<DeviceInfo>,
    ) -> Result<TokenResponse, Self::StorageError> {
        let _ = device;
        self.handle_login(req).await
    }

    /// Returns `(user_id, password_hash)` for a normalized e-mail address.
    async fn password_credentials_by_email(
        &self,
        email: &str,
    ) -> Result<Option<(String, String)>, AuthError> {
        let _ = email;
        Err(unsupported_password_reset())
    }
    async fn password_hash_for_user(&self, user_id: &str) -> Result<Option<String>, AuthError> {
        let _ = user_id;
        Err(unsupported_password_reset())
    }
    async fn store_password_hash(
        &self,
        user_id: &str,
        password_hash: &str,
    ) -> Result<(), AuthError> {
        let _ = (user_id, password_hash);
        Err(unsupported_password_reset())
    }
    fn issue_reset_token(&self, user_id: &str, fingerprint: &str) -> Result<String, AuthError> {
        let _ = (user_id, fingerprint);
        Err(unsupported_password_reset())
    }
    fn verify_reset_token(&self, token: &str) -> Result<(String, String), AuthError> {
        let _ = token;
        Err(unsupported_password_reset())
    }
    fn reset_code(
        &self,
        user_id: &str,
        fingerprint: &str,
        window: i64,
    ) -> Result<String, AuthError> {
        let _ = (user_id, fingerprint, window);
        Err(unsupported_password_reset())
    }

    /// Issues a single-use reset token. Returns `None` for unknown e-mails so
    /// callers can answer identically and never reveal which accounts exist.
    /// Returns `(email, reset_token, user_id, reset_code)`.
    async fn handle_request_password_reset(
        &self,
        email: &str,
    ) -> Result<Option<(String, String, String, String)>, AuthError> {
        let email = normalize_reset_email(email)?;
        let Some((user_id, hash)) = self.password_credentials_by_email(&email).await? else {
            return Ok(None);
        };
        let fingerprint = password_fingerprint(&hash);
        let token = self.issue_reset_token(&user_id, &fingerprint)?;
        let code = self.reset_code(&user_id, &fingerprint, reset_code_window(0))?;
        Ok(Some((email, token, user_id, code)))
    }

    /// Confirms a reset with the six-digit code e-mailed to `email`. The code
    /// is valid for 10 to 15 minutes and for a single password change.
    async fn handle_confirm_password_reset_with_code(
        &self,
        email: &str,
        code: &str,
        new_password: &str,
    ) -> Result<(), AuthError> {
        let email = normalize_reset_email(email)?;
        let (user_id, hash) = self
            .password_credentials_by_email(&email)
            .await?
            .ok_or(AuthError::Unauthorized)?;
        let fingerprint = password_fingerprint(&hash);
        let mut matched = false;
        for back in 0..RESET_CODE_WINDOWS {
            let expected = self.reset_code(&user_id, &fingerprint, reset_code_window(back))?;
            matched |= constant_time_eq(expected.as_bytes(), code.trim().as_bytes());
        }
        if !matched {
            return Err(AuthError::Unauthorized);
        }
        let new_hash = hash_new_password(new_password)?;
        self.store_password_hash(&user_id, &new_hash).await
    }

    async fn handle_confirm_password_reset(
        &self,
        reset_token: &str,
        new_password: &str,
    ) -> Result<(), AuthError> {
        let (user_id, expected) = self.verify_reset_token(reset_token)?;
        let current = self
            .password_hash_for_user(&user_id)
            .await?
            .ok_or(AuthError::Unauthorized)?;
        if password_fingerprint(&current) != expected {
            return Err(AuthError::Unauthorized);
        }
        let new_hash = hash_new_password(new_password)?;
        self.store_password_hash(&user_id, &new_hash).await
    }
    async fn handle_external_login(
        &self,
        identity: ExternalIdentity,
    ) -> Result<TokenResponse, AuthError>
    where
        Self: JsonRpcAuthServer<StorageError = AuthError>,
    {
        let _ = identity;
        Err(AuthError::InvalidConfiguration(
            "this storage backend does not implement external identity persistence".to_owned(),
        ))
    }
    async fn link_external_identity(
        &self,
        user_id: String,
        identity: ExternalIdentity,
    ) -> Result<(), AuthError>
    where
        Self: JsonRpcAuthServer<StorageError = AuthError>,
    {
        let _ = (user_id, identity);
        Err(AuthError::InvalidConfiguration(
            "this storage backend does not implement external identity linking".to_owned(),
        ))
    }

    #[cfg(feature = "oauth-provider-core")]
    async fn handle_provider_link(
        &self,
        user_id: String,
        req: ProviderCallbackRequest,
    ) -> Result<(), AuthError>
    where
        Self: JsonRpcAuthServer<StorageError = AuthError>,
    {
        let identity = crate::oauth2_providers::exchange_code(req).await?;
        self.link_external_identity(user_id, identity).await
    }

    #[cfg(feature = "oauth-provider-core")]
    async fn handle_firebase_id_token(
        &self,
        project_id: &str,
        id_token: &str,
    ) -> Result<TokenResponse, AuthError>
    where
        Self: JsonRpcAuthServer<StorageError = AuthError>,
    {
        let identity =
            crate::oauth2_providers::verify_firebase_id_token(id_token, project_id).await?;
        self.handle_external_login(identity).await
    }

    #[cfg(feature = "oauth-provider-core")]
    async fn link_firebase_id_token(
        &self,
        user_id: String,
        project_id: &str,
        id_token: &str,
    ) -> Result<(), AuthError>
    where
        Self: JsonRpcAuthServer<StorageError = AuthError>,
    {
        let identity =
            crate::oauth2_providers::verify_firebase_id_token(id_token, project_id).await?;
        self.link_external_identity(user_id, identity).await
    }

    #[cfg(feature = "oauth-provider-core")]
    async fn handle_provider_callback(
        &self,
        req: ProviderCallbackRequest,
    ) -> Result<TokenResponse, AuthError>
    where
        Self: JsonRpcAuthServer<StorageError = AuthError>,
    {
        let identity = crate::oauth2_providers::exchange_code(req).await?;
        self.handle_external_login(identity).await
    }
    async fn handle_get_profile(&self, user_id: String)
    -> Result<UserResponse, Self::StorageError>;
    async fn handle_update_profile(
        &self,
        user_id: String,
        profile_data: HashMap<String, String>,
    ) -> Result<UserResponse, Self::StorageError>;
    async fn handle_add_role(
        &self,
        user_id: String,
        role_name: String,
    ) -> Result<(), Self::StorageError>;
    async fn handle_remove_role(
        &self,
        user_id: String,
        role_name: String,
    ) -> Result<(), Self::StorageError>;
    async fn handle_add_permission(
        &self,
        role_name: String,
        permission_name: String,
    ) -> Result<(), Self::StorageError>;
    async fn handle_remove_permission(
        &self,
        role_name: String,
        permission_name: String,
    ) -> Result<(), Self::StorageError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_configuration_debug_output_redacts_password() {
        let config = DbConfig {
            db_password: Some("not-for-logs".to_owned()),
            ..DbConfig::default()
        };
        let debug = format!("{config:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("not-for-logs"));
    }
}

#[cfg(not(feature = "auth-storage-core"))]
fn password_fingerprint(_: &str) -> String {
    String::new()
}

#[cfg(not(feature = "auth-storage-core"))]
fn hash_new_password(_: &str) -> Result<String, AuthError> {
    Err(unsupported_password_reset())
}

fn unsupported_password_reset() -> AuthError {
    AuthError::InvalidConfiguration(
        "this storage backend does not implement password reset".to_owned(),
    )
}

const RESET_CODE_WINDOW_SECS: i64 = 300;
const RESET_CODE_WINDOWS: i64 = 3;

fn reset_code_window(back: i64) -> i64 {
    chrono::Utc::now().timestamp() / RESET_CODE_WINDOW_SECS - back
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn normalize_reset_email(email: &str) -> Result<String, AuthError> {
    let email = email.trim().to_ascii_lowercase();
    if email.is_empty() || email.len() > 254 || email.matches('@').count() != 1 {
        return Err(AuthError::InvalidParams("email is invalid".to_owned()));
    }
    Ok(email)
}
