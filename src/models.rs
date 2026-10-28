use crate::AuthError;
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
    #[serde(default)]
    pub profile: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub grant_type: String,
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
