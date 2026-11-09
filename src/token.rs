#[cfg(feature = "auth-storage-core")]
use crate::AuthError;
#[cfg(feature = "auth-storage-core")]
use crate::TokenResponse;
#[cfg(feature = "auth-storage-core")]
use pasetors::{
    Local,
    claims::{Claims, ClaimsValidationRules},
    keys::SymmetricKey,
    local,
    token::UntrustedToken,
    version4::V4,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
#[cfg(feature = "auth-storage-core")]
use std::{convert::TryFrom, sync::Arc};

#[cfg(feature = "auth-storage-core")]
const RESET_TOKEN_MINUTES: i64 = 15;

#[derive(Clone, Debug)]
pub struct TokenConfig {
    pub issuer: String,
    pub access_token_lifetime: Duration,
    pub refresh_token_lifetime: Duration,
}

impl TokenConfig {
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            access_token_lifetime: Duration::from_secs(15 * 60),
            refresh_token_lifetime: Duration::from_secs(30 * 24 * 60 * 60),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AccessTokenClaims {
    pub subject: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub expires_at: String,
}

#[cfg(feature = "auth-storage-core")]
#[derive(Clone)]
pub(crate) struct TokenService {
    key: Arc<SymmetricKey<V4>>,
    config: TokenConfig,
}

#[cfg(feature = "auth-storage-core")]
impl TokenService {
    pub(crate) fn new(key: &str, config: TokenConfig) -> Result<Self, AuthError> {
        if config.issuer.trim().is_empty()
            || config.access_token_lifetime.is_zero()
            || config.refresh_token_lifetime.is_zero()
        {
            return Err(AuthError::InvalidConfiguration(
                "issuer and token lifetimes must be non-empty and greater than zero".to_owned(),
            ));
        }
        let key = SymmetricKey::<V4>::try_from(key)
            .map_err(|error| AuthError::Token(error.to_string()))?;
        Ok(Self {
            key: Arc::new(key),
            config,
        })
    }

    pub(crate) fn issue_pair(
        &self,
        subject: &str,
        roles: &[String],
        permissions: &[String],
    ) -> Result<TokenResponse, AuthError> {
        self.issue_session_pair(subject, roles, permissions, None)
    }

    /// Like [`Self::issue_pair`], binding both tokens to a device session.
    pub(crate) fn issue_session_pair(
        &self,
        subject: &str,
        roles: &[String],
        permissions: &[String],
        session: Option<(&str, &str)>,
    ) -> Result<TokenResponse, AuthError> {
        let access_token = self.issue(
            subject,
            roles,
            permissions,
            "access",
            self.config.access_token_lifetime,
            session,
        )?;
        let refresh_token = self.issue(
            subject,
            roles,
            permissions,
            "refresh",
            self.config.refresh_token_lifetime,
            session,
        )?;
        Ok(TokenResponse {
            access_token,
            refresh_token,
            token_type: "Bearer".to_owned(),
            expires_in: self.config.access_token_lifetime.as_secs(),
        })
    }

    pub(crate) fn verify_access_token(&self, token: &str) -> Result<AccessTokenClaims, AuthError> {
        let claims = self.decrypt(token)?;
        let token_use = claims
            .get_claim("token_use")
            .and_then(serde_json::Value::as_str)
            .ok_or(AuthError::Unauthorized)?;
        if token_use != "access" {
            return Err(AuthError::Unauthorized);
        }
        let subject = claims
            .get_claim("sub")
            .and_then(serde_json::Value::as_str)
            .ok_or(AuthError::Unauthorized)?
            .to_owned();
        let roles = claim_strings(&claims, "roles")?;
        let permissions = claim_strings(&claims, "permissions")?;
        let expires_at = claims
            .get_claim("exp")
            .and_then(serde_json::Value::as_str)
            .ok_or(AuthError::Unauthorized)?
            .to_owned();
        Ok(AccessTokenClaims {
            subject,
            roles,
            permissions,
            expires_at,
        })
    }

    pub(crate) fn verify_refresh_token(&self, token: &str) -> Result<String, AuthError> {
        self.verify_refresh_session(token).map(|(subject, _)| subject)
    }

    /// Returns the subject and, for device sessions, `(session id, device id)`.
    pub(crate) fn verify_refresh_session(
        &self,
        token: &str,
    ) -> Result<(String, Option<(String, String)>), AuthError> {
        let claims = self.decrypt(token)?;
        let string_claim = |name: &str| {
            claims
                .get_claim(name)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        if string_claim("token_use").as_deref() != Some("refresh") {
            return Err(AuthError::Unauthorized);
        }
        let subject = string_claim("sub").ok_or(AuthError::Unauthorized)?;
        let session = match (string_claim("sid"), string_claim("device_id")) {
            (Some(sid), Some(device)) => Some((sid, device)),
            _ => None,
        };
        Ok((subject, session))
    }

    pub(crate) fn issue_reset_token(
        &self,
        subject: &str,
        password_fingerprint: &str,
    ) -> Result<String, AuthError> {
        let expires = chrono::Utc::now() + chrono::Duration::minutes(RESET_TOKEN_MINUTES);
        let mut claims = Claims::new().map_err(token_error)?;
        claims.issuer(&self.config.issuer).map_err(token_error)?;
        claims.subject(subject).map_err(token_error)?;
        claims
            .expiration(&expires.to_rfc3339())
            .map_err(token_error)?;
        claims
            .add_additional("token_use", "reset")
            .map_err(token_error)?;
        claims
            .add_additional("pwd", password_fingerprint)
            .map_err(token_error)?;
        local::encrypt(&self.key, &claims, None, None).map_err(token_error)
    }

    pub(crate) fn verify_reset_token(&self, token: &str) -> Result<(String, String), AuthError> {
        let claims = self.decrypt(token)?;
        let string_claim = |name: &str| {
            claims
                .get_claim(name)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or(AuthError::Unauthorized)
        };
        if string_claim("token_use")? != "reset" {
            return Err(AuthError::Unauthorized);
        }
        Ok((string_claim("sub")?, string_claim("pwd")?))
    }

    /// Six-digit reset code for a time window: HMAC-SHA256 over the user and
    /// the current password fingerprint, keyed by the token key. It is
    /// stateless, so every backend instance derives the same code, and it
    /// dies with the password change.
    pub(crate) fn reset_code(&self, user_id: &str, fingerprint: &str, window: i64) -> String {
        use sha2::{Digest, Sha256};
        let mut key = [0u8; 64];
        let secret = self.key.as_bytes();
        if secret.len() > 64 {
            key[..32].copy_from_slice(&Sha256::digest(secret));
        } else {
            key[..secret.len()].copy_from_slice(secret);
        }
        let mut inner = Sha256::new();
        inner.update(key.map(|byte| byte ^ 0x36));
        inner.update(b"reset-code\0");
        inner.update(user_id.as_bytes());
        inner.update([0]);
        inner.update(fingerprint.as_bytes());
        inner.update([0]);
        inner.update(window.to_be_bytes());
        let mut outer = Sha256::new();
        outer.update(key.map(|byte| byte ^ 0x5c));
        outer.update(inner.finalize());
        let digest = outer.finalize();
        let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
        format!("{:06}", value % 1_000_000)
    }

    pub(crate) fn refresh_pair(
        &self,
        token: &str,
        roles: &[String],
        permissions: &[String],
    ) -> Result<TokenResponse, AuthError> {
        let subject = self.verify_refresh_token(token)?;
        self.issue_pair(&subject, roles, permissions)
    }

    /// Re-issues a pair for an already verified device session.
    pub(crate) fn refresh_session_pair(
        &self,
        subject: &str,
        roles: &[String],
        permissions: &[String],
        session: Option<(&str, &str)>,
    ) -> Result<TokenResponse, AuthError> {
        self.issue_session_pair(subject, roles, permissions, session)
    }

    fn issue(
        &self,
        subject: &str,
        roles: &[String],
        permissions: &[String],
        token_use: &str,
        lifetime: Duration,
        session: Option<(&str, &str)>,
    ) -> Result<String, AuthError> {
        let expires = chrono::Utc::now()
            + chrono::Duration::from_std(lifetime).map_err(|error| {
                AuthError::InvalidConfiguration(format!("invalid token lifetime: {error}"))
            })?;
        let mut claims = Claims::new().map_err(token_error)?;
        claims.issuer(&self.config.issuer).map_err(token_error)?;
        claims.subject(subject).map_err(token_error)?;
        claims
            .expiration(&expires.to_rfc3339())
            .map_err(token_error)?;
        claims.add_additional("roles", roles).map_err(token_error)?;
        claims
            .add_additional("permissions", permissions)
            .map_err(token_error)?;
        claims
            .add_additional("token_use", token_use)
            .map_err(token_error)?;
        if let Some((sid, device_id)) = session {
            claims.add_additional("sid", sid).map_err(token_error)?;
            claims
                .add_additional("device_id", device_id)
                .map_err(token_error)?;
        }
        local::encrypt(&self.key, &claims, None, None).map_err(token_error)
    }

    fn decrypt(&self, token: &str) -> Result<pasetors::claims::Claims, AuthError> {
        let untrusted = UntrustedToken::<Local, V4>::try_from(token)
            .map_err(|_| AuthError::Unauthorized)?;
        let mut validation = ClaimsValidationRules::new();
        validation.validate_issuer_with(&self.config.issuer);
        let trusted =
            local::decrypt(&self.key, &untrusted, &validation, None, None)
                .map_err(|_| AuthError::Unauthorized)?;
        trusted
            .payload_claims()
            .cloned()
            .ok_or(AuthError::Unauthorized)
    }
}

#[cfg(feature = "auth-storage-core")]
fn claim_strings(
    claims: &pasetors::claims::Claims,
    claim_name: &str,
) -> Result<Vec<String>, AuthError> {
    claims
        .get_claim(claim_name)
        .and_then(serde_json::Value::as_array)
        .ok_or(AuthError::Unauthorized)?
        .iter()
        .map(|claim| {
            claim
                .as_str()
                .map(str::to_owned)
                .ok_or(AuthError::Unauthorized)
        })
        .collect()
}

#[cfg(feature = "auth-storage-core")]
fn token_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::Token(error.to_string())
}

#[cfg(all(test, feature = "auth-storage-core"))]
mod tests {
    use super::*;
    use pasetors::{
        keys::{Generate, SymmetricKey},
        paserk::FormatAsPaserk,
    };

    #[test]
    fn tokens_are_v4_local_and_separate_access_from_refresh_use() {
        let key = SymmetricKey::<V4>::generate().unwrap();
        let mut paserk = String::new();
        key.fmt(&mut paserk).unwrap();
        let service = TokenService::new(&paserk, TokenConfig::new("test-service")).unwrap();
        let issued = service
            .issue_pair(
                "user-123",
                &["member".to_owned()],
                &["profile.read".to_owned()],
            )
            .unwrap();

        let claims = service.verify_access_token(&issued.access_token).unwrap();
        assert_eq!(claims.subject, "user-123");
        assert_eq!(claims.roles, ["member"]);
        assert_eq!(claims.permissions, ["profile.read"]);
        assert!(matches!(
            service.verify_access_token(&issued.refresh_token),
            Err(AuthError::Unauthorized)
        ));
        assert!(matches!(
            service.verify_refresh_token(&issued.access_token),
            Err(AuthError::Unauthorized)
        ));
    }
}
