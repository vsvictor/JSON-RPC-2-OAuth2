use crate::{
    AuthError, ExternalIdentity, OAuth2Provider, ProviderAuthorization,
    ProviderAuthorizationRequest, ProviderCallbackRequest,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode,
    jwk::{Jwk, JwkSet},
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;
use url::Url;
use uuid::Uuid;

struct ProviderEndpoints {
    authorization: String,
    token: String,
    userinfo: String,
    default_scopes: &'static [&'static str],
}

pub(crate) async fn authorization(
    req: ProviderAuthorizationRequest,
) -> Result<ProviderAuthorization, AuthError> {
    ensure_provider_enabled(req.provider)?;
    if req.client_id.trim().is_empty() {
        return Err(invalid_config("OAuth client_id is required"));
    }
    validate_https_url(&req.redirect_uri)?;
    let endpoints = endpoints(req.provider, req.issuer_url.as_deref())
        .await?
        .ok_or_else(|| unsupported(req.provider))?;
    let state = Uuid::new_v4().to_string();
    let verifier = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let mut url =
        Url::parse(&endpoints.authorization).map_err(|error| invalid_config(error.to_string()))?;
    let mut scopes = endpoints
        .default_scopes
        .iter()
        .map(|scope| (*scope).to_owned())
        .collect::<Vec<_>>();
    for scope in req.scopes {
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    let scope = scopes.join(" ");
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &req.client_id)
        .append_pair("redirect_uri", &req.redirect_uri)
        .append_pair("scope", &scope)
        .append_pair("state", &state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    Ok(ProviderAuthorization {
        authorization_url: url.into(),
        state,
        pkce_verifier: verifier,
    })
}

pub(crate) async fn exchange_code(
    req: ProviderCallbackRequest,
) -> Result<ExternalIdentity, AuthError> {
    ensure_provider_enabled(req.provider)?;
    if req.state.is_empty() || req.state != req.expected_state {
        return Err(AuthError::Unauthorized);
    }
    if req.client_id.trim().is_empty()
        || req.client_secret.trim().is_empty()
        || req.code.is_empty()
        || req.pkce_verifier.is_empty()
    {
        return Err(AuthError::InvalidParams(
            "OAuth client credentials, authorization code, and PKCE verifier are required"
                .to_owned(),
        ));
    }
    validate_https_url(&req.redirect_uri)?;
    let endpoints = endpoints(req.provider, req.issuer_url.as_deref())
        .await?
        .ok_or_else(|| unsupported(req.provider))?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|error| invalid_config(error.to_string()))?;
    let token_request = client
        .post(endpoints.token.clone())
        .header(reqwest::header::ACCEPT, "application/json");
    let token_request = if matches!(
        req.provider,
        OAuth2Provider::Bitbucket | OAuth2Provider::X | OAuth2Provider::Spotify
    ) {
        token_request
            .basic_auth(&req.client_id, Some(&req.client_secret))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", req.code.as_str()),
                ("redirect_uri", req.redirect_uri.as_str()),
                ("code_verifier", req.pkce_verifier.as_str()),
            ])
    } else if req.provider == OAuth2Provider::Facebook {
        client.get(endpoints.token.clone()).query(&[
            ("client_id", req.client_id.as_str()),
            ("client_secret", req.client_secret.as_str()),
            ("code", req.code.as_str()),
            ("redirect_uri", req.redirect_uri.as_str()),
            ("code_verifier", req.pkce_verifier.as_str()),
        ])
    } else {
        token_request.form(&[
            ("grant_type", "authorization_code"),
            ("code", req.code.as_str()),
            ("redirect_uri", req.redirect_uri.as_str()),
            ("client_id", req.client_id.as_str()),
            ("client_secret", req.client_secret.as_str()),
            ("code_verifier", req.pkce_verifier.as_str()),
        ])
    };
    let token: TokenReply = token_request
        .send()
        .await
        .map_err(|_| AuthError::Unauthorized)?
        .error_for_status()
        .map_err(|_| AuthError::Unauthorized)?
        .json()
        .await
        .map_err(|_| AuthError::Unauthorized)?;

    let profile = if req.provider == OAuth2Provider::Apple {
        let id_token = token.id_token.as_deref().ok_or(AuthError::Unauthorized)?;
        verify_apple_id_token(&client, id_token, &req.client_id).await?
    } else {
        fetch_user_profile(
            &client,
            req.provider,
            &endpoints.userinfo,
            &token.access_token,
            &req.client_id,
        )
        .await?
    };
    let subject = profile_subject(&profile).ok_or(AuthError::Unauthorized)?;
    let email = profile
        .get("email")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_lowercase());
    let verified = profile
        .get("email_verified")
        .or_else(|| profile.get("verified"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(ExternalIdentity {
        provider: req.provider,
        subject,
        email,
        email_verified: verified,
    })
}

async fn endpoints(
    provider: OAuth2Provider,
    issuer_url: Option<&str>,
) -> Result<Option<ProviderEndpoints>, AuthError> {
    let fixed = match provider {
        OAuth2Provider::Google => Some(ProviderEndpoints {
            authorization: "https://accounts.google.com/o/oauth2/v2/auth".to_owned(),
            token: "https://oauth2.googleapis.com/token".to_owned(),
            userinfo: "https://openidconnect.googleapis.com/v1/userinfo".to_owned(),
            default_scopes: &["openid", "email", "profile"],
        }),
        OAuth2Provider::LinkedIn => Some(ProviderEndpoints {
            authorization: "https://www.linkedin.com/oauth/v2/authorization".to_owned(),
            token: "https://www.linkedin.com/oauth/v2/accessToken".to_owned(),
            userinfo: "https://api.linkedin.com/v2/userinfo".to_owned(),
            default_scopes: &["openid", "profile", "email"],
        }),
        OAuth2Provider::Slack => Some(ProviderEndpoints {
            authorization: "https://slack.com/openid/connect/authorize".to_owned(),
            token: "https://slack.com/api/openid.connect.token".to_owned(),
            userinfo: "https://slack.com/api/openid.connect.userInfo".to_owned(),
            default_scopes: &["openid", "profile", "email"],
        }),
        OAuth2Provider::Facebook => Some(ProviderEndpoints {
            authorization: "https://www.facebook.com/v21.0/dialog/oauth".to_owned(),
            token: "https://graph.facebook.com/v21.0/oauth/access_token".to_owned(),
            userinfo: "https://graph.facebook.com/v21.0/me?fields=id,email".to_owned(),
            default_scopes: &["email", "public_profile"],
        }),
        OAuth2Provider::X => Some(ProviderEndpoints {
            authorization: "https://twitter.com/i/oauth2/authorize".to_owned(),
            token: "https://api.twitter.com/2/oauth2/token".to_owned(),
            userinfo: "https://api.twitter.com/2/users/me?user.fields=id".to_owned(),
            default_scopes: &["users.read"],
        }),
        OAuth2Provider::Twitch => Some(ProviderEndpoints {
            authorization: "https://id.twitch.tv/oauth2/authorize".to_owned(),
            token: "https://id.twitch.tv/oauth2/token".to_owned(),
            userinfo: "https://api.twitch.tv/helix/users".to_owned(),
            default_scopes: &["user:read:email"],
        }),
        OAuth2Provider::Spotify => Some(ProviderEndpoints {
            authorization: "https://accounts.spotify.com/authorize".to_owned(),
            token: "https://accounts.spotify.com/api/token".to_owned(),
            userinfo: "https://api.spotify.com/v1/me".to_owned(),
            default_scopes: &["user-read-email", "user-read-private"],
        }),
        OAuth2Provider::Apple => Some(ProviderEndpoints {
            authorization: "https://appleid.apple.com/auth/authorize".to_owned(),
            token: "https://appleid.apple.com/auth/token".to_owned(),
            userinfo: String::new(),
            default_scopes: &["name", "email"],
        }),
        OAuth2Provider::GitHub => Some(ProviderEndpoints {
            authorization: "https://github.com/login/oauth/authorize".to_owned(),
            token: "https://github.com/login/oauth/access_token".to_owned(),
            userinfo: "https://api.github.com/user".to_owned(),
            default_scopes: &["read:user", "user:email"],
        }),
        OAuth2Provider::Bitbucket => Some(ProviderEndpoints {
            authorization: "https://bitbucket.org/site/oauth2/authorize".to_owned(),
            token: "https://bitbucket.org/site/oauth2/access_token".to_owned(),
            userinfo: "https://api.bitbucket.org/2.0/user".to_owned(),
            default_scopes: &["account", "email"],
        }),
        OAuth2Provider::Discord => Some(ProviderEndpoints {
            authorization: "https://discord.com/oauth2/authorize".to_owned(),
            token: "https://discord.com/api/oauth2/token".to_owned(),
            userinfo: "https://discord.com/api/users/@me".to_owned(),
            default_scopes: &["identify", "email"],
        }),
        OAuth2Provider::Auth0
        | OAuth2Provider::Okta
        | OAuth2Provider::GitLab
        | OAuth2Provider::Microsoft => {
            let issuer = validated_issuer(issuer_url)?;
            if provider == OAuth2Provider::Microsoft {
                let issuer_host = Url::parse(&issuer)
                    .map_err(|error| invalid_config(error.to_string()))?
                    .host_str()
                    .unwrap_or_default()
                    .to_owned();
                if issuer_host != "login.microsoftonline.com" {
                    return Err(invalid_config(
                        "Microsoft issuer_url must use login.microsoftonline.com",
                    ));
                }
            }
            let discovery = discover_oidc(&issuer).await?;
            return Ok(Some(ProviderEndpoints {
                authorization: discovery.authorization_endpoint,
                token: discovery.token_endpoint,
                userinfo: discovery.userinfo_endpoint,
                default_scopes: &["openid", "profile", "email"],
            }));
        }
        OAuth2Provider::FirebaseAuthentication => None,
    };
    Ok(fixed)
}

async fn fetch_user_profile(
    client: &reqwest::Client,
    provider: OAuth2Provider,
    endpoint: &str,
    access_token: &str,
    client_id: &str,
) -> Result<Value, AuthError> {
    let mut request = client
        .get(endpoint)
        .bearer_auth(access_token)
        .header(reqwest::header::ACCEPT, "application/json");
    if provider == OAuth2Provider::Twitch {
        request = request.header("Client-Id", client_id);
    }
    if provider == OAuth2Provider::GitHub {
        request = request
            .header(reqwest::header::USER_AGENT, "json-rpc-2-oauth2")
            .header("X-GitHub-Api-Version", "2022-11-28");
    }
    let profile: Value = request
        .send()
        .await
        .map_err(|_| AuthError::Unauthorized)?
        .error_for_status()
        .map_err(|_| AuthError::Unauthorized)?
        .json()
        .await
        .map_err(|_| AuthError::Unauthorized)?;

    match provider {
        OAuth2Provider::X => {
            let mut merged = profile;
            if let Some(id) = merged.get("data").and_then(|data| data.get("id")).cloned() {
                merged["sub"] = id;
            }
            Ok(merged)
        }
        OAuth2Provider::Twitch => {
            let mut merged = profile;
            let details = merged
                .get("data")
                .and_then(Value::as_array)
                .and_then(|users| users.first())
                .map(|user| (user.get("id").cloned(), user.get("email").cloned()));
            if let Some((id, email)) = details {
                if let Some(id) = id {
                    merged["sub"] = id;
                }
                if let Some(email) = email {
                    merged["email"] = email;
                }
            }
            Ok(merged)
        }
        OAuth2Provider::Microsoft => {
            let mut merged = profile;
            if merged.get("email").is_none()
                && let Some(email) = merged
                    .get("mail")
                    .or_else(|| merged.get("userPrincipalName"))
                    .cloned()
            {
                merged["email"] = email;
            }
            Ok(merged)
        }
        OAuth2Provider::GitHub => {
            let emails: Vec<Value> = client
                .get("https://api.github.com/user/emails")
                .bearer_auth(access_token)
                .header(reqwest::header::USER_AGENT, "json-rpc-2-oauth2")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .send()
                .await
                .map_err(|_| AuthError::Unauthorized)?
                .error_for_status()
                .map_err(|_| AuthError::Unauthorized)?
                .json()
                .await
                .map_err(|_| AuthError::Unauthorized)?;
            let email = emails
                .iter()
                .find(|email| {
                    email.get("primary").and_then(Value::as_bool) == Some(true)
                        && email.get("verified").and_then(Value::as_bool) == Some(true)
                })
                .and_then(|email| email.get("email"))
                .and_then(Value::as_str);
            let mut merged = profile;
            set_verified_email(&mut merged, email);
            Ok(merged)
        }
        OAuth2Provider::Bitbucket => {
            let emails: Value = client
                .get("https://api.bitbucket.org/2.0/user/emails")
                .bearer_auth(access_token)
                .send()
                .await
                .map_err(|_| AuthError::Unauthorized)?
                .error_for_status()
                .map_err(|_| AuthError::Unauthorized)?
                .json()
                .await
                .map_err(|_| AuthError::Unauthorized)?;
            let email = emails
                .get("values")
                .and_then(Value::as_array)
                .and_then(|values| {
                    values.iter().find(|item| {
                        item.get("is_primary").and_then(Value::as_bool) == Some(true)
                            && item.get("is_confirmed").and_then(Value::as_bool) == Some(true)
                    })
                })
                .and_then(|item| item.get("email"))
                .and_then(Value::as_str);
            let mut merged = profile;
            set_verified_email(&mut merged, email);
            Ok(merged)
        }
        OAuth2Provider::Discord => {
            let mut merged = profile;
            if let Some(verified) = merged.get("verified").cloned() {
                merged["email_verified"] = verified;
            }
            Ok(merged)
        }
        _ => Ok(profile),
    }
}

fn profile_subject(profile: &Value) -> Option<String> {
    match profile.get("sub").or_else(|| profile.get("id"))? {
        Value::String(value) if !value.is_empty() => Some(value.clone()),
        Value::Number(value) if value.is_i64() || value.is_u64() => Some(value.to_string()),
        _ => None,
    }
}

fn set_verified_email(profile: &mut Value, email: Option<&str>) {
    if let Some(email) = email {
        profile["email"] = Value::String(email.to_owned());
        profile["email_verified"] = Value::Bool(true);
    } else {
        if let Some(profile) = profile.as_object_mut() {
            profile.remove("email");
        }
        profile["email_verified"] = Value::Bool(false);
    }
}

#[derive(Deserialize)]
struct TokenReply {
    access_token: String,
    id_token: Option<String>,
}

#[derive(Deserialize)]
struct OidcDiscovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
}

#[derive(Deserialize)]
struct AppleIdTokenClaims {
    iss: String,
    aud: String,
    sub: String,
    email: Option<String>,
    email_verified: Option<AppleEmailVerified>,
}

#[derive(Deserialize)]
struct FirebaseIdTokenClaims {
    iss: String,
    aud: String,
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AppleEmailVerified {
    Boolean(bool),
    String(String),
}

impl AppleEmailVerified {
    fn is_verified(&self) -> bool {
        match self {
            Self::Boolean(value) => *value,
            Self::String(value) => value == "true",
        }
    }
}

async fn verify_apple_id_token(
    client: &reqwest::Client,
    id_token: &str,
    client_id: &str,
) -> Result<Value, AuthError> {
    let header = jsonwebtoken::decode_header(id_token).map_err(|_| AuthError::Unauthorized)?;
    if header.alg != Algorithm::RS256 {
        return Err(AuthError::Unauthorized);
    }
    let kid = header.kid.ok_or(AuthError::Unauthorized)?;
    let jwks: JwkSet = client
        .get("https://appleid.apple.com/auth/keys")
        .send()
        .await
        .map_err(|_| AuthError::Unauthorized)?
        .error_for_status()
        .map_err(|_| AuthError::Unauthorized)?
        .json()
        .await
        .map_err(|_| AuthError::Unauthorized)?;
    let key: &Jwk = jwks.find(&kid).ok_or(AuthError::Unauthorized)?;
    let decoding_key = DecodingKey::from_jwk(key).map_err(|_| AuthError::Unauthorized)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[client_id]);
    validation.set_issuer(&["https://appleid.apple.com"]);
    let claims = decode::<AppleIdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|_| AuthError::Unauthorized)?
        .claims;
    if claims.iss != "https://appleid.apple.com" || claims.aud != client_id || claims.sub.is_empty()
    {
        return Err(AuthError::Unauthorized);
    }
    let verified = claims
        .email_verified
        .as_ref()
        .is_some_and(AppleEmailVerified::is_verified);
    let mut profile = serde_json::json!({
        "sub": claims.sub,
        "email_verified": verified,
    });
    if let Some(email) = claims.email {
        profile["email"] = Value::String(email);
    }
    Ok(profile)
}

pub(crate) async fn verify_firebase_id_token(
    id_token: &str,
    project_id: &str,
) -> Result<ExternalIdentity, AuthError> {
    ensure_provider_enabled(OAuth2Provider::FirebaseAuthentication)?;
    let header = jsonwebtoken::decode_header(id_token).map_err(|_| AuthError::Unauthorized)?;
    if header.alg != Algorithm::RS256 {
        return Err(AuthError::Unauthorized);
    }

    let kid = header.kid.ok_or(AuthError::Unauthorized)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|error| invalid_config(error.to_string()))?;
    let jwks: JwkSet = client
        .get("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com")
        .send()
        .await
        .map_err(|_| AuthError::Unauthorized)?
        .error_for_status()
        .map_err(|_| AuthError::Unauthorized)?
        .json()
        .await
        .map_err(|_| AuthError::Unauthorized)?;
    let key = jwks.find(&kid).ok_or(AuthError::Unauthorized)?;
    let decoding_key = DecodingKey::from_jwk(key).map_err(|_| AuthError::Unauthorized)?;
    let issuer = format!("https://securetoken.google.com/{project_id}");
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[project_id]);
    validation.set_issuer(&[issuer.as_str()]);
    let claims = decode::<FirebaseIdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|_| AuthError::Unauthorized)?
        .claims;
    if claims.iss != issuer || claims.aud != project_id || claims.sub.is_empty() {
        return Err(AuthError::Unauthorized);
    }
    Ok(ExternalIdentity {
        provider: OAuth2Provider::FirebaseAuthentication,
        subject: claims.sub,
        email: claims.email.map(|email| email.trim().to_lowercase()),
        email_verified: claims.email_verified.unwrap_or(false),
    })
}

fn ensure_provider_enabled(provider: OAuth2Provider) -> Result<(), AuthError> {
    let enabled = match provider {
        OAuth2Provider::Google => cfg!(feature = "oauth-google"),
        OAuth2Provider::FirebaseAuthentication => {
            cfg!(feature = "oauth-firebase-authentication")
        }
        OAuth2Provider::Apple => cfg!(feature = "oauth-apple"),
        OAuth2Provider::Microsoft => cfg!(feature = "oauth-microsoft"),
        OAuth2Provider::Facebook => cfg!(feature = "oauth-facebook"),
        OAuth2Provider::X => cfg!(feature = "oauth-x"),
        OAuth2Provider::LinkedIn => cfg!(feature = "oauth-linkedin"),
        OAuth2Provider::Slack => cfg!(feature = "oauth-slack"),
        OAuth2Provider::GitHub => cfg!(feature = "oauth-github"),
        OAuth2Provider::GitLab => cfg!(feature = "oauth-gitlab"),
        OAuth2Provider::Bitbucket => cfg!(feature = "oauth-bitbucket"),
        OAuth2Provider::Discord => cfg!(feature = "oauth-discord"),
        OAuth2Provider::Twitch => cfg!(feature = "oauth-twitch"),
        OAuth2Provider::Spotify => cfg!(feature = "oauth-spotify"),
        OAuth2Provider::Auth0 => cfg!(feature = "oauth-auth0"),
        OAuth2Provider::Okta => cfg!(feature = "oauth-okta"),
    };
    if enabled {
        Ok(())
    } else {
        Err(unsupported(provider))
    }
}

async fn discover_oidc(issuer: &str) -> Result<OidcDiscovery, AuthError> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let discovery: OidcDiscovery = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|error| invalid_config(error.to_string()))?
        .get(url)
        .send()
        .await
        .map_err(|_| AuthError::Unauthorized)?
        .error_for_status()
        .map_err(|_| AuthError::Unauthorized)?
        .json()
        .await
        .map_err(|_| AuthError::Unauthorized)?;
    validate_https_url(&discovery.authorization_endpoint)?;
    validate_https_url(&discovery.token_endpoint)?;
    validate_https_url(&discovery.userinfo_endpoint)?;
    let expected_origin = Url::parse(issuer).map_err(|error| invalid_config(error.to_string()))?;
    for endpoint in [&discovery.authorization_endpoint, &discovery.token_endpoint] {
        let endpoint_url =
            Url::parse(endpoint).map_err(|error| invalid_config(error.to_string()))?;
        if endpoint_url.origin() != expected_origin.origin() {
            return Err(invalid_config(
                "OIDC discovery endpoints must share the configured issuer origin",
            ));
        }
    }
    let userinfo_url = Url::parse(&discovery.userinfo_endpoint)
        .map_err(|error| invalid_config(error.to_string()))?;
    let userinfo_host = userinfo_url.host_str().unwrap_or_default();
    let microsoft_graph_userinfo = expected_origin
        .host_str()
        .is_some_and(|host| host == "login.microsoftonline.com")
        && userinfo_host == "graph.microsoft.com";
    if userinfo_url.origin() != expected_origin.origin() && !microsoft_graph_userinfo {
        return Err(invalid_config(
            "OIDC discovery userinfo endpoint must share the issuer origin",
        ));
    }
    if discovery.issuer.trim_end_matches('/') != issuer.trim_end_matches('/') {
        return Err(invalid_config(
            "OIDC discovery issuer does not match the configured issuer_url",
        ));
    }
    Ok(discovery)
}

fn validated_issuer(issuer: Option<&str>) -> Result<String, AuthError> {
    let issuer = issuer.ok_or_else(|| invalid_config("OIDC issuer_url is required"))?;
    validate_https_url(issuer)?;
    Ok(issuer.trim_end_matches('/').to_owned())
}

fn validate_https_url(value: &str) -> Result<(), AuthError> {
    let url = Url::parse(value).map_err(|error| invalid_config(error.to_string()))?;
    if url.scheme() != "https" {
        return Err(invalid_config("OAuth URLs must use HTTPS"));
    }
    Ok(())
}

fn unsupported(provider: OAuth2Provider) -> AuthError {
    invalid_config(format!(
        "OAuth2 provider {provider:?} is not implemented; see the provider support table"
    ))
}

fn invalid_config(message: impl Into<String>) -> AuthError {
    AuthError::InvalidConfiguration(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[cfg(feature = "oauth-google")]
    async fn authorization_returns_state_and_pkce_challenge() {
        let result = authorization(ProviderAuthorizationRequest {
            provider: OAuth2Provider::Google,
            client_id: "client-id".to_owned(),
            redirect_uri: "https://service.example/callback".to_owned(),
            scopes: Vec::new(),
            issuer_url: None,
        })
        .await
        .unwrap();
        let url = Url::parse(&result.authorization_url).unwrap();
        let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        let expected_challenge =
            URL_SAFE_NO_PAD.encode(Sha256::digest(result.pkce_verifier.as_bytes()));
        assert_eq!(params["state"], result.state);
        assert_eq!(params["code_challenge"], expected_challenge);
        assert_eq!(params["code_challenge_method"], "S256");
        assert!(!result.pkce_verifier.is_empty());
    }

    #[tokio::test]
    #[cfg(feature = "oauth-google")]
    async fn callback_rejects_mismatched_state_before_network_requests() {
        let result = exchange_code(ProviderCallbackRequest {
            provider: OAuth2Provider::Google,
            client_id: "client-id".to_owned(),
            client_secret: "secret".to_owned(),
            redirect_uri: "https://service.example/callback".to_owned(),
            code: "authorization-code".to_owned(),
            state: "attacker-state".to_owned(),
            expected_state: "stored-state".to_owned(),
            pkce_verifier: "verifier".to_owned(),
            issuer_url: None,
        })
        .await;
        assert!(matches!(result, Err(AuthError::Unauthorized)));
    }

    #[tokio::test]
    #[cfg(all(feature = "oauth-apple", feature = "oauth-slack"))]
    async fn authorization_supports_apple_and_slack_with_required_scopes() {
        for (provider, expected_host, required_scope) in [
            (OAuth2Provider::Apple, "appleid.apple.com", "email"),
            (OAuth2Provider::Slack, "slack.com", "openid"),
        ] {
            let result = authorization(ProviderAuthorizationRequest {
                provider,
                client_id: "client-id".to_owned(),
                redirect_uri: "https://service.example/callback".to_owned(),
                scopes: vec!["custom.scope".to_owned()],
                issuer_url: None,
            })
            .await
            .unwrap();
            let url = Url::parse(&result.authorization_url).unwrap();
            assert_eq!(url.host_str(), Some(expected_host));
            let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
            let scopes = params["scope"].split(' ').collect::<Vec<_>>();
            assert!(scopes.contains(&required_scope));
            assert!(scopes.contains(&"custom.scope"));
        }
    }

    #[tokio::test]
    #[cfg(feature = "oauth-firebase-authentication")]
    async fn firebase_requires_its_id_token_flow_not_authorization_code() {
        let result = authorization(ProviderAuthorizationRequest {
            provider: OAuth2Provider::FirebaseAuthentication,
            client_id: "client-id".to_owned(),
            redirect_uri: "https://service.example/callback".to_owned(),
            scopes: Vec::new(),
            issuer_url: None,
        })
        .await;
        assert!(matches!(result, Err(AuthError::InvalidConfiguration(_))));
    }

    #[test]
    #[cfg(all(feature = "oauth-google", not(feature = "oauth-facebook")))]
    fn disabled_provider_returns_configuration_error() {
        assert!(ensure_provider_enabled(OAuth2Provider::Google).is_ok());
        assert!(matches!(
            ensure_provider_enabled(OAuth2Provider::Facebook),
            Err(AuthError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn primary_verified_email_is_optional_for_existing_provider_identities() {
        let profile = serde_json::json!({"id": "provider-user", "email": "unverified@example.com"});
        let mut profile = profile;
        set_verified_email(&mut profile, None);
        assert_eq!(
            profile.get("id").and_then(Value::as_str),
            Some("provider-user")
        );
        assert!(profile.get("email").is_none());
        assert_eq!(
            profile.get("email_verified").and_then(Value::as_bool),
            Some(false)
        );

        set_verified_email(&mut profile, Some("verified@example.com"));
        assert_eq!(
            profile.get("email").and_then(Value::as_str),
            Some("verified@example.com")
        );
        assert_eq!(
            profile.get("email_verified").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn profile_subject_accepts_string_and_integer_provider_ids() {
        assert_eq!(
            profile_subject(&serde_json::json!({"sub": "oidc-subject"})),
            Some("oidc-subject".to_owned())
        );
        assert_eq!(
            profile_subject(&serde_json::json!({"id": 123456789})),
            Some("123456789".to_owned())
        );
        assert_eq!(profile_subject(&serde_json::json!({"id": 1.5})), None);
    }
}
