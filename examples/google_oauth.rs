use json_rpc_2_oauth2::{
    AuthError, JsonRpcAuthServer, OAuth2Provider, ProviderAuthorization,
    ProviderAuthorizationRequest, ProviderCallbackRequest, SqliteAuthServer, TokenConfig,
    TokenResponse,
};
use std::error::Error;

async fn begin_google_login(
    auth: &impl JsonRpcAuthServer<StorageError = AuthError>,
    client_id: String,
    redirect_uri: String,
) -> Result<ProviderAuthorization, AuthError> {
    auth.provider_authorization(ProviderAuthorizationRequest {
        provider: OAuth2Provider::Google,
        client_id,
        redirect_uri,
        scopes: Vec::new(),
        issuer_url: None,
    })
    .await
}

async fn finish_google_login(
    auth: &impl JsonRpcAuthServer<StorageError = AuthError>,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    code_from_callback: String,
    state_from_callback: String,
    pending: ProviderAuthorization,
) -> Result<TokenResponse, AuthError> {
    auth.handle_provider_callback(ProviderCallbackRequest {
        provider: OAuth2Provider::Google,
        client_id,
        client_secret,
        redirect_uri,
        code: code_from_callback,
        state: state_from_callback,
        expected_state: pending.state,
        pkce_verifier: pending.pkce_verifier,
        issuer_url: None,
    })
    .await
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let paserk_key = std::env::var("PASETO_LOCAL_KEY")?;
    let client_id = std::env::var("GOOGLE_CLIENT_ID")?;
    let client_secret = std::env::var("GOOGLE_CLIENT_SECRET")?;
    let redirect_uri = std::env::var("GOOGLE_REDIRECT_URI")?;
    let mut auth = SqliteAuthServer::new(&paserk_key, TokenConfig::new("example-service"))?;
    auth.set_db_host(":memory:");
    auth.initialize_storage().await?;

    let pending = begin_google_login(&auth, client_id.clone(), redirect_uri.clone()).await?;
    println!("Redirect the browser to: {}", pending.authorization_url);
    println!("After authorizing, paste the callback's code and state separated by a space:");

    let mut callback = String::new();
    std::io::stdin().read_line(&mut callback)?;
    let mut values = callback.split_whitespace();
    let code = values
        .next()
        .ok_or_else(|| std::io::Error::other("callback authorization code is required"))?;
    let state = values
        .next()
        .ok_or_else(|| std::io::Error::other("callback state is required"))?;
    if values.next().is_some() {
        return Err(std::io::Error::other("expected exactly a code and a state").into());
    }

    let tokens = finish_google_login(
        &auth,
        client_id,
        client_secret,
        redirect_uri,
        code.to_owned(),
        state.to_owned(),
        pending,
    )
    .await?;
    println!(
        "Google login completed; access token expires in {} seconds.",
        tokens.expires_in
    );
    Ok(())
}
