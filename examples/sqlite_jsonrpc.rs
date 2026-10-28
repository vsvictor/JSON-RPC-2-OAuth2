use json_rpc_2_oauth2::{
    JsonRpcAuthServer, ProfileFieldType, RegisterRequest, SqliteAuthServer, TokenConfig,
};
use json_rpc_2_server::RpcServer;
use serde_json::{Value, json};
use std::{collections::HashMap, error::Error};

async fn call_rpc(
    server: &RpcServer,
    method: &str,
    params: Value,
) -> Result<Value, Box<dyn Error>> {
    let request = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });
    let response = server
        .handle_bytes(&serde_json::to_vec(&request)?)
        .await
        .ok_or_else(|| std::io::Error::other("server returned no JSON-RPC response"))?;
    Ok(serde_json::from_slice(&response)?)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let paserk_key = std::env::var("PASETO_LOCAL_KEY")?;
    let mut auth = SqliteAuthServer::new(&paserk_key, TokenConfig::new("example-service"))?;
    auth.set_db_host(":memory:");
    auth.set_profile_schema(HashMap::from([
        ("display_name".to_owned(), ProfileFieldType::Text),
        ("login_count".to_owned(), ProfileFieldType::Integer),
    ]))?;
    auth.initialize_storage().await?;

    let user = auth
        .handle_register(RegisterRequest {
            email: "reader@example.test".to_owned(),
            password: "example-only-password".to_owned(),
            profile: HashMap::from([
                ("display_name".to_owned(), "Example Reader".to_owned()),
                ("login_count".to_owned(), "0".to_owned()),
            ]),
        })
        .await?;

    auth.handle_add_role(user.id.clone(), "reader".to_owned())
        .await?;
    auth.handle_add_permission("reader".to_owned(), "profile.read".to_owned())
        .await?;

    let tokens = auth
        .handle_login(json_rpc_2_oauth2::LoginRequest {
            email: "reader@example.test".to_owned(),
            password: "example-only-password".to_owned(),
            grant_type: "password".to_owned(),
        })
        .await?;
    auth.require_permission(&tokens.access_token, "profile.read")?;

    let rpc = RpcServer::new();
    auth.register_auth_methods(&rpc)?;
    let response = call_rpc(
        &rpc,
        "auth.updateProfile",
        json!({
            "access_token": tokens.access_token,
            "profile": { "display_name": "Updated Reader" }
        }),
    )
    .await?;

    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}
