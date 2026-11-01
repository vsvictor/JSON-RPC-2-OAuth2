use std::collections::HashMap;

use json_rpc_2_oauth2::{
    AuthPlugin, AuthorizedRequest, JsonRpcAuthServer, LoginRequest, RegisterRequest, RpcError,
    RpcServer, ServerPlugin, SqliteAuthServer, TokenConfig, authorize,
};
use serde_json::{Value, json};

#[authorize(scopes = "navi.read")]
async fn route(
    auth: AuthPlugin<SqliteAuthServer>,
    request: AuthorizedRequest,
) -> Result<Value, RpcError> {
    Ok(json!({"user_id": request.claims.subject, "destination": request.params["destination"]}))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let key = std::env::var("PASETO_LOCAL_KEY")?;
    let mut storage = SqliteAuthServer::new(&key, TokenConfig::new("annotated-example"))?;
    storage.set_db_host(":memory:");
    let plugin = AuthPlugin::new(storage.clone());
    let server = RpcServer::new();
    plugin.register(&server, "navi.route", route)?;
    plugin.install(&server).await?;

    // Demo-only provisioning; production roles must be assigned by a trusted administrator.
    let user = storage
        .handle_register(RegisterRequest {
            email: "reader@example.test".into(),
            password: "example-only-password".into(),
            profile: HashMap::new(),
        })
        .await?;
    storage.handle_add_role(user.id, "reader".into()).await?;
    storage
        .handle_add_permission("reader".into(), "navi.read".into())
        .await?;
    let tokens = storage
        .handle_login(LoginRequest {
            email: "reader@example.test".into(),
            password: "example-only-password".into(),
            grant_type: "password".into(),
        })
        .await?;
    let request = json!({
        "jsonrpc": "2.0", "id": 1, "method": "navi.route",
        "params": {"access_token": tokens.access_token, "destination": "Kyiv"}
    });
    let response = server
        .handle_bytes(&serde_json::to_vec(&request)?)
        .await
        .ok_or_else(|| anyhow::anyhow!("missing JSON-RPC response"))?;
    println!("{}", std::str::from_utf8(&response)?);
    Ok(())
}
