use std::{
    collections::HashMap,
    sync::atomic::{AtomicUsize, Ordering},
};

use json_rpc_2_oauth2::{
    AuthError, AuthPlugin, AuthorizedRequest, JsonRpcAuthServer, LoginRequest, RegisterRequest,
    RpcError, RpcServer, ServerPlugin, SqliteAuthServer, TokenConfig, authorize,
};
use pasetors::{
    keys::{Generate, SymmetricKey},
    paserk::FormatAsPaserk,
    version4::V4,
};
use serde_json::{Value, json};

static CALLS: AtomicUsize = AtomicUsize::new(0);

#[tokio::test]
async fn profile_reader_returns_current_storage_data_for_authenticated_subject() {
    let auth = storage(TokenConfig::new("profile-test"));
    let rpc = RpcServer::new();
    AuthPlugin::new(auth.clone()).install(&rpc).await.unwrap();
    let user = auth
        .handle_register(RegisterRequest {
            email: "profile@example.test".into(),
            password: "profile-test-password".into(),
            profile: HashMap::new(),
        })
        .await
        .unwrap();
    let tokens = auth
        .handle_login(LoginRequest {
            email: "profile@example.test".into(),
            password: "profile-test-password".into(),
            grant_type: "password".into(),
        })
        .await
        .unwrap();
    auth.handle_add_role(user.id.clone(), "new-role".into())
        .await
        .unwrap();
    for params in [
        json!({"access_token": tokens.access_token, "user_id": "another-user"}),
        json!({"authorization": format!("Bearer {}", tokens.access_token)}),
    ] {
        let response = call(&rpc, "auth.getProfile", params).await;
        assert_eq!(response["result"]["id"], user.id);
        assert_eq!(response["result"]["email"], user.email);
        assert_eq!(response["result"]["roles"], json!(["new-role"]));
        assert_eq!(
            response["result"]["profile"],
            json!({
                "contacts": [{"type":"email", "value": "profile@example.test"}]
            })
        );
        assert!(response["result"].get("password_hash").is_none());
    }
    for params in [
        json!({}),
        json!({"access_token": "invalid"}),
        json!({"access_token": tokens.refresh_token}),
        json!({"access_token": tokens.access_token, "authorization": format!("Bearer {}", tokens.access_token)}),
    ] {
        assert_eq!(
            call(&rpc, "auth.getProfile", params).await["error"]["code"],
            -32001
        );
    }
    assert!(
        auth.handle_get_profile("missing-user".into())
            .await
            .is_err()
    );
}

#[authorize(scopes = "navi.read navi.write")]
async fn protected<S>(auth: AuthPlugin<S>, request: AuthorizedRequest) -> Result<Value, RpcError>
where
    S: JsonRpcAuthServer<StorageError = AuthError> + Clone + 'static,
{
    CALLS.fetch_add(1, Ordering::SeqCst);
    Ok(json!({"subject": request.claims.subject, "params": request.params}))
}

#[authorize]
async fn authenticated<S>(
    auth: AuthPlugin<S>,
    request: AuthorizedRequest,
) -> Result<Value, RpcError>
where
    S: JsonRpcAuthServer<StorageError = AuthError> + Clone + 'static,
{
    Ok(json!(request.claims.subject))
}

fn storage(config: TokenConfig) -> SqliteAuthServer {
    let key = SymmetricKey::<V4>::generate().unwrap();
    let mut paserk = String::new();
    key.fmt(&mut paserk).unwrap();
    let mut auth = SqliteAuthServer::new(&paserk, config).unwrap();
    auth.set_db_host(":memory:");
    auth
}

async fn call(server: &RpcServer, method: &str, params: Value) -> Value {
    let request = json!({"jsonrpc": "2.0", "method": method, "params": params, "id": 1});
    let response = server
        .handle_bytes(&serde_json::to_vec(&request).unwrap())
        .await
        .unwrap();
    serde_json::from_slice(&response).unwrap()
}

#[tokio::test]
async fn annotations_fail_closed_and_enforce_all_permissions_before_handler() {
    let auth = storage(TokenConfig::new("plugin-test"));
    let plugin = AuthPlugin::new(auth.clone());
    let server = RpcServer::new();
    plugin.register(&server, "protected", protected).unwrap();
    plugin
        .register(&server, "authenticated", authenticated)
        .unwrap();
    plugin.clone().install(&server).await.unwrap();
    let user = auth
        .handle_register(RegisterRequest {
            email: "reader@example.test".into(),
            password: "test-only-password".into(),
            profile: HashMap::new(),
        })
        .await
        .unwrap();
    auth.handle_add_role(user.id.clone(), "reader".into())
        .await
        .unwrap();
    auth.handle_add_permission("reader".into(), "navi.read".into())
        .await
        .unwrap();
    let login = LoginRequest {
        email: "reader@example.test".into(),
        password: "test-only-password".into(),
        grant_type: "password".into(),
    };
    let tokens = auth.handle_login(login.clone()).await.unwrap();
    for params in [
        json!({}),
        json!({"access_token": ""}),
        json!({"access_token": 42}),
        json!({"authorization": "Basic invalid"}),
        json!({"access_token": "invalid"}),
        json!({"access_token": tokens.refresh_token}),
        json!({"access_token": tokens.access_token, "authorization": "Bearer invalid"}),
        json!({"access_token": format!(" {} ", tokens.access_token)}),
    ] {
        assert_eq!(
            call(&server, "protected", params).await["error"]["code"],
            -32001
        );
    }
    assert_eq!(
        call(&server, "protected", json!([])).await["error"]["code"],
        -32602
    );
    assert_eq!(
        call(
            &server,
            "protected",
            json!({"access_token": tokens.access_token})
        )
        .await["error"]["code"],
        -32003
    );
    assert_eq!(CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(
        call(
            &server,
            "authenticated",
            json!({"access_token": tokens.access_token})
        )
        .await["result"],
        user.id
    );

    auth.handle_add_permission("reader".into(), "navi.write".into())
        .await
        .unwrap();
    let tokens = auth.handle_login(login).await.unwrap();
    for params in [
        json!({"access_token": tokens.access_token, "destination": "Kyiv"}),
        json!({"authorization": format!("Bearer {}", tokens.access_token), "destination": "Kyiv"}),
    ] {
        let response = call(&server, "protected", params).await;
        assert_eq!(response["result"]["subject"], user.id);
        assert_eq!(response["result"]["params"], json!({"destination": "Kyiv"}));
    }
    assert_eq!(CALLS.load(Ordering::SeqCst), 2);
    let batch = json!([
        {"jsonrpc": "2.0", "id": 2, "method": "authenticated", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "authenticated", "params": {"access_token": tokens.access_token}}
    ]);
    let responses: Vec<Value> = serde_json::from_slice(
        &server
            .handle_bytes(&serde_json::to_vec(&batch).unwrap())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(responses.len(), 2);
    assert_eq!(
        responses.iter().find(|r| r["id"] == 2).unwrap()["error"]["code"],
        -32001
    );
    assert_eq!(
        responses.iter().find(|r| r["id"] == 3).unwrap()["result"],
        user.id
    );
    let notification = json!({"jsonrpc": "2.0", "method": "protected", "params": {}});
    assert!(
        server
            .handle_bytes(&serde_json::to_vec(&notification).unwrap())
            .await
            .is_none()
    );
    assert_eq!(CALLS.load(Ordering::SeqCst), 2);
    server
        .register("public", |_| async { Ok(json!("public")) })
        .unwrap();
    assert_eq!(call(&server, "public", json!({})).await["result"], "public");
    assert!(plugin.register(&server, "protected", protected).is_err());
    assert!(plugin.install(&server).await.is_err());
}

#[tokio::test]
async fn storage_initialization_failure_aborts_plugin_installation() {
    let mut auth = storage(TokenConfig::new("configuration-test"));
    auth.set_db_user("unsupported-by-sqlite");
    let server = RpcServer::new();
    assert!(AuthPlugin::new(auth).install(&server).await.is_err());
    assert_eq!(
        call(&server, "auth.login", json!({})).await["error"]["code"],
        -32601
    );
}

#[tokio::test]
async fn expired_tokens_are_rejected_by_annotated_method() {
    let mut config = TokenConfig::new("expiry-test");
    config.access_token_lifetime = std::time::Duration::from_secs(1);
    let auth = storage(config);
    let plugin = AuthPlugin::new(auth.clone());
    let server = RpcServer::new();
    plugin
        .register(&server, "authenticated", authenticated)
        .unwrap();
    plugin.install(&server).await.unwrap();
    auth.handle_register(RegisterRequest {
        email: "expiry@example.test".into(),
        password: "test-only-password".into(),
        profile: HashMap::new(),
    })
    .await
    .unwrap();
    let tokens = auth
        .handle_login(LoginRequest {
            email: "expiry@example.test".into(),
            password: "test-only-password".into(),
            grant_type: "password".into(),
        })
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    assert_eq!(
        call(
            &server,
            "authenticated",
            json!({"access_token": tokens.access_token})
        )
        .await["error"]["code"],
        -32001
    );
}
