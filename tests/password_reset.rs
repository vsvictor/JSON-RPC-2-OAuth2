use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use json_rpc_2_oauth2::{
    JsonRpcAuthServer, LoginRequest, PasswordResetNotice, RegisterRequest, RpcServer,
    SqliteAuthServer, TokenConfig, register_auth_methods_with_reset_notifier,
};
use pasetors::{
    keys::{Generate, SymmetricKey},
    paserk::FormatAsPaserk,
    version4::V4,
};
use serde_json::{Value, json};

type Inbox = Arc<Mutex<Vec<PasswordResetNotice>>>;

async fn setup() -> (SqliteAuthServer, RpcServer, Inbox) {
    let key = SymmetricKey::<V4>::generate().unwrap();
    let mut paserk = String::new();
    key.fmt(&mut paserk).unwrap();
    let mut auth = SqliteAuthServer::new(&paserk, TokenConfig::new("reset-test")).unwrap();
    auth.set_db_host(":memory:");
    auth.initialize_storage().await.unwrap();
    auth.handle_register(RegisterRequest {
        email: "user@example.test".into(),
        password: "old-password-1".into(),
        profile: HashMap::new(),
    })
    .await
    .unwrap();
    let inbox: Inbox = Arc::default();
    let sink = inbox.clone();
    let server = RpcServer::new();
    register_auth_methods_with_reset_notifier(
        auth.clone(),
        &server,
        Arc::new(move |notice| sink.lock().unwrap().push(notice)),
    )
    .unwrap();
    (auth, server, inbox)
}

async fn call(server: &RpcServer, method: &str, params: Value) -> Value {
    let request = json!({"jsonrpc": "2.0", "method": method, "params": params, "id": 1});
    let response = server
        .handle_bytes(&serde_json::to_vec(&request).unwrap())
        .await
        .unwrap();
    serde_json::from_slice(&response).unwrap()
}

async fn login(auth: &SqliteAuthServer, password: &str) -> bool {
    auth.handle_login(LoginRequest {
        email: "user@example.test".into(),
        password: password.into(),
        grant_type: "password".into(),
    })
    .await
    .is_ok()
}

#[tokio::test]
async fn reset_changes_password_and_token_is_single_use() {
    let (auth, rpc, inbox) = setup().await;
    let accepted = call(
        &rpc,
        "auth.requestPasswordReset",
        json!({"email": " User@Example.test "}),
    )
    .await;
    assert_eq!(accepted["result"]["accepted"], true);
    let token = inbox.lock().unwrap()[0].reset_token.clone();

    let done = call(
        &rpc,
        "auth.confirmPasswordReset",
        json!({"reset_token": token, "new_password": "new-password-2"}),
    )
    .await;
    assert_eq!(done["result"]["reset"], true);
    assert!(!login(&auth, "old-password-1").await);
    assert!(login(&auth, "new-password-2").await);

    let replay = call(
        &rpc,
        "auth.confirmPasswordReset",
        json!({"reset_token": token, "new_password": "third-password-3"}),
    )
    .await;
    assert_eq!(replay["error"]["code"], -32001);
    assert!(login(&auth, "new-password-2").await);
}

#[tokio::test]
async fn unknown_email_gets_same_answer_and_no_notice() {
    let (_auth, rpc, inbox) = setup().await;
    let response = call(
        &rpc,
        "auth.requestPasswordReset",
        json!({"email": "nobody@example.test"}),
    )
    .await;
    assert_eq!(response["result"]["accepted"], true);
    assert!(inbox.lock().unwrap().is_empty());
}

#[tokio::test]
async fn invalid_tokens_and_weak_passwords_are_rejected() {
    let (auth, rpc, inbox) = setup().await;
    for token in ["", "garbage"] {
        let response = call(
            &rpc,
            "auth.confirmPasswordReset",
            json!({"reset_token": token, "new_password": "new-password-2"}),
        )
        .await;
        assert_eq!(response["error"]["code"], -32001);
    }
    let tokens = auth
        .handle_login(LoginRequest {
            email: "user@example.test".into(),
            password: "old-password-1".into(),
            grant_type: "password".into(),
        })
        .await
        .unwrap();
    for token in [tokens.access_token, tokens.refresh_token] {
        let response = call(
            &rpc,
            "auth.confirmPasswordReset",
            json!({"reset_token": token, "new_password": "new-password-2"}),
        )
        .await;
        assert_eq!(response["error"]["code"], -32001);
    }

    call(
        &rpc,
        "auth.requestPasswordReset",
        json!({"email": "user@example.test"}),
    )
    .await;
    let token = inbox.lock().unwrap()[0].reset_token.clone();
    let weak = call(
        &rpc,
        "auth.confirmPasswordReset",
        json!({"reset_token": token, "new_password": "short"}),
    )
    .await;
    assert_eq!(weak["error"]["code"], -32602);
    assert!(login(&auth, "old-password-1").await);
}

#[test]
fn notice_debug_redacts_token() {
    let notice = PasswordResetNotice {
        email: "a@b.c".into(),
        reset_token: "secret-token".into(),
        user_id: "u1".into(),
    };
    assert!(!format!("{notice:?}").contains("secret-token"));
}
