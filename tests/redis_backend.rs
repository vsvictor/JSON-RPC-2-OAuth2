use json_rpc_2_oauth2::{
    JsonRpcAuthServer, LoginRequest, ProfileFieldType, RedisAuthServer, RegisterRequest,
    TokenConfig,
};
use pasetors::{
    keys::{Generate, SymmetricKey},
    paserk::FormatAsPaserk,
    version4::V4,
};
use std::collections::HashMap;
use testcontainers_modules::{redis::Redis, testcontainers::runners::AsyncRunner};

#[tokio::test]
async fn redis_auth_profile_rbac_and_refresh_work_end_to_end() {
    let container = Redis::default().start().await.unwrap();
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(6379).await.unwrap();
    let key = SymmetricKey::<V4>::generate().unwrap();
    let mut paserk = String::new();
    key.fmt(&mut paserk).unwrap();
    let mut auth = RedisAuthServer::new(&paserk, TokenConfig::new("redis-test")).unwrap();
    auth.set_db_host(&format!("{host}:{port}"));
    auth.define_profile_schema(HashMap::from([
        ("joined_at".to_owned(), ProfileFieldType::DateTime),
        ("active".to_owned(), ProfileFieldType::Boolean),
    ]));
    auth.initialize_storage().await.unwrap();

    let user = auth
        .handle_register(RegisterRequest {
            email: "redis@example.test".to_owned(),
            password: "a long secure password".to_owned(),
            profile: HashMap::from([
                ("joined_at".to_owned(), "2024-01-02T03:04:05Z".to_owned()),
                ("active".to_owned(), "true".to_owned()),
            ]),
        })
        .await
        .unwrap();
    assert_eq!(user.profile["active"], true);
    auth.handle_add_role(user.id.clone(), "reader".to_owned())
        .await
        .unwrap();
    auth.handle_add_permission("reader".to_owned(), "profile.read".to_owned())
        .await
        .unwrap();

    let tokens = auth
        .handle_login(LoginRequest {
            email: "redis@example.test".to_owned(),
            password: "a long secure password".to_owned(),
            grant_type: "password".to_owned(),
        })
        .await
        .unwrap();
    assert!(
        auth.require_permission(&tokens.access_token, "profile.read")
            .is_ok()
    );
    let renewed = auth.handle_refresh(&tokens.refresh_token).await.unwrap();
    assert!(
        auth.authenticate_access_token(&renewed.access_token)
            .is_ok()
    );

    let updated = auth
        .handle_update_profile(
            user.id,
            HashMap::from([("active".to_owned(), "false".to_owned())]),
        )
        .await
        .unwrap();
    assert_eq!(updated.profile["active"], false);
}
