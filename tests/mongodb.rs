use json_rpc_2_oauth2::{
    JsonRpcAuthServer, LoginRequest, MongoAuthServer, ProfileFieldType, RegisterRequest,
    TokenConfig,
};
use pasetors::{
    keys::{Generate, SymmetricKey},
    paserk::FormatAsPaserk,
    version4::V4,
};
use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};
use testcontainers_modules::{mongo::Mongo, testcontainers::runners::AsyncRunner};

#[tokio::test]
async fn mongodb_auth_profile_and_rbac_work_end_to_end() {
    let mongo = Mongo::default().start().await.unwrap();
    let host = mongo.get_host().await.unwrap();
    let port = mongo.get_host_port_ipv4(27017).await.unwrap();
    let database_name = format!(
        "json_rpc_auth_test_{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let mut server =
        MongoAuthServer::new(&test_key(), TokenConfig::new("integration-test")).unwrap();
    server.set_db_host(&format!("{host}:{port}"));
    server.set_db_name(&database_name);
    server
        .set_profile_schema(HashMap::from([
            ("joined_at".to_owned(), ProfileFieldType::DateTime),
            ("avatar".to_owned(), ProfileFieldType::Blob),
        ]))
        .unwrap();
    server.initialize_storage().await.unwrap();

    let profile = HashMap::from([
        ("joined_at".to_owned(), "2024-02-03T04:05:06Z".to_owned()),
        ("avatar".to_owned(), "AQIDBA==".to_owned()),
    ]);
    let registered = server
        .handle_register(RegisterRequest {
            email: "admin@example.test".to_owned(),
            password: "correct horse battery staple".to_owned(),
            profile,
        })
        .await
        .unwrap();
    assert_eq!(registered.profile["avatar"], "AQIDBA==");
    assert_eq!(registered.profile["joined_at"], "2024-02-03T04:05:06+00:00");

    server
        .handle_add_role(registered.id.clone(), "administrator".to_owned())
        .await
        .unwrap();
    server
        .handle_add_permission("administrator".to_owned(), "rbac.users.write".to_owned())
        .await
        .unwrap();
    let token = server
        .handle_login(LoginRequest {
            email: "admin@example.test".to_owned(),
            password: "correct horse battery staple".to_owned(),
            grant_type: "password".to_owned(),
        })
        .await
        .unwrap();
    assert!(
        server
            .require_permission(&token.access_token, "rbac.users.write")
            .is_ok()
    );
    assert!(
        server
            .require_permission(&token.access_token, "rbac.roles.write")
            .is_err()
    );

    let updated = server
        .handle_update_profile(
            registered.id,
            HashMap::from([(
                "joined_at".to_owned(),
                "2025-03-04T05:06:07+00:00".to_owned(),
            )]),
        )
        .await
        .unwrap();
    assert_eq!(updated.profile["joined_at"], "2025-03-04T05:06:07+00:00");
}

fn test_key() -> String {
    let key = SymmetricKey::<V4>::generate().unwrap();
    let mut paserk = String::new();
    key.fmt(&mut paserk).unwrap();
    paserk
}
