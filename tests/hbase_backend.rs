use json_rpc_2_oauth2::{
    AuthError, HbaseAuthServer, JsonRpcAuthServer, LoginRequest, ProfileFieldType, RegisterRequest,
    TokenConfig,
};
use pasetors::{
    keys::{Generate, SymmetricKey},
    paserk::FormatAsPaserk,
    version4::V4,
};
use std::{collections::HashMap, time::Duration};
use testcontainers_modules::testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};

#[tokio::test]
async fn hbase_auth_profile_rbac_and_refresh_work_end_to_end() {
    let container = GenericImage::new("harisekhon/hbase", "2.1")
        .with_exposed_port(9090.tcp())
        .with_wait_for(WaitFor::message_on_stdout(
            "Using default thrift server type",
        ))
        .with_startup_timeout(Duration::from_secs(300))
        .start()
        .await
        .unwrap();
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(9090).await.unwrap();
    let address = format!("{host}:{port}");

    let key = SymmetricKey::<V4>::generate().unwrap();
    let mut paserk = String::new();
    key.fmt(&mut paserk).unwrap();
    let mut auth = HbaseAuthServer::new(&paserk, TokenConfig::new("hbase-test")).unwrap();
    auth.set_db_host(&address);
    auth.set_db_name("auth_test");
    auth.define_profile_schema(HashMap::from([
        ("joined_at".to_owned(), ProfileFieldType::DateTime),
        ("avatar".to_owned(), ProfileFieldType::Blob),
        ("active".to_owned(), ProfileFieldType::Boolean),
    ]));
    let mut attempts = 0;
    while let Err(error) = auth.initialize_storage().await {
        attempts += 1;
        assert!(attempts < 60, "HBase did not become ready: {error}");
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    let user = auth
        .handle_register(RegisterRequest {
            email: "hbase@example.test".to_owned(),
            password: "a long secure password".to_owned(),
            profile: HashMap::from([
                ("joined_at".to_owned(), "2024-01-02T03:04:05Z".to_owned()),
                ("avatar".to_owned(), "AQIDBA==".to_owned()),
                ("active".to_owned(), "true".to_owned()),
            ]),
        })
        .await
        .unwrap();
    assert_eq!(user.profile["avatar"], "AQIDBA==");
    assert!(matches!(
        auth.handle_register(RegisterRequest {
            email: "HBASE@example.test".to_owned(),
            password: "another secure password".to_owned(),
            profile: HashMap::new(),
        })
        .await,
        Err(AuthError::DuplicateEmail)
    ));

    auth.handle_add_role(user.id.clone(), "reader".to_owned())
        .await
        .unwrap();
    auth.handle_add_permission("reader".to_owned(), "profile.read".to_owned())
        .await
        .unwrap();
    let tokens = auth
        .handle_login(LoginRequest {
            email: "hbase@example.test".to_owned(),
            password: "a long secure password".to_owned(),
            grant_type: "password".to_owned(),
        })
        .await
        .unwrap();
    assert!(
        auth.require_permission(&tokens.access_token, "profile.read")
            .is_ok()
    );
    assert!(matches!(
        auth.require_permission(&tokens.access_token, "profile.write"),
        Err(AuthError::Forbidden)
    ));
    let renewed = auth.handle_refresh(&tokens.refresh_token).await.unwrap();
    assert!(
        auth.authenticate_access_token(&renewed.access_token)
            .is_ok()
    );

    let updated = auth
        .handle_update_profile(
            user.id.clone(),
            HashMap::from([("active".to_owned(), "false".to_owned())]),
        )
        .await
        .unwrap();
    assert_eq!(updated.profile["active"], false);

    auth.handle_remove_permission("reader".to_owned(), "profile.read".to_owned())
        .await
        .unwrap();
    auth.handle_remove_role(user.id, "reader".to_owned())
        .await
        .unwrap();
}
