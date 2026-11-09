use std::collections::HashMap;

use json_rpc_2_oauth2::{
    DeviceInfo, JsonRpcAuthServer, LoginRequest, OsInfo, RegisterRequest, SqliteAuthServer,
    TokenConfig,
};
use pasetors::{
    keys::{Generate, SymmetricKey},
    paserk::FormatAsPaserk,
    version4::V4,
};

const EMAIL: &str = "device@example.test";
const PASSWORD: &str = "correct horse battery staple";

fn login_request() -> LoginRequest {
    LoginRequest {
        email: EMAIL.to_owned(),
        password: PASSWORD.to_owned(),
        grant_type: "password".to_owned(),
    }
}

fn device(id: &str, os: &str, version: &str) -> Option<DeviceInfo> {
    Some(DeviceInfo {
        device_id: id.to_owned(),
        os: Some(OsInfo {
            name: os.to_owned(),
            version: version.to_owned(),
        }),
    })
}

#[tokio::test]
async fn each_device_has_its_own_session() {
    let key = SymmetricKey::<V4>::generate().unwrap();
    let mut paserk = String::new();
    key.fmt(&mut paserk).unwrap();
    let mut server = SqliteAuthServer::new(&paserk, TokenConfig::new("sqlite-devices")).unwrap();
    server.set_db_host(":memory:");
    server.initialize_storage().await.unwrap();
    server
        .handle_register(RegisterRequest {
            email: EMAIL.to_owned(),
            password: PASSWORD.to_owned(),
            profile: HashMap::new(),
        })
        .await
        .unwrap();

    let phone = server
        .handle_login_with_device(login_request(), device("phone-1", "Android", "15"))
        .await
        .unwrap();
    let tablet = server
        .handle_login_with_device(login_request(), device("tablet-1", "iOS", "18.2"))
        .await
        .unwrap();
    assert_ne!(phone.refresh_token, tablet.refresh_token);

    let phone_next = server.handle_refresh(&phone.refresh_token).await.unwrap();
    server.handle_refresh(&tablet.refresh_token).await.unwrap();

    server
        .handle_login_with_device(login_request(), device("phone-1", "Android", "16"))
        .await
        .unwrap();
    assert!(server.handle_refresh(&phone.refresh_token).await.is_err());
    assert!(server.handle_refresh(&phone_next.refresh_token).await.is_err());
    server.handle_refresh(&tablet.refresh_token).await.unwrap();

    let legacy = server.handle_login(login_request()).await.unwrap();
    server.handle_refresh(&legacy.refresh_token).await.unwrap();

    assert!(
        server
            .handle_login_with_device(login_request(), device("phone-1", "And$roid", "15"))
            .await
            .is_err()
    );
}
