use json_rpc_2_oauth2::{
    DeviceInfo, JsonRpcAuthServer, LoginRequest, MongoAuthServer, OsInfo, RegisterRequest,
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

const EMAIL: &str = "device@example.test";
const PASSWORD: &str = "correct horse battery staple";

fn login_request() -> LoginRequest {
    LoginRequest {
        email: EMAIL.to_owned(),
        password: PASSWORD.to_owned(),
        grant_type: "password".to_owned(),
    }
}

fn device(id: &str) -> Option<DeviceInfo> {
    Some(DeviceInfo {
        device_id: id.to_owned(),
        os: Some(OsInfo {
            name: "Android".to_owned(),
            version: "15".to_owned(),
        }),
    })
}

#[tokio::test]
async fn each_device_has_its_own_session() {
    // MONGODB_TEST_HOST (host:port) lets the test run without Docker.
    let (_container, host) = match std::env::var("MONGODB_TEST_HOST") {
        Ok(host) => (None, host),
        Err(_) => {
            let mongo = Mongo::default().start().await.unwrap();
            let host = format!(
                "{}:{}",
                mongo.get_host().await.unwrap(),
                mongo.get_host_port_ipv4(27017).await.unwrap()
            );
            (Some(mongo), host)
        }
    };
    let mut server =
        MongoAuthServer::new(&test_key(), TokenConfig::new("device-sessions")).unwrap();
    server.set_db_host(&host);
    server.set_db_name(&format!(
        "device_sessions_{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
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
        .handle_login_with_device(login_request(), device("phone-1"))
        .await
        .unwrap();
    let tablet = server
        .handle_login_with_device(login_request(), device("tablet-1"))
        .await
        .unwrap();
    assert_ne!(phone.refresh_token, tablet.refresh_token);

    // Both devices refresh independently.
    let phone_next = server.handle_refresh(&phone.refresh_token).await.unwrap();
    server.handle_refresh(&tablet.refresh_token).await.unwrap();

    // Signing in again on the phone replaces only the phone session.
    server
        .handle_login_with_device(login_request(), device("phone-1"))
        .await
        .unwrap();
    assert!(server.handle_refresh(&phone.refresh_token).await.is_err());
    assert!(
        server
            .handle_refresh(&phone_next.refresh_token)
            .await
            .is_err()
    );
    server.handle_refresh(&tablet.refresh_token).await.unwrap();

    // Login without a device keeps working and is not tied to a session.
    let legacy = server.handle_login(login_request()).await.unwrap();
    server.handle_refresh(&legacy.refresh_token).await.unwrap();

    // Invalid device ids are rejected.
    assert!(
        server
            .handle_login_with_device(login_request(), device("bad id!"))
            .await
            .is_err()
    );
}

fn test_key() -> String {
    let key = SymmetricKey::<V4>::generate().unwrap();
    let mut paserk = String::new();
    key.fmt(&mut paserk).unwrap();
    paserk
}
