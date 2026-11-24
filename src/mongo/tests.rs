use super::*;
use pasetors::{
    keys::{Generate, SymmetricKey},
    paserk::FormatAsPaserk,
    version4::V4,
};

#[test]
fn collection_prefix_can_be_configured_before_initialization() {
    let mut key = String::new();
    SymmetricKey::<V4>::generate()
        .unwrap()
        .fmt(&mut key)
        .unwrap();
    let mut auth = MongoAuthServer::new(&key, TokenConfig::new("test")).unwrap();
    assert_eq!(auth.collection_name(SESSIONS), "sessions");
    auth.set_collection_prefix("coopnav_oauth_").unwrap();
    assert_eq!(auth.collection_name(SESSIONS), "coopnav_oauth_sessions");
    assert_eq!(auth.collection_name(USERS), "coopnav_oauth_users");
    assert!(auth.set_collection_prefix("system.").is_err());
    assert_eq!(auth.collection_name(SESSIONS), "coopnav_oauth_sessions");
    let clone = auth.clone();
    assert!(auth.set_collection_prefix("other_").is_err());
    drop(clone);
    auth.set_collection_prefix("other_").unwrap();
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn configured_collections_are_isolated_from_existing_sessions() {
    use testcontainers_modules::{mongo::Mongo, testcontainers::runners::AsyncRunner};

    let mongo = Mongo::default().start().await.unwrap();
    let uri = format!(
        "mongodb://{}:{}",
        mongo.get_host().await.unwrap(),
        mongo.get_host_port_ipv4(27017).await.unwrap()
    );
    let database = mongodb::Client::with_uri_str(&uri)
        .await
        .unwrap()
        .database("oauth_isolation");
    database
        .collection::<Document>("sessions")
        .insert_one(doc! { "_id": "tms", "principal_key": "existing" })
        .await
        .unwrap();
    let mut key = String::new();
    SymmetricKey::<V4>::generate()
        .unwrap()
        .fmt(&mut key)
        .unwrap();
    let mut auth = MongoAuthServer::new(&key, TokenConfig::new("test")).unwrap();
    auth.set_collection_prefix("coopnav_oauth_").unwrap();
    auth.set_db_host(&uri);
    auth.set_db_name("oauth_isolation");
    auth.initialize_storage().await.unwrap();
    auth.handle_register(RegisterRequest {
        email: "test@example.test".to_owned(),
        password: "example password".to_owned(),
        profile: HashMap::new(),
    })
    .await
    .unwrap();
    let tokens = auth
        .handle_login_with_device(
            LoginRequest {
                email: "test@example.test".to_owned(),
                password: "example password".to_owned(),
                grant_type: "password".to_owned(),
            },
            Some(DeviceInfo {
                device_id: "phone".to_owned(),
                os: None,
            }),
        )
        .await
        .unwrap();
    auth.handle_refresh(&tokens.refresh_token).await.unwrap();
    assert_eq!(
        database
            .collection::<Document>("coopnav_oauth_sessions")
            .count_documents(doc! {})
            .await
            .unwrap(),
        1
    );
    let names = database.list_collection_names().await.unwrap();
    for name in [
        "coopnav_oauth_users",
        "coopnav_oauth_roles",
        "coopnav_oauth_sessions",
        "coopnav_oauth_external_identities",
    ] {
        assert!(names.iter().any(|entry| entry == name), "{name}");
    }
    assert_eq!(
        database
            .collection::<Document>("sessions")
            .count_documents(doc! {})
            .await
            .unwrap(),
        1
    );
}
