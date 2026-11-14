use super::*;
use crate::{ProfileFieldType, RegisterRequest, UserResponse};
use serde_json::json;

fn contacts() -> Value {
    json!([
        {"type": "phone", "value": "+1 (202) 555-0100"},
        {"type": "email", "value": "contact@example.invalid"},
        {"type": "telegram", "value": "@example_contact"},
        {"type": "viber", "value": "+12025550101"},
        {"type": "facebook", "value": "example.contact"},
        {"type": "x", "value": "example_contact"},
        {"type": "instagram", "value": "@example.contact"},
        {"type": "tiktok", "value": "@example_contact"},
        {"type": "whatsapp", "value": "+12025550123"},
        {"type": "signal", "value": "example.123"},
        {"type": "linkedin", "value": "https://www.linkedin.com/in/example-contact"},
        {"type": "website", "value": "https://example.invalid"}
    ])
}

#[test]
fn native_contacts_and_legacy_scalar_fields_round_trip() {
    let input = json!({
        "email": "login@example.invalid",
        "password": "test-only-password",
        "profile": {"first_name": "Ada", "contacts": contacts()}
    });
    let request: RegisterRequest = serde_json::from_value(input.clone()).unwrap();
    assert_eq!(request.profile["first_name"], "Ada");
    assert_eq!(
        parse_contacts(&request.profile["contacts"]).unwrap(),
        contacts()
    );
    assert_eq!(serde_json::to_value(request).unwrap(), input);
    let legacy: RegisterRequest = serde_json::from_value(json!({
        "email": "login@example.invalid", "password": "test-only-password",
        "profile": {"contacts": "[]", "age": "37", "active": "true"}
    }))
    .unwrap();
    assert_eq!(legacy.profile["age"], "37");
    assert_eq!(
        serde_json::to_value(legacy).unwrap()["profile"]["contacts"],
        json!([])
    );
    for profile in [
        json!({"first_name": []}),
        json!({"active": true}),
        json!({"contacts": null}),
    ] {
        assert!(serde_json::from_value::<RegisterRequest>(json!({
            "email": "login@example.invalid", "password": "test-only-password", "profile": profile
        })).is_err());
    }
}

#[test]
fn validation_is_shared_and_rejects_malformed_contacts() {
    assert_eq!(parse_contacts(&contacts().to_string()).unwrap(), contacts());
    assert_eq!(
        parse_contacts(r#"[{"type":"email","value":"  other@example.invalid  "}]"#).unwrap(),
        json!([{"type":"email","value":"other@example.invalid"}])
    );
    for value in [
        json!({}),
        json!(null),
        json!([null]),
        json!(["email"]),
        json!([{"type":"unknown","value":"something"}]),
        json!([{"type":"Email","value":"contact@example.invalid"}]),
        json!([{"type":"email","value":7}]),
        json!([{"type":"email","value":"missing-at.invalid"}]),
        json!([{"type":"email","value":"a@@example.invalid"}]),
        json!([{"type":"phone","value":"123"}]),
        json!([{"type":"viber","value":"javascript:alert(1)"}]),
        json!([{"type":"telegram","value":""}]),
        json!([{"type":"telegram","value":"line\nbreak"}]),
        json!([{"type":"facebook","value":"https://evil.invalid/example"}]),
        json!([{"type":"x","value":"http://x.com/example"}]),
        json!([{"type":"instagram","value":"https://user@instagram.com/example"}]),
        json!([{"type":"tiktok","value":"https://tiktok.com/"}]),
        json!([{"type":"whatsapp","value":"not-a-phone"}]),
        json!([{"type":"signal","value":"+123"}]),
        json!([{"type":"signal","value":"https://signal.me/"}]),
        json!([{"type":"signal","value":"https://evil.invalid/#eu/example"}]),
        json!([{"type":"linkedin","value":"https://evil.invalid/in/example"}]),
        json!([{"type":"website","value":"javascript:alert(1)"}]),
        json!([{"type":"website","value":"ftp://example.invalid"}]),
        json!([{"type":"website","value":"https://user:pass@example.invalid"}]),
        json!([{"type":"website","value":"example.invalid"}]),
        json!([{"type":"website","value":"https://example.invalid/a b"}]),
        json!([{"type":"email","value":"contact@example.invalid", "verified":true}]),
        json!(vec![
            json!({"type":"email","value":"contact@example.invalid"});
            33
        ]),
        json!([{"type":"telegram","value":"a".repeat(2049)}]),
    ] {
        assert!(
            matches!(
                parse_contacts(&value.to_string()),
                Err(AuthError::InvalidParams(_))
            ),
            "{value}"
        );
    }
    for (kind, url) in [
        ("telegram", "https://t.me/example_contact"),
        ("facebook", "https://www.facebook.com/example.contact"),
        ("x", "https://x.com/example_contact"),
        ("instagram", "https://instagram.com/example.contact"),
        ("tiktok", "https://www.tiktok.com/@example_contact"),
        ("linkedin", "https://www.linkedin.com/in/example-contact"),
        ("signal", "https://signal.me/#eu/example_token"),
        ("signal", "https://signal.me/#p/+12025550123"),
        ("signal", "+12025550123"),
        ("signal", "example.123"),
        ("whatsapp", "+1 (202) 555-0123"),
        ("website", "https://example.invalid"),
        ("website", "http://example.invalid:8080/contact"),
    ] {
        parse_contacts(&json!([{"type":kind,"value":url}]).to_string()).unwrap();
    }
}

#[test]
fn missing_contacts_fall_back_but_empty_contacts_do_not() {
    let user = UserResponse {
        id: "fake-user".into(),
        email: "login@example.invalid".into(),
        created_at: "2026-01-01T00:00:00Z".into(),
        roles: vec![],
        profile: HashMap::new(),
    };
    let fallback = with_legacy_contacts(user.clone());
    assert_eq!(
        fallback.profile["contacts"],
        json!([{"type":"email","value":"login@example.invalid"}])
    );
    let mut empty = user;
    empty.profile.insert("contacts".into(), json!([]));
    assert_eq!(with_legacy_contacts(empty).profile["contacts"], json!([]));
}

#[test]
fn contacts_is_a_reserved_builtin_schema_field() {
    let schema = crate::registration::with_registration_fields(HashMap::from([(
        "contacts".into(),
        ProfileFieldType::Text,
    )]));
    assert_eq!(schema["contacts"], ProfileFieldType::Contacts);
}

#[cfg(any(
    feature = "sqlx",
    feature = "redis",
    feature = "oracle",
    feature = "mssql",
    feature = "cassandra",
    feature = "hbase"
))]
#[test]
fn json_storage_backends_round_trip_structured_contacts() {
    let schema = crate::registration::with_registration_fields(HashMap::new());
    let values = HashMap::from([("contacts".into(), contacts().to_string())]);
    let parsed = crate::profile_values::parse_profile(&schema, &values).unwrap();
    let stored = serde_json::to_string(&parsed).unwrap();
    let restored: HashMap<String, Value> = serde_json::from_str(&stored).unwrap();
    assert_eq!(restored["contacts"], contacts());
    assert!(
        crate::profile_values::parse_profile(
            &schema,
            &HashMap::from([(
                "contacts".into(),
                r#"[{"type":"email","value":"bad"}]"#.into()
            ),])
        )
        .is_err()
    );
}

#[cfg(feature = "mongodb")]
#[test]
fn mongodb_round_trips_contacts_as_bson_array() {
    use mongodb::bson::Bson;
    let schema = crate::registration::with_registration_fields(HashMap::new());
    let values = HashMap::from([("contacts".into(), contacts().to_string())]);
    let stored = crate::profile::parse_profile(&schema, &values).unwrap();
    assert!(matches!(stored.get("contacts"), Some(Bson::Array(_))));
    let restored = crate::profile::profile_to_json(&schema, stored).unwrap();
    assert_eq!(restored["contacts"], contacts());
}

#[cfg(feature = "sqlx")]
#[tokio::test]
async fn sqlx_storage_round_trips_large_contact_arrays_and_empty_updates() {
    use crate::{JsonRpcAuthServer, SqlDatabase, SqlxAuthServer, TokenConfig};
    use pasetors::{
        keys::{Generate, SymmetricKey},
        paserk::FormatAsPaserk,
        version4::V4,
    };
    let mut key = String::new();
    SymmetricKey::<V4>::generate()
        .unwrap()
        .fmt(&mut key)
        .unwrap();
    let mut storage = SqlxAuthServer::new(
        SqlDatabase::Sqlite,
        &key,
        TokenConfig::new("contact-sqlx-test"),
    )
    .unwrap();
    storage.set_db_host("sqlite::memory:");
    storage.initialize_storage().await.unwrap();
    let user = storage
        .handle_register(RegisterRequest {
            email: "login@example.invalid".into(),
            password: "test-only-password".into(),
            profile: HashMap::new(),
        })
        .await
        .unwrap();
    assert_eq!(
        user.profile["contacts"],
        json!([{"type":"email","value":"login@example.invalid"}])
    );
    let large = json!(vec![
        json!({"type":"telegram","value":"a".repeat(2048)});
        32
    ]);
    let updated = storage
        .handle_update_profile(
            user.id.clone(),
            HashMap::from([("contacts".into(), large.to_string())]),
        )
        .await
        .unwrap();
    assert_eq!(updated.profile["contacts"], large);
    assert_eq!(
        storage
            .handle_get_profile(user.id.clone())
            .await
            .unwrap()
            .profile["contacts"],
        large
    );
    let cleared = storage
        .handle_update_profile(
            user.id.clone(),
            HashMap::from([("contacts".into(), "[]".into())]),
        )
        .await
        .unwrap();
    assert_eq!(cleared.profile["contacts"], json!([]));
    assert_eq!(
        storage.handle_get_profile(user.id).await.unwrap().profile["contacts"],
        json!([])
    );
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use crate::{
        ExternalIdentity, JsonRpcAuthServer, LoginRequest, OAuth2Provider, RpcServer,
        SqliteAuthServer, TokenConfig,
    };
    use pasetors::{
        keys::{Generate, SymmetricKey},
        paserk::FormatAsPaserk,
        version4::V4,
    };

    fn storage() -> SqliteAuthServer {
        let mut key = String::new();
        SymmetricKey::<V4>::generate()
            .unwrap()
            .fmt(&mut key)
            .unwrap();
        let mut storage = SqliteAuthServer::new(&key, TokenConfig::new("contact-test")).unwrap();
        storage.set_db_host(":memory:");
        storage
    }

    async fn call(rpc: &RpcServer, method: &str, params: Value) -> Value {
        let request = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        serde_json::from_slice(
            &rpc.handle_bytes(&serde_json::to_vec(&request).unwrap())
                .await
                .unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn registration_updates_and_both_bearer_modes_preserve_login_email() {
        let storage = storage();
        storage.initialize_storage().await.unwrap();
        let rpc = RpcServer::new();
        storage.register_auth_methods(&rpc).unwrap();
        let user = call(&rpc, "auth.register", json!({
            "email":"login@example.invalid","password":"test-only-password",
            "profile":{"first_name":"Ada","last_name":"Example","account_type":"private","contacts":contacts()}
        })).await;
        assert!(user.get("error").is_none(), "{user}");
        assert_eq!(user["result"]["profile"]["contacts"], contacts());
        let tokens = storage
            .handle_login(LoginRequest {
                email: "login@example.invalid".into(),
                password: "test-only-password".into(),
                grant_type: "password".into(),
            })
            .await
            .unwrap();
        for auth in [
            json!({"access_token":tokens.access_token}),
            json!({"authorization":format!("Bearer {}", tokens.access_token)}),
        ] {
            let mut params = auth.clone();
            params["profile"] = json!({"contacts":[]});
            let cleared = call(&rpc, "auth.updateProfile", params.clone()).await;
            assert_eq!(
                cleared["result"]["profile"]["contacts"],
                json!([]),
                "{cleared}"
            );
            assert_eq!(cleared["result"]["email"], "login@example.invalid");
            let loaded = call(&rpc, "auth.getProfile", auth.clone()).await;
            assert_eq!(loaded["result"]["profile"]["contacts"], json!([]));
            params["profile"] = json!({"contacts":contacts()});
            assert_eq!(
                call(&rpc, "auth.updateProfile", params.clone()).await["result"]["profile"]["contacts"],
                contacts()
            );
            params["profile"] = json!({"contacts":[{"type":"email","value":"bad"}]});
            assert_eq!(
                call(&rpc, "auth.updateProfile", params).await["error"]["code"],
                -32602
            );
            assert_eq!(
                call(&rpc, "auth.getProfile", auth).await["result"]["profile"]["contacts"],
                contacts()
            );
        }
        assert!(
            storage
                .handle_login(LoginRequest {
                    email: "contact@example.invalid".into(),
                    password: "test-only-password".into(),
                    grant_type: "password".into(),
                })
                .await
                .is_err()
        );
        assert!(
            storage
                .handle_request_password_reset("contact@example.invalid")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            storage
                .handle_request_password_reset("login@example.invalid")
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            call(
                &rpc,
                "auth.updateProfile",
                json!({"profile":{"contacts":[]}})
            )
            .await["error"]["code"],
            -32001
        );
    }

    #[tokio::test]
    async fn external_identities_keep_verified_linking_rules_and_explicit_empty_contacts() {
        let storage = storage();
        storage.initialize_storage().await.unwrap();
        let user = storage
            .handle_register(RegisterRequest {
                email: "login@example.invalid".into(),
                password: "test-only-password".into(),
                profile: HashMap::from([("contacts".into(), contacts().to_string())]),
            })
            .await
            .unwrap();
        let contact_identity = ExternalIdentity {
            provider: OAuth2Provider::Google,
            subject: "fake-contact-identity".into(),
            email: Some("contact@example.invalid".into()),
            email_verified: false,
        };
        assert!(
            storage
                .handle_external_login(contact_identity.clone())
                .await
                .is_err()
        );
        let tokens = storage
            .handle_external_login(ExternalIdentity {
                email_verified: true,
                ..contact_identity
            })
            .await
            .unwrap();
        let external_id = storage
            .authenticate_access_token(&tokens.access_token)
            .unwrap()
            .subject;
        assert_ne!(external_id, user.id);
        assert_eq!(
            storage
                .handle_get_profile(external_id.clone())
                .await
                .unwrap()
                .profile["contacts"],
            json!([{"type":"email","value":"contact@example.invalid"}])
        );
        storage
            .handle_update_profile(
                external_id.clone(),
                HashMap::from([("contacts".into(), "[]".into())]),
            )
            .await
            .unwrap();
        let tokens = storage
            .handle_external_login(ExternalIdentity {
                provider: OAuth2Provider::Google,
                subject: "fake-contact-identity".into(),
                email: None,
                email_verified: false,
            })
            .await
            .unwrap();
        assert_eq!(
            storage
                .authenticate_access_token(&tokens.access_token)
                .unwrap()
                .subject,
            external_id
        );
        assert_eq!(
            storage
                .handle_get_profile(external_id)
                .await
                .unwrap()
                .profile["contacts"],
            json!([])
        );
    }

    #[tokio::test]
    async fn legacy_sqlite_schema_migrates_and_contacts_survive_reopening() {
        use sqlx::Connection;
        let path = format!("target/contact-migration-{}.sqlite", uuid::Uuid::new_v4());
        let uri = format!("sqlite://{path}?mode=rwc");
        let mut connection = sqlx::SqliteConnection::connect(&uri).await.unwrap();
        sqlx::query("CREATE TABLE user_profiles (user_id TEXT PRIMARY KEY NOT NULL)")
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();
        let mut storage = storage();
        storage.set_db_host(&path);
        storage.initialize_storage().await.unwrap();
        let user = storage
            .handle_register(RegisterRequest {
                email: "legacy@example.invalid".into(),
                password: "test-only-password".into(),
                profile: HashMap::new(),
            })
            .await
            .unwrap();
        assert_eq!(
            user.profile["contacts"],
            json!([{"type":"email","value":"legacy@example.invalid"}])
        );
        storage
            .handle_update_profile(
                user.id.clone(),
                HashMap::from([("contacts".into(), contacts().to_string())]),
            )
            .await
            .unwrap();
        let mut reopened = super::sqlite::storage();
        reopened.set_db_host(&path);
        reopened.initialize_storage().await.unwrap();
        assert_eq!(
            reopened.handle_get_profile(user.id).await.unwrap().profile["contacts"],
            contacts()
        );
        drop(reopened);
        drop(storage);
        std::fs::remove_file(path).unwrap();
    }
}
