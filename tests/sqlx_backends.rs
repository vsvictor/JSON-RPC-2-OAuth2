use json_rpc_2_oauth2::{
    JsonRpcAuthServer, LoginRequest, ProfileFieldType, RegisterRequest, SqlDatabase,
    SqlxAuthServer, TokenConfig,
};
use pasetors::{
    keys::{Generate, SymmetricKey},
    paserk::FormatAsPaserk,
    version4::V4,
};
use std::collections::HashMap;
use testcontainers_modules::{
    mysql::Mysql, postgres::Postgres, testcontainers::runners::AsyncRunner,
};

#[tokio::test]
async fn postgres_auth_profile_rbac_and_refresh_work_end_to_end() {
    let container = Postgres::default().start().await.unwrap();
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let mut auth = new_server(SqlDatabase::PostgreSql, "postgres-test");
    auth.set_db_host(&format!("{host}:{port}"));
    auth.set_db_name("postgres");
    auth.set_db_user("postgres");
    auth.set_db_password("postgres");
    auth.initialize_storage().await.unwrap();
    exercise_backend(auth).await;
}

#[tokio::test]
async fn mysql_auth_profile_rbac_and_refresh_work_end_to_end() {
    let container = Mysql::default().start().await.unwrap();
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(3306).await.unwrap();
    let mut auth = new_server(SqlDatabase::MySql, "mysql-test");
    auth.set_db_host(&format!("{host}:{port}"));
    auth.set_db_name("test");
    auth.set_db_user("root");
    auth.initialize_storage().await.unwrap();
    exercise_backend(auth).await;
}

fn new_server(database: SqlDatabase, issuer: &str) -> SqlxAuthServer {
    let key = SymmetricKey::<V4>::generate().unwrap();
    let mut paserk = String::new();
    key.fmt(&mut paserk).unwrap();
    let mut auth = SqlxAuthServer::new(database, &paserk, TokenConfig::new(issuer)).unwrap();
    auth.set_profile_schema(HashMap::from([
        ("joined_at".to_owned(), ProfileFieldType::DateTime),
        ("avatar".to_owned(), ProfileFieldType::Blob),
        ("active".to_owned(), ProfileFieldType::Boolean),
    ]))
    .unwrap();
    auth
}

async fn exercise_backend(auth: SqlxAuthServer) {
    let user = auth
        .handle_register(RegisterRequest {
            email: "shared@example.test".to_owned(),
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
    auth.handle_add_role(user.id.clone(), "reader".to_owned())
        .await
        .unwrap();
    auth.handle_add_permission("reader".to_owned(), "profile.read".to_owned())
        .await
        .unwrap();
    let tokens = auth
        .handle_login(LoginRequest {
            email: "shared@example.test".to_owned(),
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
