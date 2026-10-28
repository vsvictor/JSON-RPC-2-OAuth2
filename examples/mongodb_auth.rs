use json_rpc_2_oauth2::{
    JsonRpcAuthServer, MongoAuthServer, ProfileFieldType, RegisterRequest, TokenConfig,
};
use std::{
    collections::HashMap,
    env,
    error::Error,
    time::{SystemTime, UNIX_EPOCH},
};

fn env_or_default(name: &str, default: &str) -> Result<String, env::VarError> {
    match env::var(name) {
        Ok(value) => Ok(value),
        Err(env::VarError::NotPresent) => Ok(default.to_owned()),
        Err(error) => Err(error),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let paserk_key = std::env::var("PASETO_LOCAL_KEY")?;
    let mut auth = MongoAuthServer::new(&paserk_key, TokenConfig::new("example-service"))?;
    auth.set_db_host(&env_or_default(
        "MONGODB_HOST",
        "mongodb://localhost:27017",
    )?);
    auth.set_db_name(&env_or_default("MONGODB_DATABASE", "auth")?);

    match env::var("MONGODB_USER") {
        Ok(user) => auth.set_db_user(&user),
        Err(env::VarError::NotPresent) => {}
        Err(error) => return Err(error.into()),
    }
    match env::var("MONGODB_PASSWORD") {
        Ok(password) => auth.set_db_password(&password),
        Err(env::VarError::NotPresent) => {}
        Err(error) => return Err(error.into()),
    }

    auth.set_profile_schema(HashMap::from([
        ("display_name".to_owned(), ProfileFieldType::Text),
        ("active".to_owned(), ProfileFieldType::Boolean),
    ]))?;
    auth.initialize_storage().await?;

    let unique_id = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let user = auth
        .handle_register(RegisterRequest {
            email: format!("mongo-reader-{unique_id}@example.test"),
            password: "example-only-password".to_owned(),
            profile: HashMap::from([
                ("display_name".to_owned(), "Mongo Reader".to_owned()),
                ("active".to_owned(), "true".to_owned()),
            ]),
        })
        .await?;
    println!("Created user {} ({})", user.email, user.id);
    Ok(())
}
