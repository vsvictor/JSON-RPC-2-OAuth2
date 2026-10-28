use json_rpc_2_server::RpcError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
    #[error("invalid credentials or access token")]
    Unauthorized,
    #[error("insufficient permissions")]
    Forbidden,
    #[error("email is already registered")]
    DuplicateEmail,
    #[error("external identity must be linked to an existing account explicitly")]
    AccountLinkRequired,
    #[error("storage has not been initialized")]
    StorageNotInitialized,
    #[error("invalid database configuration: {0}")]
    InvalidConfiguration(String),
    #[error("MongoDB error: {0}")]
    Mongo(String),
    #[error("SQL database error: {0}")]
    Sql(String),
    #[error("Redis error: {0}")]
    Redis(String),
    #[error("Oracle database error: {0}")]
    Oracle(String),
    #[error("Microsoft SQL Server error: {0}")]
    Mssql(String),
    #[error("Cassandra error: {0}")]
    Cassandra(String),
    #[error("HBase error: {0}")]
    Hbase(String),
    #[error("password hashing error: {0}")]
    PasswordHash(String),
    #[error("token error: {0}")]
    Token(String),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[cfg(feature = "mongodb")]
impl From<mongodb::error::Error> for AuthError {
    fn from(error: mongodb::error::Error) -> Self {
        Self::Mongo(error.to_string())
    }
}

#[cfg(any(feature = "sqlite", feature = "sqlx"))]
impl From<sqlx::Error> for AuthError {
    fn from(error: sqlx::Error) -> Self {
        Self::Sql(error.to_string())
    }
}

impl AuthError {
    pub fn into_rpc_error(self) -> RpcError {
        match self {
            Self::InvalidParams(_) => RpcError::invalid_params(),
            Self::Unauthorized => RpcError::new(-32001, "Unauthorized"),
            Self::Forbidden => RpcError::new(-32003, "Forbidden"),
            Self::DuplicateEmail => RpcError::new(-32000, "Email is already registered"),
            Self::AccountLinkRequired => {
                RpcError::new(-32001, "External identity must be linked explicitly")
            }
            Self::StorageNotInitialized | Self::InvalidConfiguration(_) => {
                RpcError::new(-32000, "Authentication service is not configured")
            }
            Self::Mongo(_)
            | Self::Sql(_)
            | Self::Redis(_)
            | Self::Oracle(_)
            | Self::Mssql(_)
            | Self::Cassandra(_)
            | Self::Hbase(_)
            | Self::PasswordHash(_)
            | Self::Token(_)
            | Self::Serialization(_) => RpcError::internal_error(),
        }
    }
}
