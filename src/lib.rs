//! OAuth 2.0 authentication and RBAC authorization for JSON-RPC-2 servers.
//!
//! Storage implementations include MongoDB, SQLite, PostgreSQL, MySQL, Redis, Oracle,
//! MS SQL Server, Cassandra and HBase.
//! Configure a backend and its profile schema before calling
//! [`JsonRpcAuthServer::initialize_storage`].

#[cfg(any(feature = "sqlite", feature = "sqlx"))]
extern crate sqlx_driver as sqlx;

mod error;
#[cfg(feature = "hbase")]
mod hbase_backend;
mod models;
#[cfg(feature = "mongodb")]
mod mongo;
#[cfg(feature = "mssql")]
mod mssql_backend;
#[cfg(feature = "oauth-provider-core")]
mod oauth2_providers;
#[cfg(feature = "oracle")]
mod oracle_backend;
#[cfg(feature = "mongodb")]
mod profile;
#[cfg(any(
    feature = "sqlx",
    feature = "redis",
    feature = "oracle",
    feature = "mssql",
    feature = "cassandra",
    feature = "hbase"
))]
mod profile_values;
#[cfg(feature = "redis")]
mod redis_backend;
mod rpc;
#[cfg(feature = "cassandra")]
mod scylla_backend;
#[cfg(feature = "sqlite")]
mod sqlite;
#[cfg(feature = "sqlx")]
mod sqlx_backend;
mod token;

pub use error::AuthError;
#[cfg(feature = "hbase")]
pub use hbase_backend::HbaseAuthServer;
pub use models::{
    DbConfig, ExternalIdentity, JsonRpcAuthServer, LoginRequest, OAuth2Provider, ProfileFieldType,
    ProviderAuthorization, ProviderAuthorizationRequest, ProviderCallbackRequest, RegisterRequest,
    TokenResponse, UserResponse,
};
#[cfg(feature = "mongodb")]
pub use mongo::MongoAuthServer;
#[cfg(feature = "mssql")]
pub use mssql_backend::MssqlAuthServer;
#[cfg(feature = "oracle")]
pub use oracle_backend::OracleAuthServer;
#[cfg(feature = "redis")]
pub use redis_backend::RedisAuthServer;
pub use rpc::register_auth_methods;
#[cfg(feature = "cassandra")]
pub use scylla_backend::CassandraAuthServer;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteAuthServer;
#[cfg(feature = "sqlx")]
pub use sqlx_backend::{SqlDatabase, SqlxAuthServer};
pub use token::{AccessTokenClaims, TokenConfig};
