//! OAuth 2.0 authentication and RBAC authorization for JSON-RPC-2 servers.
//!
//! Storage implementations include MongoDB, SQLite, PostgreSQL, MySQL, Redis, Oracle,
//! MS SQL Server, Cassandra and HBase.
//! Configure a backend and its profile schema before calling
//! [`JsonRpcAuthServer::initialize_storage`].

#[cfg(any(feature = "sqlite", feature = "sqlx"))]
extern crate sqlx_driver as sqlx;

mod contacts;
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
#[cfg(feature = "auth-storage-core")]
mod password;
mod plugin;
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
mod registration;
mod rpc;
#[cfg(feature = "cassandra")]
mod scylla_backend;
#[cfg(feature = "sqlite")]
mod sqlite;
#[cfg(feature = "sqlx")]
mod sqlx_backend;
mod token;

pub use contacts::{ContactType, ProfileContact, validate_contacts};

pub use error::AuthError;
#[cfg(feature = "hbase")]
pub use hbase_backend::HbaseAuthServer;
#[cfg(feature = "annotations")]
pub use json_rpc_2_oauth2_macros::authorize;
pub use json_rpc_2_server::{RpcError, RpcServer, ServerPlugin};
pub use models::{
    DbConfig, DeviceInfo, ExternalIdentity, JsonRpcAuthServer, LoginRequest, OAuth2Provider,
    OsInfo, ProfileFieldType, ProviderAuthorization, ProviderAuthorizationRequest,
    ProviderCallbackRequest, RegisterRequest, TokenResponse, UserResponse,
};
#[cfg(feature = "mongodb")]
pub use mongo::MongoAuthServer;
#[cfg(feature = "mssql")]
pub use mssql_backend::MssqlAuthServer;
#[cfg(feature = "oracle")]
pub use oracle_backend::OracleAuthServer;
pub use plugin::{AuthPlugin, AuthorizedRequest};
#[cfg(feature = "redis")]
pub use redis_backend::RedisAuthServer;
pub use rpc::{
    PasswordResetNotice, PasswordResetNotifier, register_auth_methods,
    register_auth_methods_with_reset_notifier,
};
#[cfg(feature = "cassandra")]
pub use scylla_backend::CassandraAuthServer;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteAuthServer;
#[cfg(feature = "sqlx")]
pub use sqlx_backend::{SqlDatabase, SqlxAuthServer};
pub use token::{AccessTokenClaims, TokenConfig};

#[doc(hidden)]
pub mod __private {
    pub use serde_json::Value;
}
