use std::future::Future;

use json_rpc_2_server::{PluginHandle, RegistrationError, RpcError, RpcServer, ServerPlugin};
use serde_json::Value;

use crate::{AccessTokenClaims, AuthError, JsonRpcAuthServer, register_auth_methods};

/// A verified principal and business parameters, with authentication fields removed.
pub struct AuthorizedRequest {
    pub claims: AccessTokenClaims,
    pub params: Value,
}

/// Storage-independent authentication plugin for JSON-RPC-2 backend builders.
#[derive(Clone)]
pub struct AuthPlugin<S> {
    storage: S,
}

impl<S> AuthPlugin<S>
where
    S: JsonRpcAuthServer<StorageError = AuthError> + Clone + 'static,
{
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Registers an annotated handler without changing other methods' policies.
    pub fn register<F, Fut>(
        &self,
        server: &RpcServer,
        name: impl Into<String>,
        handler: F,
    ) -> Result<(), RegistrationError>
    where
        F: Fn(Self, Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value, RpcError>> + Send + 'static,
    {
        let plugin = self.clone();
        server.register(name, move |params| handler(plugin.clone(), params))
    }

    /// Validates an access token and requires every named RBAC permission.
    ///
    /// Token parameters work identically on all JSON-RPC transports. Never use
    /// unencrypted transports to send bearer tokens over an untrusted network.
    pub fn authorize(
        &self,
        mut params: Value,
        permissions: &[&str],
    ) -> Result<AuthorizedRequest, RpcError> {
        let object = params
            .as_object_mut()
            .ok_or_else(RpcError::invalid_params)?;
        let access_token = object.remove("access_token");
        let authorization = object.remove("authorization");
        let token = match (access_token, authorization) {
            (Some(Value::String(token)), None) => token,
            (None, Some(Value::String(header))) => header
                .strip_prefix("Bearer ")
                .ok_or(AuthError::Unauthorized.into_rpc_error())?
                .to_owned(),
            _ => return Err(AuthError::Unauthorized.into_rpc_error()),
        };
        if token.is_empty() || token.trim() != token {
            return Err(AuthError::Unauthorized.into_rpc_error());
        }
        let claims = self
            .storage
            .authenticate_access_token(&token)
            .map_err(AuthError::into_rpc_error)?;
        for permission in permissions {
            self.storage
                .require_permission(&token, permission)
                .map_err(AuthError::into_rpc_error)?;
        }
        Ok(AuthorizedRequest { claims, params })
    }
}

impl<S> ServerPlugin for AuthPlugin<S>
where
    S: JsonRpcAuthServer<StorageError = AuthError> + Clone + 'static,
{
    const NAME: &'static str = "oauth2";

    async fn install(self, server: &RpcServer) -> anyhow::Result<PluginHandle> {
        self.storage.initialize_storage().await?;
        register_auth_methods(self.storage, server)?;
        Ok(PluginHandle::new())
    }
}
