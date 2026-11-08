use crate::{
    AuthError, JsonRpcAuthServer, LoginRequest, RegisterRequest, TokenResponse, UserResponse,
};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::{collections::HashMap, sync::Arc};

/// Register the common authentication, profile and RBAC procedures on a
/// JSON-RPC-2 server for any storage implementing [`JsonRpcAuthServer`].
pub fn register_auth_methods<S>(
    storage: S,
    server: &json_rpc_2_server::RpcServer,
) -> Result<(), json_rpc_2_server::RegistrationError>
where
    S: JsonRpcAuthServer<StorageError = AuthError> + Clone + 'static,
{
    register_auth_methods_with_reset_notifier(storage, server, Arc::new(|_| {}))
}

/// Delivery hook for password-reset tokens. The server never sends e-mail and
/// never logs the token; the application delivers it however it chooses.
#[derive(Clone)]
pub struct PasswordResetNotice {
    pub email: String,
    pub reset_token: String,
}

impl std::fmt::Debug for PasswordResetNotice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordResetNotice")
            .field("email", &self.email)
            .field("reset_token", &"<redacted>")
            .finish()
    }
}

pub type PasswordResetNotifier = Arc<dyn Fn(PasswordResetNotice) + Send + Sync>;

/// Like [`register_auth_methods`], delivering reset tokens to `notifier`.
pub fn register_auth_methods_with_reset_notifier<S>(
    storage: S,
    server: &json_rpc_2_server::RpcServer,
    notifier: PasswordResetNotifier,
) -> Result<(), json_rpc_2_server::RegistrationError>
where
    S: JsonRpcAuthServer<StorageError = AuthError> + Clone + 'static,
{
    let service = storage.clone();
    server.register("auth.requestPasswordReset", move |params| {
        let service = service.clone();
        let notifier = notifier.clone();
        async move {
            let request: RequestPasswordResetParams = parse_params(params)?;
            if let Some((email, reset_token)) = service
                .handle_request_password_reset(&request.email)
                .await
                .map_err(AuthError::into_rpc_error)?
            {
                notifier(PasswordResetNotice { email, reset_token });
            }
            Ok(serde_json::json!({ "accepted": true }))
        }
    })?;

    let service = storage.clone();
    server.register("auth.confirmPasswordReset", move |params| {
        let service = service.clone();
        async move {
            let request: ConfirmPasswordResetParams = parse_params(params)?;
            service
                .handle_confirm_password_reset(&request.reset_token, &request.new_password)
                .await
                .map_err(AuthError::into_rpc_error)?;
            Ok(serde_json::json!({ "reset": true }))
        }
    })?;

    register_profile_reader(storage.clone(), server)?;
    let service = storage.clone();
    server.register("auth.register", move |params| {
        let service = service.clone();
        async move {
            let request: RegisterRequest = parse_params(params)?;
            let user: UserResponse = service
                .handle_register(request)
                .await
                .map_err(AuthError::into_rpc_error)?;
            to_value(user)
        }
    })?;

    let service = storage.clone();
    server.register("auth.login", move |params| {
        let service = service.clone();
        async move {
            let request: LoginRequest = parse_params(params)?;
            let tokens: TokenResponse = service
                .handle_login(request)
                .await
                .map_err(AuthError::into_rpc_error)?;
            to_value(tokens)
        }
    })?;

    let service = storage.clone();
    server.register("auth.refresh", move |params| {
        let service = service.clone();
        async move {
            let request: RefreshParams = parse_params(params)?;
            let tokens = service
                .handle_refresh(&request.refresh_token)
                .await
                .map_err(AuthError::into_rpc_error)?;
            to_value(tokens)
        }
    })?;

    let service = storage.clone();
    server.register("auth.updateProfile", move |params| {
        let service = service.clone();
        async move {
            let request: ProfileParams = parse_params(params)?;
            let token = request.bearer_token().map_err(AuthError::into_rpc_error)?;
            let claims = service
                .authenticate_access_token(&token)
                .map_err(AuthError::into_rpc_error)?;
            let user = service
                .handle_update_profile(claims.subject, request.profile)
                .await
                .map_err(AuthError::into_rpc_error)?;
            to_value(user)
        }
    })?;

    let service = storage.clone();
    server.register("rbac.addRoleToUser", move |params| {
        let service = service.clone();
        async move {
            let request: RoleParams = parse_params(params)?;
            authorize(&service, &request.auth, "rbac.users.write")?;
            service
                .handle_add_role(request.user_id, request.role_name)
                .await
                .map_err(AuthError::into_rpc_error)?;
            Ok(Value::Null)
        }
    })?;

    let service = storage.clone();
    server.register("rbac.removeRoleFromUser", move |params| {
        let service = service.clone();
        async move {
            let request: RoleParams = parse_params(params)?;
            authorize(&service, &request.auth, "rbac.users.write")?;
            service
                .handle_remove_role(request.user_id, request.role_name)
                .await
                .map_err(AuthError::into_rpc_error)?;
            Ok(Value::Null)
        }
    })?;

    let service = storage.clone();
    server.register("rbac.addPermissionToRole", move |params| {
        let service = service.clone();
        async move {
            let request: PermissionParams = parse_params(params)?;
            authorize(&service, &request.auth, "rbac.roles.write")?;
            service
                .handle_add_permission(request.role_name, request.permission_name)
                .await
                .map_err(AuthError::into_rpc_error)?;
            Ok(Value::Null)
        }
    })?;

    let service = storage;
    server.register("rbac.removePermissionFromRole", move |params| {
        let service = service.clone();
        async move {
            let request: PermissionParams = parse_params(params)?;
            authorize(&service, &request.auth, "rbac.roles.write")?;
            service
                .handle_remove_permission(request.role_name, request.permission_name)
                .await
                .map_err(AuthError::into_rpc_error)?;
            Ok(Value::Null)
        }
    })?;

    Ok(())
}

pub(crate) fn register_profile_reader<S>(
    storage: S,
    server: &json_rpc_2_server::RpcServer,
) -> Result<(), json_rpc_2_server::RegistrationError>
where
    S: JsonRpcAuthServer<StorageError = AuthError> + Clone + 'static,
{
    let plugin = crate::AuthPlugin::new(storage.clone());
    server.register("auth.getProfile", move |params| {
        let storage = storage.clone();
        let plugin = plugin.clone();
        async move {
            let request = plugin.authorize(params, &[])?;
            let user = storage
                .handle_get_profile(request.claims.subject)
                .await
                .map_err(AuthError::into_rpc_error)?;
            to_value(user)
        }
    })
}

fn authorize<S>(
    service: &S,
    auth: &AuthenticatedParams,
    permission: &str,
) -> Result<(), json_rpc_2_server::RpcError>
where
    S: JsonRpcAuthServer<StorageError = AuthError>,
{
    let token = auth.bearer_token().map_err(AuthError::into_rpc_error)?;
    service
        .require_permission(&token, permission)
        .map(|_| ())
        .map_err(AuthError::into_rpc_error)
}

fn parse_params<T: DeserializeOwned>(params: Value) -> Result<T, json_rpc_2_server::RpcError> {
    serde_json::from_value(params).map_err(|_| json_rpc_2_server::RpcError::invalid_params())
}

fn to_value<T: serde::Serialize>(value: T) -> Result<Value, json_rpc_2_server::RpcError> {
    serde_json::to_value(value).map_err(|_| json_rpc_2_server::RpcError::internal_error())
}

#[derive(Deserialize)]
struct RefreshParams {
    refresh_token: String,
}

#[derive(Deserialize)]
struct AuthenticatedParams {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    authorization: Option<String>,
}

impl AuthenticatedParams {
    fn bearer_token(&self) -> Result<String, AuthError> {
        let value = self
            .access_token
            .as_deref()
            .or(self.authorization.as_deref())
            .ok_or(AuthError::Unauthorized)?;
        let token = value.strip_prefix("Bearer ").unwrap_or(value);
        if token.trim().is_empty() {
            return Err(AuthError::Unauthorized);
        }
        Ok(token.to_owned())
    }
}

#[derive(Deserialize)]
struct ProfileParams {
    #[serde(flatten)]
    auth: AuthenticatedParams,
    profile: HashMap<String, String>,
}

impl ProfileParams {
    fn bearer_token(&self) -> Result<String, AuthError> {
        self.auth.bearer_token()
    }
}

#[derive(Deserialize)]
struct RoleParams {
    #[serde(flatten)]
    auth: AuthenticatedParams,
    user_id: String,
    role_name: String,
}

#[derive(Deserialize)]
struct PermissionParams {
    #[serde(flatten)]
    auth: AuthenticatedParams,
    role_name: String,
    permission_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestPasswordResetParams {
    email: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmPasswordResetParams {
    #[serde(alias = "token")]
    reset_token: String,
    new_password: String,
}
