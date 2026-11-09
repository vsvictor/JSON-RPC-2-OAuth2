use crate::{AuthError, ProfileFieldType, RegisterRequest};
use std::collections::HashMap;

const ACCOUNT_TYPES: [&str; 2] = ["private", "corporate"];

/// Adds the built-in registration fields (text) to a storage profile schema
/// unless the application already defined them.
#[allow(dead_code)]
pub(crate) fn with_registration_fields(
    mut schema: HashMap<String, ProfileFieldType>,
) -> HashMap<String, ProfileFieldType> {
    for name in ["first_name", "last_name", "middle_name", "account_type"] {
        schema
            .entry(name.to_owned())
            .or_insert(ProfileFieldType::Text);
    }
    schema
}

/// Validates and normalizes the profile sent with `auth.register`.
///
/// Required: `first_name`, `last_name` and `account_type` (`private` or
/// `corporate`). `middle_name` is optional and dropped when empty. The profile
/// schema of the storage must define these fields (all of type text).
pub(crate) fn validate_registration(request: &mut RegisterRequest) -> Result<(), AuthError> {
    for value in request.profile.values_mut() {
        *value = value.trim().to_owned();
    }
    for name in ["first_name", "last_name"] {
        if request.profile.get(name).is_none_or(String::is_empty) {
            return Err(AuthError::InvalidParams(format!(
                "profile field `{name}` is required"
            )));
        }
    }
    if request
        .profile
        .get("middle_name")
        .is_some_and(String::is_empty)
    {
        request.profile.remove("middle_name");
    }
    let account_type = request
        .profile
        .get("account_type")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    if !ACCOUNT_TYPES.contains(&account_type.as_str()) {
        return Err(AuthError::InvalidParams(
            "profile field `account_type` must be `private` or `corporate`".to_owned(),
        ));
    }
    request
        .profile
        .insert("account_type".to_owned(), account_type);
    Ok(())
}

#[cfg(test)]
mod tests;
