use crate::{AuthError, ProfileFieldType};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde_json::{Number, Value};
use std::collections::HashMap;

pub(crate) fn parse_profile(
    schema: &HashMap<String, ProfileFieldType>,
    fields: &HashMap<String, String>,
) -> Result<HashMap<String, Value>, AuthError> {
    fields
        .iter()
        .map(|(name, raw)| {
            let kind = schema.get(name).ok_or_else(|| {
                AuthError::InvalidParams(format!("profile field `{name}` is not defined"))
            })?;
            let value = match kind {
                ProfileFieldType::Text => Value::String(raw.clone()),
                ProfileFieldType::Integer => Value::Number(
                    raw.parse::<i64>()
                        .map_err(|_| {
                            AuthError::InvalidParams(format!(
                                "profile field `{name}` must be an integer"
                            ))
                        })?
                        .into(),
                ),
                ProfileFieldType::Float => {
                    let number: f64 = raw.parse().map_err(|_| {
                        AuthError::InvalidParams(format!("profile field `{name}` must be a float"))
                    })?;
                    Value::Number(Number::from_f64(number).ok_or_else(|| {
                        AuthError::InvalidParams(format!(
                            "profile field `{name}` must be a finite float"
                        ))
                    })?)
                }
                ProfileFieldType::Boolean => Value::Bool(match raw.as_str() {
                    "true" | "TRUE" | "True" => true,
                    "false" | "FALSE" | "False" => false,
                    _ => {
                        return Err(AuthError::InvalidParams(format!(
                            "profile field `{name}` must be true or false"
                        )));
                    }
                }),
                ProfileFieldType::DateTime => {
                    let date = DateTime::parse_from_rfc3339(raw).map_err(|_| {
                        AuthError::InvalidParams(format!(
                            "profile field `{name}` must be an RFC 3339 timestamp"
                        ))
                    })?;
                    Value::String(date.with_timezone(&Utc).to_rfc3339())
                }
                ProfileFieldType::Blob => {
                    let bytes = STANDARD.decode(raw).map_err(|_| {
                        AuthError::InvalidParams(format!(
                            "profile field `{name}` must be valid Base64"
                        ))
                    })?;
                    Value::String(STANDARD.encode(bytes))
                }
            };
            Ok((name.clone(), value))
        })
        .collect()
}
