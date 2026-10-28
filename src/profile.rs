use crate::{AuthError, ProfileFieldType};
use base64::{Engine, engine::general_purpose::STANDARD};
use mongodb::bson::{Binary, Bson, Document, spec::BinarySubtype};
use std::collections::HashMap;

pub(crate) fn parse_profile(
    schema: &HashMap<String, ProfileFieldType>,
    values: &HashMap<String, String>,
) -> Result<Document, AuthError> {
    let mut profile = Document::new();
    for (name, value) in values {
        if !valid_field_name(name) {
            return Err(AuthError::InvalidParams(format!(
                "invalid profile field name `{name}`"
            )));
        }
        let field_type = schema.get(name).ok_or_else(|| {
            AuthError::InvalidParams(format!("profile field `{name}` is not defined"))
        })?;
        let bson = match field_type {
            ProfileFieldType::Text => Bson::String(value.clone()),
            ProfileFieldType::Integer => Bson::Int64(value.parse().map_err(|_| {
                AuthError::InvalidParams(format!("profile field `{name}` must be an integer"))
            })?),
            ProfileFieldType::Float => {
                let parsed: f64 = value.parse().map_err(|_| {
                    AuthError::InvalidParams(format!("profile field `{name}` must be a float"))
                })?;
                if !parsed.is_finite() {
                    return Err(AuthError::InvalidParams(format!(
                        "profile field `{name}` must be a finite float"
                    )));
                }
                Bson::Double(parsed)
            }
            ProfileFieldType::Boolean => match value.as_str() {
                "true" | "TRUE" | "True" => Bson::Boolean(true),
                "false" | "FALSE" | "False" => Bson::Boolean(false),
                _ => {
                    return Err(AuthError::InvalidParams(format!(
                        "profile field `{name}` must be true or false"
                    )));
                }
            },
            ProfileFieldType::DateTime => {
                let datetime = chrono::DateTime::parse_from_rfc3339(value).map_err(|_| {
                    AuthError::InvalidParams(format!(
                        "profile field `{name}` must be an RFC 3339 timestamp"
                    ))
                })?;
                Bson::DateTime(mongodb::bson::DateTime::from_millis(
                    datetime.timestamp_millis(),
                ))
            }
            ProfileFieldType::Blob => Bson::Binary(Binary {
                subtype: BinarySubtype::Generic,
                bytes: STANDARD.decode(value).map_err(|_| {
                    AuthError::InvalidParams(format!("profile field `{name}` must be valid base64"))
                })?,
            }),
        };
        profile.insert(name, bson);
    }
    Ok(profile)
}

pub(crate) fn profile_to_json(
    schema: &HashMap<String, ProfileFieldType>,
    profile: Document,
) -> Result<HashMap<String, serde_json::Value>, AuthError> {
    let mut result = HashMap::new();
    for (name, bson) in profile {
        let field_type = schema.get(&name).ok_or_else(|| {
            AuthError::InvalidConfiguration(format!(
                "stored profile field `{name}` is missing from the configured schema"
            ))
        })?;
        let value = match (field_type, bson) {
            (ProfileFieldType::Text, Bson::String(value)) => serde_json::Value::String(value),
            (ProfileFieldType::Integer, Bson::Int32(value)) => {
                serde_json::Value::Number(value.into())
            }
            (ProfileFieldType::Integer, Bson::Int64(value)) => {
                serde_json::Value::Number(value.into())
            }
            (ProfileFieldType::Float, Bson::Double(value)) if value.is_finite() => {
                serde_json::Number::from_f64(value)
                    .map(serde_json::Value::Number)
                    .ok_or_else(|| {
                        AuthError::InvalidConfiguration(format!(
                            "stored profile field `{name}` is not a finite float"
                        ))
                    })?
            }
            (ProfileFieldType::Boolean, Bson::Boolean(value)) => serde_json::Value::Bool(value),
            (ProfileFieldType::DateTime, Bson::DateTime(value)) => {
                let date_time = chrono::DateTime::from_timestamp_millis(value.timestamp_millis())
                    .ok_or_else(|| {
                    AuthError::InvalidConfiguration(format!(
                        "stored profile field `{name}` is outside the RFC 3339 range"
                    ))
                })?;
                serde_json::Value::String(date_time.to_rfc3339())
            }
            (ProfileFieldType::Blob, Bson::Binary(value)) => {
                serde_json::Value::String(STANDARD.encode(value.bytes))
            }
            _ => {
                return Err(AuthError::InvalidConfiguration(format!(
                    "stored profile field `{name}` does not match its configured type"
                )));
            }
        };
        result.insert(name, value);
    }
    Ok(result)
}

fn valid_field_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_serializes_cross_database_profile_types() {
        let schema = HashMap::from([
            ("name".to_owned(), ProfileFieldType::Text),
            ("age".to_owned(), ProfileFieldType::Integer),
            ("rating".to_owned(), ProfileFieldType::Float),
            ("active".to_owned(), ProfileFieldType::Boolean),
            ("joined".to_owned(), ProfileFieldType::DateTime),
            ("avatar".to_owned(), ProfileFieldType::Blob),
        ]);
        let input = HashMap::from([
            ("name".to_owned(), "Ada".to_owned()),
            ("age".to_owned(), "37".to_owned()),
            ("rating".to_owned(), "4.5".to_owned()),
            ("active".to_owned(), "true".to_owned()),
            ("joined".to_owned(), "2024-01-02T03:04:05Z".to_owned()),
            ("avatar".to_owned(), "AAEC".to_owned()),
        ]);

        let stored = parse_profile(&schema, &input).unwrap();
        let result = profile_to_json(&schema, stored).unwrap();

        assert_eq!(result["name"], "Ada");
        assert_eq!(result["age"], 37);
        assert_eq!(result["rating"], 4.5);
        assert_eq!(result["active"], true);
        assert_eq!(result["joined"], "2024-01-02T03:04:05+00:00");
        assert_eq!(result["avatar"], "AAEC");
    }

    #[test]
    fn rejects_unknown_fields_and_invalid_types() {
        let schema = HashMap::from([("age".to_owned(), ProfileFieldType::Integer)]);
        assert!(
            parse_profile(
                &schema,
                &HashMap::from([("other".to_owned(), "1".to_owned())])
            )
            .is_err()
        );
        assert!(
            parse_profile(
                &schema,
                &HashMap::from([("age".to_owned(), "abc".to_owned())])
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_mongodb_path_injection_in_field_names() {
        let schema = HashMap::from([("profile.admin".to_owned(), ProfileFieldType::Text)]);
        let values = HashMap::from([("profile.admin".to_owned(), "true".to_owned())]);
        assert!(parse_profile(&schema, &values).is_err());
    }
}
