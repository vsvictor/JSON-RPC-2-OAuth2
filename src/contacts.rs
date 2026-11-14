use crate::AuthError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::collections::HashMap;

/// Contact labels are profile metadata, never verified authentication identities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactType {
    Phone,
    Email,
    Telegram,
    Viber,
    Facebook,
    X,
    Instagram,
    Tiktok,
    Whatsapp,
    Signal,
    Linkedin,
    Website,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileContact {
    #[serde(rename = "type")]
    pub contact_type: ContactType,
    pub value: String,
}

/// Validate without inferring verification, linking accounts, or changing login email.
pub fn validate_contacts(contacts: &mut [ProfileContact]) -> Result<(), AuthError> {
    if contacts.len() > 32 {
        return Err(invalid("must contain at most 32 entries"));
    }
    for contact in contacts {
        contact.value = contact.value.trim().to_owned();
        let value = contact.value.as_str();
        if value.is_empty() || value.len() > 2048 || value.chars().any(char::is_control) {
            return Err(invalid(
                "values must be nonempty, at most 2048 bytes, and contain no control characters",
            ));
        }
        match contact.contact_type {
            ContactType::Email => {
                let mut parts = value.split('@');
                let local = parts.next().unwrap_or_default();
                let domain = parts.next().unwrap_or_default();
                if value.len() > 254
                    || local.is_empty()
                    || domain.is_empty()
                    || !domain.contains('.')
                    || parts.next().is_some()
                    || value.chars().any(char::is_whitespace)
                {
                    return Err(invalid("contains an invalid email"));
                }
            }
            ContactType::Website => {
                let url = url::Url::parse(value)
                    .map_err(|_| invalid("contains an invalid website URL"))?;
                if !matches!(url.scheme(), "http" | "https")
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || value.chars().any(char::is_whitespace)
                {
                    return Err(invalid(
                        "website values must be HTTP or HTTPS URLs with a host and no credentials",
                    ));
                }
            }
            ContactType::Phone | ContactType::Viber | ContactType::Whatsapp => {
                validate_phone(value)?;
            }
            ContactType::Signal if value.starts_with('+') => {
                validate_phone(value)?;
            }
            _ => {
                if value.contains("://") {
                    let url = url::Url::parse(value)
                        .map_err(|_| invalid("contains an invalid social URL"))?;
                    let hosts: &[&str] = match contact.contact_type {
                        ContactType::Telegram => &["t.me", "telegram.me"],
                        ContactType::Facebook => &["facebook.com", "fb.com"],
                        ContactType::X => &["x.com", "twitter.com"],
                        ContactType::Instagram => &["instagram.com"],
                        ContactType::Tiktok => &["tiktok.com"],
                        ContactType::Linkedin => &["linkedin.com"],
                        ContactType::Signal => &["signal.me"],
                        _ => unreachable!(),
                    };
                    let host = url.host_str().unwrap_or_default();
                    let host = host.strip_prefix("www.").unwrap_or(host);
                    let has_profile = !url.path().trim_matches('/').is_empty()
                        || (contact.contact_type == ContactType::Signal
                            && url.fragment().is_some_and(|fragment| !fragment.is_empty()));
                    if url.scheme() != "https"
                        || !url.username().is_empty()
                        || url.password().is_some()
                        || url.port().is_some()
                        || value.chars().any(char::is_whitespace)
                        || !hosts.contains(&host)
                        || !has_profile
                    {
                        return Err(invalid(
                            "social URLs must use HTTPS and the matching provider host and profile path",
                        ));
                    }
                } else {
                    let handle = value.strip_prefix('@').unwrap_or(value);
                    if handle.is_empty()
                        || !handle
                            .chars()
                            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
                    {
                        return Err(invalid(
                            "social values must be handles or matching HTTPS profile URLs",
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_phone(value: &str) -> Result<(), AuthError> {
    let digits = value.chars().filter(char::is_ascii_digit).count();
    if !(7..=15).contains(&digits)
        || !value.chars().enumerate().all(|(index, ch)| {
            ch.is_ascii_digit()
                || matches!(ch, ' ' | '-' | '(' | ')' | '.')
                || (index == 0 && ch == '+')
        })
    {
        return Err(invalid(
            "phone contacts must contain 7 to 15 digits with optional leading + and separators",
        ));
    }
    Ok(())
}

fn invalid(message: &str) -> AuthError {
    AuthError::InvalidParams(format!("profile field `contacts` {message}"))
}

pub(crate) fn parse_contacts(raw: &str) -> Result<Value, AuthError> {
    let mut contacts: Vec<ProfileContact> = serde_json::from_str(raw)
        .map_err(|_| invalid("must be an array of {type, value} contacts"))?;
    validate_contacts(&mut contacts)?;
    Ok(serde_json::to_value(contacts)?)
}

pub(crate) fn deserialize_profile<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = HashMap::<String, Value>::deserialize(deserializer)?;
    values
        .into_iter()
        .map(|(name, value)| {
            let raw = match value {
                Value::String(raw) => raw,
                Value::Array(_) if name == "contacts" => value.to_string(),
                _ => {
                    return Err(serde::de::Error::custom(format!(
                        "profile field `{name}` must be a string (contacts accepts an array)"
                    )));
                }
            };
            Ok((name, raw))
        })
        .collect()
}

pub(crate) fn serialize_profile<S>(
    profile: &HashMap<String, String>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut values: HashMap<String, Value> = profile
        .iter()
        .map(|(name, value)| (name.clone(), Value::String(value.clone())))
        .collect();
    if let Some(raw) = profile.get("contacts") {
        values.insert(
            "contacts".to_owned(),
            parse_contacts(raw).map_err(serde::ser::Error::custom)?,
        );
    }
    values.serialize(serializer)
}

pub(crate) fn with_legacy_contacts(mut user: crate::UserResponse) -> crate::UserResponse {
    user.profile
        .entry("contacts".to_owned())
        .or_insert_with(|| {
            if user.email.is_empty() {
                serde_json::json!([])
            } else {
                serde_json::json!([{ "type": "email", "value": user.email }])
            }
        });
    user
}

#[cfg(test)]
mod tests;
