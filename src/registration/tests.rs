use super::validate_registration;
use crate::RegisterRequest;
use std::collections::HashMap;

fn request(fields: &[(&str, &str)]) -> RegisterRequest {
    RegisterRequest {
        email: "user@example.test".into(),
        password: "long-enough-password".into(),
        profile: fields
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect::<HashMap<_, _>>(),
    }
}

#[test]
fn accepts_minimal_profile() {
    let mut r = request(&[
        ("first_name", "Ada"),
        ("last_name", "Lovelace"),
        ("account_type", "Private"),
    ]);
    validate_registration(&mut r).unwrap();
    assert_eq!(r.profile["account_type"], "private");
}

#[test]
fn drops_empty_middle_name_and_keeps_filled_one() {
    let mut r = request(&[
        ("first_name", "Ada"),
        ("last_name", "Lovelace"),
        ("middle_name", "  "),
        ("account_type", "corporate"),
    ]);
    validate_registration(&mut r).unwrap();
    assert!(!r.profile.contains_key("middle_name"));

    let mut r = request(&[
        ("first_name", "Ada"),
        ("last_name", "Lovelace"),
        ("middle_name", "King"),
        ("account_type", "corporate"),
    ]);
    validate_registration(&mut r).unwrap();
    assert_eq!(r.profile["middle_name"], "King");
}

#[test]
fn rejects_missing_names_and_bad_account_type() {
    for fields in [
        vec![("last_name", "L"), ("account_type", "private")],
        vec![("first_name", "A"), ("account_type", "private")],
        vec![
            ("first_name", " "),
            ("last_name", "L"),
            ("account_type", "private"),
        ],
        vec![("first_name", "A"), ("last_name", "L")],
        vec![
            ("first_name", "A"),
            ("last_name", "L"),
            ("account_type", "business"),
        ],
    ] {
        assert!(validate_registration(&mut request(&fields)).is_err());
    }
}
