use json_rpc_2_oauth2::DeviceInfo;

fn device(id: &str) -> DeviceInfo {
    serde_json::from_value(serde_json::json!({ "deviceId": id })).unwrap()
}

#[test]
fn accepts_typical_device_ids() {
    for id in ["phone-1", "3F2504E0-4F89-41D3-9A0C-0305E82C3301", "a.b_c:d"] {
        assert!(device(id).validate().is_ok(), "{id}");
    }
}

#[test]
fn rejects_empty_long_or_unsafe_device_ids() {
    for id in ["", "bad id", "x$", &"a".repeat(129)] {
        assert!(device(id).validate().is_err(), "{id}");
    }
}

#[test]
fn accepts_snake_case_alias() {
    let device: DeviceInfo = serde_json::from_str(r#"{"device_id":"d1"}"#).unwrap();
    assert_eq!(device.device_id, "d1");
    assert!(device.os.is_none());
}

fn with_os(name: &str, version: &str) -> DeviceInfo {
    serde_json::from_value(serde_json::json!({
        "deviceId": "d1",
        "os": { "name": name, "version": version }
    }))
    .unwrap()
}

#[test]
fn accepts_valid_os() {
    for (name, version) in [
        ("Android", "15"),
        ("iOS", "18.2.1"),
        ("Android", "14 (API 34)"),
    ] {
        let device = with_os(name, version);
        assert!(device.validate().is_ok(), "{name} {version}");
        assert_eq!(device.os_name(), Some(name));
        assert_eq!(device.os_version(), Some(version));
    }
}

#[test]
fn rejects_invalid_os() {
    for (name, version) in [
        ("", "15"),
        ("Android", ""),
        ("And$roid", "15"),
        ("iOS", "1;2"),
    ] {
        assert!(
            with_os(name, version).validate().is_err(),
            "{name} {version}"
        );
    }
}
