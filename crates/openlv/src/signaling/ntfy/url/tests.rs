use super::*;

#[test]
fn token_userinfo_authorizes_with_bearer() {
    let info = parse_ntfy_url("https://tk_secret@ntfy.example.com/").unwrap();

    assert_eq!(info.host, "ntfy.example.com");
    assert_eq!(
        info.credentials.unwrap().authorization(),
        "Bearer tk_secret"
    );
}

#[test]
fn user_password_userinfo_authorizes_with_basic() {
    let info = parse_ntfy_url("ntfys://user:password@ntfy.example.com").unwrap();

    assert_eq!(info.protocol, "https");
    assert_eq!(info.host, "ntfy.example.com");
    assert_eq!(
        info.credentials.unwrap().authorization(),
        "Basic dXNlcjpwYXNzd29yZA=="
    );
}

#[test]
fn url_without_userinfo_has_no_credentials() {
    let info = parse_ntfy_url("https://ntfy.sh/?auth=token").unwrap();

    assert_eq!(info.credentials, None);
    assert_eq!(info.parameters.as_deref(), Some("?auth=token"));
}

#[test]
fn debug_output_hides_credentials() {
    let info = parse_ntfy_url("https://user:hunter2@ntfy.example.com/").unwrap();

    assert!(!format!("{info:?}").contains("hunter2"));
}
