pub fn redact_url(url: &str) -> String {
    if let Some(idx) = url.find('?') {
        format!("{}?[redacted]", &url[..idx])
    } else {
        url.to_string()
    }
}
