use regex::Regex;

use crate::OpenLvError;

use super::{NtfyConnectionInfo, NtfyCredentials};

pub fn parse_ntfy_url(url: &str) -> Result<NtfyConnectionInfo, OpenLvError> {
    let regex = Regex::new(
        r"^(?P<protocol>https?|ntfys?)://(?:(?:(?P<user>[^:@]+):)?(?P<password>[^@]+)?@)?(?P<host>[^/?]+)/?(?P<parameters>.*)$",
    )
    .map_err(|error| OpenLvError::Signaling(error.to_string()))?;

    let captures = regex
        .captures(url)
        .ok_or_else(|| OpenLvError::Signaling(format!("invalid NTFY URL: {url}")))?;

    let protocol_type = captures
        .name("protocol")
        .ok_or_else(|| OpenLvError::Signaling(format!("invalid NTFY URL: {url}")))?
        .as_str();

    let (protocol, ws_protocol) = match protocol_type {
        "http" | "ntfy" => ("http", "ws"),
        "https" | "ntfys" => ("https", "wss"),
        _ => return Err(OpenLvError::Signaling(format!("invalid NTFY URL: {url}"))),
    };

    let host = captures
        .name("host")
        .ok_or_else(|| OpenLvError::Signaling(format!("invalid NTFY URL: {url}")))?
        .as_str()
        .to_string();

    let parameters = captures.name("parameters").and_then(|value| {
        let raw = value.as_str();
        if raw.is_empty() {
            None
        } else if raw.starts_with('?') {
            Some(raw.to_string())
        } else {
            Some(format!("?{raw}"))
        }
    });

    let credentials = match (captures.name("user"), captures.name("password")) {
        (Some(user), Some(password)) => Some(NtfyCredentials::UserPassword {
            user: user.as_str().to_owned(),
            password: password.as_str().to_owned(),
        }),
        (None, Some(token)) => Some(NtfyCredentials::Token(token.as_str().to_owned())),
        _ => None,
    };

    Ok(NtfyConnectionInfo {
        host,
        protocol,
        ws_protocol,
        credentials,
        parameters,
    })
}

#[cfg(test)]
mod tests;
