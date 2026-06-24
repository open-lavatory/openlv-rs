use crate::errors::OpenLvError;

pub const HANDSHAKE_PREFIX: &str = "h";
pub const ENCRYPTED_PREFIX: &str = "x";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WirePrefix {
    Handshake,
    Encrypted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireRecipient {
    Host,
    Client,
}

impl WireRecipient {
    pub fn as_char(self) -> char {
        match self {
            Self::Host => 'h',
            Self::Client => 'c',
        }
    }

    pub fn from_char(value: char) -> Option<Self> {
        match value {
            'h' => Some(Self::Host),
            'c' => Some(Self::Client),
            _ => None,
        }
    }

    pub fn for_role(is_host: bool) -> Self {
        if is_host { Self::Host } else { Self::Client }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireFrame {
    pub prefix: WirePrefix,
    pub recipient: WireRecipient,
    pub body: String,
}

pub fn compose_frame(
    prefix: WirePrefix,
    recipient: WireRecipient,
    body: impl Into<String>,
) -> String {
    let prefix_char = match prefix {
        WirePrefix::Handshake => HANDSHAKE_PREFIX,
        WirePrefix::Encrypted => ENCRYPTED_PREFIX,
    };

    format!("{}{}{}", prefix_char, recipient.as_char(), body.into())
}

pub fn parse_frame(payload: &str) -> Result<WireFrame, OpenLvError> {
    if payload.len() < 2 {
        return Err(OpenLvError::WireFrame("wire frame is too short".into()));
    }

    let prefix = match &payload[..1] {
        HANDSHAKE_PREFIX => WirePrefix::Handshake,
        ENCRYPTED_PREFIX => WirePrefix::Encrypted,
        _ => return Err(OpenLvError::WireFrame("invalid wire frame prefix".into())),
    };

    let recipient = WireRecipient::from_char(
        payload
            .chars()
            .nth(1)
            .ok_or_else(|| OpenLvError::WireFrame("invalid wire frame recipient".into()))?,
    )
    .ok_or_else(|| OpenLvError::WireFrame("invalid wire frame recipient".into()))?;

    Ok(WireFrame {
        prefix,
        recipient,
        body: payload[2..].to_string(),
    })
}

pub fn is_recipient(frame: &WireFrame, is_host: bool) -> bool {
    frame.recipient == WireRecipient::for_role(is_host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compose_and_parse() {
        let frame = compose_frame(WirePrefix::Handshake, WireRecipient::Client, "abc123");
        let parsed = parse_frame(&frame).unwrap();
        assert_eq!(parsed.prefix, WirePrefix::Handshake);
        assert_eq!(parsed.recipient, WireRecipient::Client);
        assert_eq!(parsed.body, "abc123");
    }

    #[test]
    fn test_recipient_filter() {
        let frame = parse_frame("hctest").unwrap();
        assert!(!is_recipient(&frame, true));
        assert!(is_recipient(&frame, false));
    }
}
