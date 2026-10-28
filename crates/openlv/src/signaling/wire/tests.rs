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
