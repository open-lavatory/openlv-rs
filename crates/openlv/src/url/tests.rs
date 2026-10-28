use super::*;

#[test]
fn test_decode_connection_url() {
    let uri = "openlv://k7n8m9x2w5q1p3r6@1?h=a1b2c3d4e5f60708&k=0123456789abcdef0123456789abcdef&p=mqtt&s=wss%3A%2F%2Ftest.mosquitto.org%3A8081%2Fmqtt";
    let session_uri = SessionUri::try_from(uri).unwrap();
    let SessionUri::Version1(version1) = session_uri;

    assert_eq!(version1.session_id, "k7n8m9x2w5q1p3r6");
    assert_eq!(version1.key_hash.0, "a1b2c3d4e5f60708");
    assert_eq!(
        version1.shared_key.to_hex(),
        "0123456789abcdef0123456789abcdef"
    );
    assert_eq!(version1.signaling_protocol, SignalingProtocol::Mqtt);
    assert_eq!(
        version1.signaling_server,
        "wss://test.mosquitto.org:8081/mqtt"
    );
}

#[test]
fn test_encode_round_trip() {
    let parameters = Version1SessionUri {
        session_id: "k7n8m9x2w5q1p3r6".to_string(),
        key_hash: PublicKeyHash("a1b2c3d4e5f60708".to_string()),
        shared_key: HandshakeKey::from_hex("0123456789abcdef0123456789abcdef").unwrap(),
        signaling_protocol: SignalingProtocol::Mqtt,
        signaling_server: "wss://test.mosquitto.org:8081/mqtt".to_string(),
    };

    let encoded = parameters.to_url();
    let decoded = Version1SessionUri::from_url(&encoded).unwrap();

    assert_eq!(decoded.session_id, parameters.session_id);
    assert_eq!(decoded.key_hash.0, parameters.key_hash.0);
    assert_eq!(decoded.shared_key.to_hex(), parameters.shared_key.to_hex());
    assert_eq!(decoded.signaling_protocol, parameters.signaling_protocol);
    assert_eq!(decoded.signaling_server, parameters.signaling_server);
}

#[test]
fn test_generate_session_id_length() {
    let session_id = generate_session_id();
    assert_eq!(session_id.len(), 16);
    assert!(
        session_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    );
}

#[test]
fn test_invalid_uri_rejected() {
    assert!(Version1SessionUri::from_url("not-a-uri").is_err());
    assert!(
        Version1SessionUri::from_url(
            "openlv://short@1?h=abc&k=0123456789abcdef0123456789abcdef&p=mqtt&s=x"
        )
        .is_err()
    );
}
