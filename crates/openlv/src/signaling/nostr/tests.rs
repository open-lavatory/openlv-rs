use std::sync::{Arc, Mutex};

use k256::schnorr::{Signature, VerifyingKey};
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;

use super::*;

const TOPIC: &str = "k7n8m9x2w5q1p3r6";

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
        .collect()
}

async fn relay(replies: &'static [&'static str]) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        socket.next().await;
        for reply in replies {
            socket.send(Message::text(*reply)).await.unwrap();
        }
        if !replies.is_empty() {
            while socket.next().await.is_some() {}
        }
    });
    format!("ws://{address}/")
}

#[test]
fn event_matches_typescript_id_and_verifies() {
    let channel = NostrChannel {
        signing_key: SigningKey::from_bytes(&[1; 32]).unwrap(),
        ..NostrChannel::new(TOPIC.into(), "wss://relay.example/".into()).unwrap()
    };
    let content = "h:{\"q\":\"a/b\\\\c\nd\u{1}é😀\"}";

    let event = channel.event(content, 1_700_000_000).unwrap();

    let pubkey = "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f";
    let id = "1ebd1ff8f2f00cf9ebacb68b44ddd6427dc655c42ccb1e658c48ca7eaa1cbeea";
    assert_eq!(event["pubkey"], pubkey);
    assert_eq!(event["id"], id);
    assert_eq!(event["tags"], json!([["x", TOPIC]]));
    let signature = Signature::try_from(bytes(event["sig"].as_str().unwrap()).as_slice()).unwrap();
    VerifyingKey::from_bytes(&bytes(pubkey))
        .unwrap()
        .verify_raw(&bytes(id), &signature)
        .unwrap();
}

#[tokio::test]
async fn subscription_delivers_topic_events() {
    let url = relay(&[
        r#"["EVENT","other",{"content":"foreign"}]"#,
        r#"["EVENT","k7n8m9x2w5q1p3r6",{"content":"frame"}]"#,
        r#"["EOSE","k7n8m9x2w5q1p3r6"]"#,
    ])
    .await;
    let mut channel = NostrChannel::new(TOPIC.into(), url).unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&received);

    channel.setup().await.unwrap();
    channel
        .subscribe(Box::new(move |payload| sink.lock().unwrap().push(payload)))
        .await
        .unwrap();

    assert_eq!(*received.lock().unwrap(), ["frame"]);
}

#[tokio::test]
async fn subscription_fails_when_relay_closes_it() {
    let url = relay(&[r#"["CLOSED","k7n8m9x2w5q1p3r6","auth-required: sign in"]"#]).await;
    let mut channel = NostrChannel::new(TOPIC.into(), url).unwrap();

    channel.setup().await.unwrap();
    let error = channel.subscribe(Box::new(|_| {})).await.unwrap_err();

    assert!(error.to_string().contains("auth-required: sign in"));
}

#[tokio::test]
async fn subscription_fails_when_relay_disconnects() {
    let url = relay(&[]).await;
    let mut channel = NostrChannel::new(TOPIC.into(), url).unwrap();

    channel.setup().await.unwrap();

    assert!(channel.subscribe(Box::new(|_| {})).await.is_err());
}

#[test]
fn channel_without_relay_is_rejected() {
    assert!(NostrChannel::new(TOPIC.into(), String::new()).is_err());
}
