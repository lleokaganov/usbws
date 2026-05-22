//! Relay configuration + shared session bootstrap.
//!
//! Both the serial bridge (`share`/`attach`) and the TCP tunnel
//! (`tcp-listen`/`tcp-connect`) connect to the same ws_server relay, perform
//! the same v2 handshake, then introduce + subscribe to the peer. This module
//! holds the relay config and the reusable bootstrap so the crypto/framing is
//! written exactly once.

use std::env;
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::proto::{
    build_handshake_request, build_server_bound, decode_server_frame, pack_inner, Identity, Peer,
    CMD_HANDSHAKE_OK, CMD_INTRODUCE, CMD_SUBSCRIBE,
};

// Pi ws.lleo.me relay keys (NOT telefon). Override via env.
const DEFAULT_WS_URL: &str = "ws://ws.lleo.me/api0";
const DEFAULT_SERVER_X_PUB: &str =
    "2beba374aeb45b1220bd06a794dea54bc4484aad0a81dbea9d3d5518da73005b";
const DEFAULT_SERVER_ED_PUB: &str =
    "08d98c12e044d5cacdf54933934c9a4e34f4ce7b3527adbd29a9c0a736f3bf0f";

fn env_or(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s)
        .expect("hex32 decode")
        .try_into()
        .expect("hex32 length")
}

/// The concrete websocket stream type produced by tokio-tungstenite.
pub type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Resolved relay configuration shared by all run modes.
pub struct Relay {
    pub ws_url: String,
    pub server_x_pub: [u8; 32],
    pub server_ed_vk: VerifyingKey,
}

impl Relay {
    pub fn from_env() -> Self {
        let ws_url = env_or("USBWS_WS_URL", DEFAULT_WS_URL);
        let server_x_pub = hex32(&env_or("USBWS_SERVER_X_PUB", DEFAULT_SERVER_X_PUB));
        let server_ed_pub = hex32(&env_or("USBWS_SERVER_ED_PUB", DEFAULT_SERVER_ED_PUB));
        let server_ed_vk = VerifyingKey::from_bytes(&server_ed_pub).expect("server ed pub");
        Self { ws_url, server_x_pub, server_ed_vk }
    }
}

/// Connect to the relay and complete the v2 handshake.
///
/// On success returns the live websocket. On any failure returns `None` so the
/// caller's reconnect loop can back off and retry. `k_s2c` is the server→client
/// session key derived once by the caller.
pub async fn connect_and_handshake(
    relay: &Relay,
    me: &Identity,
    k_s2c: &[u8; 32],
) -> Option<Ws> {
    let mut ws = match tokio_tungstenite::connect_async(&relay.ws_url).await {
        Ok((ws, _)) => ws,
        Err(e) => {
            eprintln!("[usbws] connect failed: {e}");
            return None;
        }
    };
    if ws
        .send(Message::Binary(build_handshake_request(me, &relay.server_x_pub)))
        .await
        .is_err()
    {
        eprintln!("[usbws] handshake send failed");
        return None;
    }
    let ok = matches!(ws.next().await,
        Some(Ok(Message::Binary(b)))
            if decode_server_frame(&b, k_s2c, &me.x_priv, &relay.server_x_pub, &relay.server_ed_vk)
                .map(|i| i.len() >= 3 && i[2] == CMD_HANDSHAKE_OK).unwrap_or(false));
    if !ok {
        eprintln!("[usbws] handshake failed");
        return None;
    }
    Some(ws)
}

/// Introduce ourselves to the peer and subscribe to its presence.
///
/// `seq` is the caller's running message counter; it is advanced past the two
/// frames sent here and returned. Trust-by-key means the peer needs no
/// confirmation, but it must still learn our keys + nick to route replies.
pub async fn introduce_and_subscribe(
    ws: &mut Ws,
    me: &Identity,
    peer: &Peer,
    nick: &str,
    relay: &Relay,
    k_c2s: &[u8; 32],
    mut seq: u16,
) -> u16 {
    let mut intro_body = Vec::with_capacity(8 + nick.len());
    intro_body.extend_from_slice(&peer.id);
    intro_body.extend_from_slice(nick.as_bytes());
    let _ = ws
        .send(Message::Binary(build_server_bound(
            me,
            &relay.server_x_pub,
            k_c2s,
            &pack_inner(seq, CMD_INTRODUCE, &intro_body),
        )))
        .await;
    seq = seq.wrapping_add(1);

    let _ = ws
        .send(Message::Binary(build_server_bound(
            me,
            &relay.server_x_pub,
            k_c2s,
            &pack_inner(seq, CMD_SUBSCRIBE, &peer.x_pub),
        )))
        .await;
    seq.wrapping_add(1)
}

/// Standard backoff between reconnect attempts.
pub async fn backoff(secs: u64) {
    tokio::time::sleep(Duration::from_secs(secs)).await;
}
