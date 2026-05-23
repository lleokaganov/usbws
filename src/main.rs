//! usbws — tunnel a serial port between two machines over the encrypted
//! ws_server relay (protocol v2).
//!
//! Stage 1: serial. One side runs `share <dev>` (the machine with the real
//! port plugged in); the other runs `attach <peer-invite>` (creates a local
//! PTY that behaves like a virtual serial port). Bytes flow both ways through
//! the relay, end-to-end encrypted between the two peers — the relay only sees
//! ciphertext.
//!
//! Identity is a persistent per-machine keypair (~/.config/usbws/identity).
//! Authorization is trust-by-key: each side is told the other's invite code
//! and connects automatically, no interactive confirmation (headless).
//!
//! Subcommands:
//!   usbws keygen
//!       Print this machine's id + invite ("K0...") and exit.
//!   usbws share  <serial-dev> --peer K0... [--baud N]
//!       Open the real serial device in raw mode and bridge it to the peer.
//!   usbws attach <peer-invite>  [--peer K0...] [--link PATH] [--baud N]
//!       Create a local PTY (printed as /dev/pts/N) and bridge it to the peer.
//!       The positional <peer-invite> IS the peer (so --peer is optional here).
//!
//! Env overrides:
//!   USBWS_WS_URL          relay URL (default ws://ws.lleo.me/api0)
//!   USBWS_SERVER_X_PUB    relay X25519 pubkey (hex32)
//!   USBWS_SERVER_ED_PUB   relay Ed25519 pubkey (hex32)
//!   USBWS_PEER            peer invite (alternative to --peer / positional)
//!   USBWS_NICK            our display name (default "usbws")
//!   USBWS_IDENTITY        identity file path (default ~/.config/usbws/identity)

mod authorized;
mod idfile;
mod proto;
mod relay;
mod tcp;

use std::env;

// Always-available proto items (used by keygen + the TCP subcommands).
use proto::{decode_qr, make_qr, Peer};

// Serial-only imports: the bidirectional byte bridge and the share/attach
// modes. Pulled in only when the `serial` feature is enabled (Android builds
// drop them — see the feature gate in Cargo.toml).
#[cfg(feature = "serial")]
use std::time::Duration;
#[cfg(feature = "serial")]
use ed25519_dalek::VerifyingKey;
#[cfg(feature = "serial")]
use futures_util::{SinkExt, StreamExt};
#[cfg(feature = "serial")]
use tokio_tungstenite::tungstenite::Message;
#[cfg(feature = "serial")]
use x25519_dalek::x25519;
#[cfg(feature = "serial")]
use proto::{
    build_peer_frame, derive_session, pack_inner, verify_and_decrypt, xor_header, Identity,
    CMD_PEER_ONLINE, CMD_SERIAL_DATA,
};
#[cfg(feature = "serial")]
pub use relay::Relay;

#[cfg(feature = "serial")]
const DEFAULT_BAUD: u32 = 115200;

fn env_or(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

// ============================== CLI ==============================

/// Minimal flag parser: pull `--name value` out of args, return remaining
/// positionals. Good enough for our small surface; avoids a clap dependency.
struct Cli {
    positionals: Vec<String>,
    flags: std::collections::HashMap<String, String>,
}

impl Cli {
    fn parse(args: &[String]) -> Self {
        let mut positionals = Vec::new();
        let mut flags = std::collections::HashMap::new();
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if let Some(name) = a.strip_prefix("--") {
                if let Some((k, v)) = name.split_once('=') {
                    flags.insert(k.to_string(), v.to_string());
                } else if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    flags.insert(name.to_string(), args[i + 1].clone());
                    i += 1;
                } else {
                    flags.insert(name.to_string(), String::new());
                }
            } else {
                positionals.push(a.clone());
            }
            i += 1;
        }
        Self { positionals, flags }
    }

    fn flag(&self, name: &str) -> Option<&str> {
        self.flags.get(name).map(|s| s.as_str())
    }
}

fn usage() -> ! {
    // The serial subcommands (share/attach) only exist when built with the
    // `serial` feature; show them accordingly so the help matches the binary.
    #[cfg(feature = "serial")]
    let serial_help = "\
  usbws share <serial-dev> --peer K0... [--baud N]\n\
      Bridge a real serial device (e.g. /dev/ttyUSB0) to the peer.\n\
\n\
  usbws attach <peer-invite> [--link PATH] [--baud N]\n\
      Create a local PTY (a virtual serial port) bridged to the peer.\n\
\n";
    #[cfg(not(feature = "serial"))]
    let serial_help = "\
  (serial mode share/attach not built in this binary — tcp-only build)\n\
\n";

    eprintln!(
        "usbws — serial + TCP tunnel over the encrypted ws_server relay\n\
\n\
USAGE:\n\
  usbws keygen\n\
      Print this machine's id + invite, then exit.\n\
\n\
{serial_help}\
  usbws tcp-listen <localport> --peer K0...\n\
      Listen on 127.0.0.1:<localport>; each accepted connection is tunneled\n\
      to the peer, which dials its tcp-connect target (e.g. usbip client side).\n\
\n\
  usbws tcp-connect <host:port> --peer K0...\n\
      On a peer's request, dial host:port and proxy bytes back (e.g. usbipd\n\
      side: usbws tcp-connect 127.0.0.1:3240 --peer K0...).\n\
\n\
  usbws tcp-connect <host:port> --accept\n\
      Capability mode: no fixed peer. Listen on our own identity and accept\n\
      a connection from anyone who knows OUR invite, learning the initiator's\n\
      key from the handshake. Gated by the authorized table (TOFU if empty).\n\
\n\
  usbws authorized\n\
      Print the authorized-initiators table (capability list).\n\
\n\
  usbws authorize <invite K0...>\n\
      Add an initiator (by invite) to the authorized table.\n\
\n\
ENV:\n\
  USBWS_WS_URL  USBWS_SERVER_X_PUB  USBWS_SERVER_ED_PUB\n\
  USBWS_PEER (invite)  USBWS_NICK  USBWS_IDENTITY"
    );
    std::process::exit(2);
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("");
    let nick = env_or("USBWS_NICK", "usbws");

    match cmd {
        "keygen" => {
            let (me, created) = idfile::load_or_create()?;
            if created {
                eprintln!(
                    "[usbws] created identity at {}",
                    idfile::identity_path().display()
                );
            }
            // Machine-readable on stdout, human notes on stderr.
            eprintln!("id     = {}", hex::encode(me.id));
            eprintln!("invite (give to peer):");
            println!("{}", make_qr(&me, &nick));
            Ok(())
        }
        #[cfg(feature = "serial")]
        "share" => {
            let cli = Cli::parse(&args[2..]);
            let dev = cli
                .positionals
                .first()
                .cloned()
                .unwrap_or_else(|| usage());
            let baud: u32 = cli
                .flag("baud")
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_BAUD);
            // For share, positional[0] is the device — the peer comes only
            // from --peer or USBWS_PEER (no positional fallback).
            let peer = resolve_peer(&cli, None)?;
            run_share(&dev, baud, peer, &nick).await
        }
        #[cfg(feature = "serial")]
        "attach" => {
            let cli = Cli::parse(&args[2..]);
            // For attach, positional[0] IS the peer invite (most ergonomic).
            let peer = resolve_peer(&cli, Some(0))?;
            let link = cli.flag("link").map(|s| s.to_string());
            run_attach(peer, link, &nick).await
        }
        // Without the `serial` feature (e.g. the Android tcp-only build) these
        // subcommands are not compiled in. Give a clear message instead of the
        // generic usage so the user understands it's a build-variant limitation.
        #[cfg(not(feature = "serial"))]
        "share" | "attach" => {
            eprintln!("serial mode not built in this binary (Android build is tcp-only)");
            std::process::exit(2);
        }
        "tcp-listen" => {
            let cli = Cli::parse(&args[2..]);
            // positional[0] is the local port; peer comes from --peer/USBWS_PEER.
            let port: u16 = cli
                .positionals
                .first()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| usage());
            let peer = resolve_peer(&cli, None)?;
            tcp::run_tcp_listen(port, peer, &nick).await
        }
        "tcp-connect" => {
            let cli = Cli::parse(&args[2..]);
            // positional[0] is the target host:port; peer from --peer/USBWS_PEER.
            let target = cli
                .positionals
                .first()
                .cloned()
                .unwrap_or_else(|| usage());
            // Capability "accept-incoming" mode: no fixed peer; accept whoever
            // connects knowing our invite (gated by the authorized table).
            if cli.flags.contains_key("accept") {
                tcp::run_tcp_connect_accept(&target, &nick).await
            } else {
                let peer = resolve_peer(&cli, None)?;
                tcp::run_tcp_connect(&target, peer, &nick).await
            }
        }
        // Print the authorized-initiators table (capability list).
        "authorized" => {
            authorized::print_table()?;
            Ok(())
        }
        // Add an initiator to the authorized table from its invite ("K0...").
        "authorize" => {
            let cli = Cli::parse(&args[2..]);
            let invite = cli
                .flag("peer")
                .map(|s| s.to_string())
                .or_else(|| cli.positionals.first().cloned())
                .unwrap_or_else(|| usage());
            let p = decode_qr(&invite)?;
            authorized::add(&p.x_pub, &p.nick)?;
            eprintln!(
                "[usbws] authorized {} ({}) — written to {}",
                hex::encode(p.id),
                p.nick,
                authorized::authorized_path().display(),
            );
            Ok(())
        }
        _ => usage(),
    }
}

/// Resolve the peer invite from --peer, an optional positional slot, or the
/// USBWS_PEER env var (in that priority order).
fn resolve_peer(cli: &Cli, positional_index: Option<usize>) -> anyhow::Result<Peer> {
    let invite = cli
        .flag("peer")
        .map(|s| s.to_string())
        .or_else(|| positional_index.and_then(|i| cli.positionals.get(i).cloned()))
        .or_else(|| env::var("USBWS_PEER").ok())
        .ok_or_else(|| {
            anyhow::anyhow!("peer invite required (--peer K0..., positional, or USBWS_PEER)")
        })?;
    decode_qr(&invite)
}

// ============================== share mode ==============================

/// Bridge a real serial device to the peer over the relay.
#[cfg(feature = "serial")]
async fn run_share(dev: &str, baud: u32, peer: Peer, nick: &str) -> anyhow::Result<()> {
    let (me, created) = idfile::load_or_create()?;
    if created {
        eprintln!(
            "[usbws] created identity at {}",
            idfile::identity_path().display()
        );
    }
    eprintln!(
        "[usbws] share {} @ {} baud  me={} → peer={} ({})",
        dev,
        baud,
        hex::encode(me.id),
        hex::encode(peer.id),
        peer.nick
    );
    eprintln!("[usbws] my invite: {}", make_qr(&me, nick));

    // Open the serial port in raw mode. serialport sets 8N1; we explicitly
    // disable flow control and use a short read timeout so the blocking read
    // (on a dedicated thread) wakes periodically to notice shutdown.
    let port = serialport::new(dev, baud)
        .timeout(Duration::from_millis(50))
        .data_bits(serialport::DataBits::Eight)
        .parity(serialport::Parity::None)
        .stop_bits(serialport::StopBits::One)
        .flow_control(serialport::FlowControl::None)
        .open()
        .map_err(|e| anyhow::anyhow!("open serial {dev}: {e}"))?;

    // Two independent handles to the same port: one for reading, one for
    // writing, so the directions don't block each other.
    let writer = port
        .try_clone()
        .map_err(|e| anyhow::anyhow!("clone serial handle: {e}"))?;
    bridge(me, peer, nick, port, writer).await
}

// ============================== attach mode ==============================

/// Create a local PTY and bridge its master to the peer. The slave path is
/// printed (and optionally symlinked) so a terminal/flasher can connect to it.
#[cfg(feature = "serial")]
async fn run_attach(peer: Peer, link: Option<String>, nick: &str) -> anyhow::Result<()> {
    let (me, created) = idfile::load_or_create()?;
    if created {
        eprintln!(
            "[usbws] created identity at {}",
            idfile::identity_path().display()
        );
    }

    let (master, slave_keepalive, slave_path) = open_pty()?;

    eprintln!(
        "[usbws] attach  me={} → peer={} ({})",
        hex::encode(me.id),
        hex::encode(peer.id),
        peer.nick
    );
    eprintln!("[usbws] my invite: {}", make_qr(&me, nick));
    eprintln!("[usbws] virtual serial port: {slave_path}");
    println!("{slave_path}");

    if let Some(link_path) = link {
        // Replace any stale symlink so the name is stable across restarts.
        let _ = std::fs::remove_file(&link_path);
        match std::os::unix::fs::symlink(&slave_path, &link_path) {
            Ok(()) => eprintln!("[usbws] symlink {link_path} -> {slave_path}"),
            Err(e) => eprintln!("[usbws] symlink {link_path} failed: {e}"),
        }
    }

    // Hold the slave fd open for the whole session. Without at least one open
    // slave fd, a read on the master returns EOF/EIO the moment no consumer is
    // attached — which would kill the bridge before anyone connects. Keeping
    // this fd open makes the master simply block while idle.
    let _slave_keepalive = slave_keepalive;

    // Two independent handles to the PTY master: one for reading, one writing.
    let writer = master
        .try_clone()
        .map_err(|e| anyhow::anyhow!("clone PTY master: {e}"))?;
    bridge(me, peer, nick, master, writer).await
}

/// Open a PTY pair in raw mode.
///
/// Returns (master as File, slave keepalive fd, slave path). The caller keeps
/// the slave fd alive so the master never sees a spurious EOF when no external
/// consumer is currently attached.
#[cfg(feature = "serial")]
fn open_pty() -> anyhow::Result<(std::fs::File, std::os::fd::OwnedFd, String)> {
    use nix::pty::openpty;
    use nix::unistd::ttyname;

    // No explicit winsize/termios: inherit defaults, then make the slave raw
    // so it behaves like a transparent serial line (no canonical/echo).
    let pty = openpty(None, None)?;

    // Put the slave end into raw mode (no line discipline cooking the bytes).
    set_raw(&pty.slave)?;

    // Derive the slave's path (/dev/pts/N).
    let slave_path = ttyname(&pty.slave)?.to_string_lossy().into_owned();

    // OwnedFd → File: File takes ownership and closes it on Drop.
    let master = std::fs::File::from(pty.master);
    Ok((master, pty.slave, slave_path))
}

/// Put a tty fd into raw mode: ~ICANON, ~ECHO, ~ISIG, raw input/output,
/// VMIN=1 VTIME=0 (block until at least one byte).
#[cfg(feature = "serial")]
fn set_raw<F: std::os::unix::io::AsFd>(fd: F) -> anyhow::Result<()> {
    use nix::sys::termios::{
        cfmakeraw, tcgetattr, tcsetattr, ControlFlags, SetArg, SpecialCharacterIndices,
    };
    let mut t = tcgetattr(&fd)?;
    cfmakeraw(&mut t);
    t.control_flags |= ControlFlags::CLOCAL | ControlFlags::CREAD;
    t.control_chars[SpecialCharacterIndices::VMIN as usize] = 1;
    t.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;
    tcsetattr(&fd, SetArg::TCSANOW, &t)?;
    Ok(())
}

// ============================== bridge core ==============================

/// The shared bidirectional bridge used by both modes.
///
/// `reader` and `writer` are two independent OS handles to the same underlying
/// device (a serialport handle and its `try_clone`, or a PTY master File and
/// its `try_clone`). Using two handles lets a dedicated reader thread block on
/// device reads while a separate writer thread independently delivers peer
/// bytes — so a quiet line never starves the write direction.
#[cfg(feature = "serial")]
async fn bridge<R, W>(
    me: Identity,
    peer: Peer,
    nick: &str,
    reader: R,
    writer: W,
) -> anyhow::Result<()>
where
    R: std::io::Read + Send + 'static,
    W: std::io::Write + Send + 'static,
{
    let relay = Relay::from_env();
    let shared_with_server = x25519(me.x_priv, relay.server_x_pub);
    let (k_c2s, k_s2c) = derive_session(&shared_with_server);

    // device → ws  (bytes read from the local device, to be sent to the peer)
    let (dev_tx, mut dev_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
    // ws → device  (bytes received from the peer, to be written to the device)
    let (net_tx, net_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

    // Reader thread: blocks on device reads, forwards chunks to the async side.
    let read_handle = std::thread::spawn(move || device_read_loop(reader, dev_tx));
    // Writer thread: drains peer bytes and writes them to the device.
    let write_handle = std::thread::spawn(move || device_write_loop(writer, net_rx));

    let mut seq: u16 = 1;

    'reconnect: loop {
        // (Re)connect + handshake. Survive relay restarts / network blips.
        let mut ws = match relay::connect_and_handshake(&relay, &me, &k_s2c).await {
            Some(ws) => ws,
            None => {
                eprintln!("[usbws] relay unavailable; retry in 5s");
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => continue 'reconnect,
                    _ = tokio::signal::ctrl_c() => break 'reconnect,
                }
            }
        };
        eprintln!("[usbws] relay connected; introducing self to peer…");

        // Introduce + subscribe (trust-by-key: no confirmation, but the peer
        // still needs to learn our keys + nick to route replies).
        seq = relay::introduce_and_subscribe(&mut ws, &me, &peer, nick, &relay, &k_c2s, seq).await;

        eprintln!("[usbws] bridge ready");

        loop {
            tokio::select! {
                // Incoming from the relay.
                msg = ws.next() => {
                    match msg {
                        Some(Ok(Message::Binary(b))) => {
                            handle_incoming(&b, &me, &peer, &k_s2c, &relay.server_x_pub, &relay.server_ed_vk, &net_tx).await;
                        }
                        Some(Ok(Message::Ping(p))) => { let _ = ws.send(Message::Pong(p)).await; }
                        Some(Ok(Message::Close(_))) | None => {
                            eprintln!("[usbws] relay closed; reconnecting in 3s");
                            break;
                        }
                        Some(Err(e)) => { eprintln!("[usbws] ws error: {e}; reconnecting in 3s"); break; }
                        _ => {}
                    }
                }
                // Bytes read from the local device → send to peer.
                chunk = dev_rx.recv() => {
                    match chunk {
                        Some(bytes) => {
                            let frame = build_peer_frame(
                                &me, &peer.x_pub, &peer.id, &k_c2s,
                                &pack_inner(0, CMD_SERIAL_DATA, &bytes),
                            );
                            if ws.send(Message::Binary(frame)).await.is_err() {
                                eprintln!("[usbws] send failed; reconnecting in 3s");
                                break;
                            }
                        }
                        None => {
                            // Device closed (EOF / unplugged). Exit cleanly.
                            eprintln!("[usbws] device closed; exiting");
                            let _ = ws.close(None).await;
                            break 'reconnect;
                        }
                    }
                }
                _ = tokio::signal::ctrl_c() => { let _ = ws.close(None).await; break 'reconnect; }
            }
        }
        let _ = ws.close(None).await;
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    // Best effort cleanup: dropping the channels signals both I/O threads to
    // stop. The reader may still be blocked on a device read, so we don't join
    // indefinitely — the process is exiting anyway.
    drop(net_tx);
    drop(read_handle);
    drop(write_handle);
    Ok(())
}

/// Decrypt an incoming relay frame and, if it's CMD_SERIAL_DATA from the peer,
/// forward the raw bytes to the device-writer channel.
#[cfg(feature = "serial")]
async fn handle_incoming(
    frame: &[u8],
    me: &Identity,
    peer: &Peer,
    k_s2c: &[u8; 32],
    _server_x_pub: &[u8; 32],
    _server_ed_vk: &VerifyingKey,
    net_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    if frame.len() < 8 + 24 + 16 + 64 {
        return;
    }
    let nonce_24: [u8; 24] = frame[8..32].try_into().unwrap();
    let mut header: [u8; 8] = frame[..8].try_into().unwrap();
    xor_header(k_s2c, &nonce_24, &mut header);

    if header == [0u8; 8] {
        // Server-bound frame (PEER_ONLINE etc.). Informational for a stream.
        // We don't need to act on it — bytes resume on their own.
        let _ = CMD_PEER_ONLINE; // referenced to keep the constant meaningful
        return;
    }

    // Peer frame. We only know one peer; verify+decrypt with their keys.
    let Some(inner) = verify_and_decrypt(&frame[8..], &me.x_priv, &peer.x_pub, &peer.ed_pub) else {
        return;
    };
    if inner.len() < 3 {
        return;
    }
    let cmd = inner[2];
    let body = &inner[3..];

    if cmd == CMD_SERIAL_DATA && !body.is_empty() {
        // Forward to the device writer. If the channel is full the peer is
        // outpacing the local device; block briefly rather than drop bytes.
        let _ = net_tx.send(body.to_vec()).await;
    }
}

/// Reader thread: block on device reads and forward chunks to the async side.
///
/// A serialport read timeout maps to "no data yet" (retry). For a PTY master,
/// the keepalive slave fd (held by attach) prevents spurious EOF/EIO while no
/// consumer is attached; a genuine EOF/EIO ends the loop.
#[cfg(feature = "serial")]
fn device_read_loop<R: std::io::Read>(
    mut reader: R,
    dev_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => {
                // EOF: drop the sender so the async side exits the bridge.
                return;
            }
            Ok(n) => {
                // blocking_send keeps backpressure; if the async side is gone, stop.
                if dev_tx.blocking_send(buf[..n].to_vec()).is_err() {
                    return;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(ref e)
                if e.raw_os_error() == Some(libc_eio()) =>
            {
                // PTY master read can momentarily return EIO when a consumer
                // detaches; with the keepalive fd held this is transient.
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            Err(_) => return,
        }
    }
}

/// Writer thread: drain peer bytes from the channel and write them out.
#[cfg(feature = "serial")]
fn device_write_loop<W: std::io::Write>(
    mut writer: W,
    mut net_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) {
    while let Some(bytes) = net_rx.blocking_recv() {
        if writer.write_all(&bytes).is_err() {
            return;
        }
        let _ = writer.flush();
    }
}

/// EIO errno (5). nix/libc constant without pulling libc in directly.
#[cfg(feature = "serial")]
fn libc_eio() -> i32 {
    5
}
