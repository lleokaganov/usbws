//! Traffic statistics for the TCP-tunnel mode. Two atomic byte counters (one
//! per direction) are bumped from the hot path, and a background ticker emits
//! a one-line stdout event every interval describing whether each direction
//! had any traffic in the last window. The wsusb Android app parses these
//! lines and blinks two little TX/RX LEDs on screen, so the user can see at a
//! glance that data is flowing.
//!
//! We emit per-window flags (0/1) rather than byte counts because the UI only
//! needs "is there life right now". Cumulative counters can be added later if
//! a future UI wants throughput numbers.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Bytes the gate has sent toward the home side (socket → peer).
pub static TX_BYTES: AtomicU64 = AtomicU64::new(0);
/// Bytes the gate has received from the home side (peer → socket).
pub static RX_BYTES: AtomicU64 = AtomicU64::new(0);

/// How often the ticker prints a STAT line. 250 ms keeps the LEDs lively and
/// the line rate manageable for Java's log-line consumer (4 lines/sec).
const TICK_MS: u64 = 250;

/// Start the background ticker. Idempotent in practice — only ever called once
/// from main/run_*; if called twice the second tick task just adds a bit of
/// duplicate noise on stdout.
pub fn spawn_ticker() {
    tokio::spawn(async move {
        let mut last_tx: u64 = 0;
        let mut last_rx: u64 = 0;
        loop {
            tokio::time::sleep(Duration::from_millis(TICK_MS)).await;
            let cur_tx = TX_BYTES.load(Ordering::Relaxed);
            let cur_rx = RX_BYTES.load(Ordering::Relaxed);
            let tx_flag = (cur_tx != last_tx) as u8;
            let rx_flag = (cur_rx != last_rx) as u8;
            // Print every tick (even all-zero) so the Java side has a clean
            // signal to switch LEDs OFF when traffic stops; otherwise it
            // would never know the difference between "idle" and "process
            // dead".
            // Rust's stdout is block-buffered when piped (which is exactly
            // what happens under Android's ProcessBuilder). Explicit flush so
            // the Java reader sees each line as it's emitted.
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "STAT tx={} rx={}", tx_flag, rx_flag);
            let _ = out.flush();
            last_tx = cur_tx;
            last_rx = cur_rx;
        }
    });
}
