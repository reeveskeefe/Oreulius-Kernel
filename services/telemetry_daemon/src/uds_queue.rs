use std::io::Read;
use std::os::unix::net::UnixStream;
use std::time::Duration;

// Magic sync bytes — must match `DRAIN_MAGIC` in `kernel/src/wait_free_ring.rs`.
const MAGIC_SYNC: [u8; 4] = [0xEF, 0xBE, 0xAD, 0xDE];

/// Mirrors `kernel/src/wait_free_ring.rs::TelemetryEvent` exactly.
///
/// Layout (16 bytes, little-endian):
///   [0..4]  pid      : u32
///   [4]     node     : u8   (IntentNode discriminant 0-8)
///   [5]     cap_type : u8
///   [6]     score    : u8   (0-255)
///   [7]     _pad     : u8   (reserved)
///   [8..16] tick     : u64
#[derive(Debug, Clone, Copy)]
pub struct TelemetryEvent {
    pub pid: u32,
    pub node: u8,
    pub cap_type: u8,
    pub score: u8,
    pub tick: u64,
}

const EVENT_SIZE: usize = 16; // sizeof(TelemetryEvent) on the wire

pub struct UdsTelemetryQueue {
    stream: Option<UnixStream>,
    socket_path: &'static str,
}

impl UdsTelemetryQueue {
    pub fn new() -> Self {
        println!("Binding to microkernel wait-free telemetry via QEMU serial socket...");
        Self {
            stream: None,
            socket_path: "/tmp/oreulia_ebpf_telemetry",
        }
    }

    fn try_connect(&mut self) -> bool {
        if self.stream.is_none() {
            if let Ok(stream) = UnixStream::connect(self.socket_path) {
                stream
                    .set_read_timeout(Some(Duration::from_millis(10)))
                    .ok();
                self.stream = Some(stream);
                println!("Connected to QEMU Telemetry Stream!");
                return true;
            }
            return false;
        }
        true
    }

    /// Scan the byte stream for the next magic-framed `TelemetryEvent`.
    ///
    /// The kernel always emits exactly:
    ///   4 magic bytes  +  16 payload bytes = 20 bytes per event.
    ///
    /// Returns `None` if no complete frame is available right now (timeout /
    /// not connected / stream closed).
    pub fn poll_event(&mut self) -> Option<TelemetryEvent> {
        if !self.try_connect() {
            return None;
        }

        let stream = self.stream.as_mut()?;

        // ---- Resync on magic header -----------------------------------------
        let mut matched = 0usize;
        let mut buf1 = [0u8; 1];
        while matched < 4 {
            match stream.read(&mut buf1) {
                Ok(1) => {
                    if buf1[0] == MAGIC_SYNC[matched] {
                        matched += 1;
                    } else {
                        matched = if buf1[0] == MAGIC_SYNC[0] { 1 } else { 0 };
                    }
                }
                _ => return None, // timeout or EOF
            }
        }

        // ---- Read exactly 16 payload bytes ------------------------------------
        let mut raw = [0u8; EVENT_SIZE];
        let mut read = 0;
        while read < EVENT_SIZE {
            match stream.read(&mut raw[read..]) {
                Ok(0) => {
                    self.stream = None; // EOF — socket closed by QEMU
                    return None;
                }
                Ok(n) => read += n,
                Err(_) => return None, // timeout mid-frame — drop partial
            }
        }

        // ---- Deserialise ------------------------------------------------------
        let pid = u32::from_le_bytes(raw[0..4].try_into().unwrap());
        let node = raw[4];
        let cap_type = raw[5];
        let score = raw[6];
        // raw[7] is _pad — ignored
        let tick = u64::from_le_bytes(raw[8..16].try_into().unwrap());

        Some(TelemetryEvent {
            pid,
            node,
            cap_type,
            score,
            tick,
        })
    }
}
