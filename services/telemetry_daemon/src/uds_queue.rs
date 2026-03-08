use std::io::Read;
use std::os::unix::net::UnixStream;
use std::time::Duration;

const TENSOR_DIM: usize = 128;
const MAGIC_SYNC: [u8; 4] = [0xEF, 0xBE, 0xAD, 0xDE];

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
                // Ensure we don't block indefinitely 
                stream.set_read_timeout(Some(Duration::from_millis(10))).ok();
                self.stream = Some(stream);
                println!("Connected to QEMU Telemetry Stream!");
                return true;
            }
            return false;
        }
        true
    }

    /// Fetches the raw tensor scalar struct from the queue, returning None if empty.
    pub fn poll_tensor<const DIM: usize>(&mut self) -> Option<[i32; DIM]> {
        if !self.try_connect() {
            return None;
        }

        assert_eq!(DIM, TENSOR_DIM);

        if let Some(stream) = &mut self.stream {
            let mut sync_buf = [0u8; 1];
            let mut matched_bytes = 0;
            
            // Fast sync to magic bytes (EF BE AD DE)
            while matched_bytes < 4 {
                if let Ok(1) = stream.read(&mut sync_buf) {
                    if sync_buf[0] == MAGIC_SYNC[matched_bytes] {
                        matched_bytes += 1;
                    } else {
                        matched_bytes = 0;
                        if sync_buf[0] == MAGIC_SYNC[0] {
                            matched_bytes = 1;
                        }
                    }
                } else {
                    return None; // No data available right now
                }
            }

            // Sync matched, read exactly DIM * 4 bytes
            let mut tensor_bytes = vec![0u8; DIM * 4];
            let mut read_bytes = 0;
            while read_bytes < DIM * 4 {
                if let Ok(n) = stream.read(&mut tensor_bytes[read_bytes..]) {
                    if n == 0 {
                        self.stream = None; // Socket closed
                        return None;
                    }
                    read_bytes += n;
                } else {
                    // Timeout/error during read, partial frame. Drop.
                    return None;
                }
            }

            let mut result = [0i32; DIM];
            for i in 0..DIM {
                let start = i * 4;
                result[i] = i32::from_le_bytes(tensor_bytes[start..start + 4].try_into().unwrap());
            }

            return Some(result);
        }

        None
    }
}
