//! # TLS 1.3 Record Layer
//!
//! A complete TLS 1.3 implementation for Oreulius, built on top of the
//! RTL8139 Ethernet driver and the kernel's existing crypto primitives.
//!
//! ## Handshake flow
//!
//! ```text
//!  Idle → TcpConnecting → SendClientHello → WaitServerHello
//!      → WaitEncryptedExts → WaitCertificate → WaitCertVerify
//!      → WaitFinished → SendFinished → Connected
//! ```

#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(clippy::needless_range_loop)]

use crate::crypto::{
    aes128_gcm_decrypt, aes128_gcm_encrypt, hkdf_expand_label_sha256, hkdf_extract, hmac_sha256,
    sha256, x25519_public_key, x25519_shared_secret, Sha256,
};
use core::convert::TryInto;

// ============================================================================
// TLS protocol constants
// ============================================================================

const TLS_VERSION_1_2: u16 = 0x0303;
const TLS_VERSION_1_3: u16 = 0x0304;
const TLS_RECORD_MAX: usize = 16_384;

const RT_CHANGE_CIPHER_SPEC: u8 = 20;
const RT_ALERT: u8 = 21;
const RT_HANDSHAKE: u8 = 22;
const RT_APPLICATION_DATA: u8 = 23;

const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_ENCRYPTED_EXTS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;

const EXT_SUPPORTED_VERSIONS: u16 = 0x002B;
const EXT_SUPPORTED_GROUPS: u16 = 0x000A;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_SIG_ALGS: u16 = 0x000D;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_RENEGOTIATION_INFO: u16 = 0xFF01;

const GROUP_X25519: u16 = 0x001D;
const CS_AES128_GCM_SHA256: u16 = 0x1301;

// ============================================================================
// Network configuration
// ============================================================================

pub type Mac = [u8; 6];
pub type Ip4 = [u8; 4];

static mut LOCAL_MAC: Mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
static mut LOCAL_IP: Ip4 = [10, 0, 2, 15];
static mut GATEWAY_MAC: Mac = [0xFF; 6];

pub fn set_local_mac(m: &Mac) {
    unsafe {
        LOCAL_MAC = *m;
    }
}
pub fn set_local_ip(ip: &Ip4) {
    unsafe {
        LOCAL_IP = *ip;
    }
}
pub fn set_gateway_mac(m: &Mac) {
    unsafe {
        GATEWAY_MAC = *m;
    }
}

// ============================================================================
// Minimal TCP layer
// ============================================================================

const ETH_HDR: usize = 14;
const IPV4_HDR: usize = 20;
const TCP_HDR: usize = 20;

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

fn ipv4_checksum(hdr: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < hdr.len() {
        sum += u16::from_be_bytes([hdr[i], hdr[i + 1]]) as u32;
        i += 2;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_checksum(src: &Ip4, dst: &Ip4, seg: &[u8]) -> u16 {
    let mut sum = 0u32;
    for i in (0..4).step_by(2) {
        sum += u16::from_be_bytes([src[i], src[i + 1]]) as u32;
        sum += u16::from_be_bytes([dst[i], dst[i + 1]]) as u32;
    }
    sum += 6u32 + seg.len() as u32;
    let mut i = 0;
    while i + 1 < seg.len() {
        sum += u16::from_be_bytes([seg[i], seg[i + 1]]) as u32;
        i += 2;
    }
    if seg.len() & 1 != 0 {
        sum += (seg[seg.len() - 1] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let r = !(sum as u16);
    if r == 0 {
        0xFFFF
    } else {
        r
    }
}

fn build_frame(
    out: &mut [u8],
    dst_mac: &Mac,
    src_ip: &Ip4,
    dst_ip: &Ip4,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    opts: &[u8],
    payload: &[u8],
) -> usize {
    let tcp_opts_len = opts.len();
    let tcp_hdr_len = TCP_HDR + tcp_opts_len;
    let tcp_words = (tcp_hdr_len / 4) as u8;
    let ip_total = IPV4_HDR + tcp_hdr_len + payload.len();
    let total = ETH_HDR + ip_total;

    out[0..6].copy_from_slice(dst_mac);
    unsafe {
        let local_mac = LOCAL_MAC;
        out[6..12].copy_from_slice(&local_mac);
    }
    out[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    let ip = &mut out[ETH_HDR..];
    ip[0] = 0x45;
    ip[1] = 0;
    ip[2..4].copy_from_slice(&(ip_total as u16).to_be_bytes());
    ip[4..8].fill(0);
    ip[8] = 64;
    ip[9] = 6;
    ip[10..12].fill(0);
    ip[12..16].copy_from_slice(src_ip);
    ip[16..20].copy_from_slice(dst_ip);
    let cs = ipv4_checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&cs.to_be_bytes());

    let t = &mut out[ETH_HDR + IPV4_HDR..];
    t[0..2].copy_from_slice(&src_port.to_be_bytes());
    t[2..4].copy_from_slice(&dst_port.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = tcp_words << 4;
    t[13] = flags;
    t[14..16].copy_from_slice(&65535u16.to_be_bytes());
    t[16..20].fill(0);
    t[18..20].fill(0);
    if !opts.is_empty() {
        t[TCP_HDR..TCP_HDR + tcp_opts_len].copy_from_slice(opts);
    }
    if !payload.is_empty() {
        t[tcp_hdr_len..tcp_hdr_len + payload.len()].copy_from_slice(payload);
    }
    let seg_len = tcp_hdr_len + payload.len();
    let cs = tcp_checksum(
        src_ip,
        dst_ip,
        &out[ETH_HDR + IPV4_HDR..ETH_HDR + IPV4_HDR + seg_len],
    );
    out[ETH_HDR + IPV4_HDR + 16..ETH_HDR + IPV4_HDR + 18].copy_from_slice(&cs.to_be_bytes());
    total
}

#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpState {
    Closed = 0,
    SynSent = 1,
    Established = 2,
    FinWait1 = 3,
    FinWait2 = 4,
    TimeWait = 5,
    CloseWait = 6,
}

const TCP_RX_BUF: usize = 8192;
const TCP_TX_BUF: usize = 4096;

struct TcpConn {
    state: TcpState,
    src_port: u16,
    dst_port: u16,
    dst_ip: Ip4,
    dst_mac: Mac,
    snd_nxt: u32,
    snd_una: u32,
    rcv_nxt: u32,
    rx_buf: [u8; TCP_RX_BUF],
    rx_start: usize,
    rx_end: usize,
    tx_unack: [u8; TCP_TX_BUF],
    tx_len: usize,
}

impl TcpConn {
    const fn empty() -> Self {
        TcpConn {
            state: TcpState::Closed,
            src_port: 0,
            dst_port: 0,
            dst_ip: [0; 4],
            dst_mac: [0; 6],
            snd_nxt: 0,
            snd_una: 0,
            rcv_nxt: 0,
            rx_buf: [0; TCP_RX_BUF],
            rx_start: 0,
            rx_end: 0,
            tx_unack: [0; TCP_TX_BUF],
            tx_len: 0,
        }
    }

    fn emit(&self, flags: u8, opts: &[u8], payload: &[u8]) {
        let (src_ip, gw_mac) = unsafe { (LOCAL_IP, GATEWAY_MAC) };
        let mut frame = [0u8; 1600];
        let n = build_frame(
            &mut frame,
            &gw_mac,
            &src_ip,
            &self.dst_ip,
            self.src_port,
            self.dst_port,
            self.snd_nxt,
            self.rcv_nxt,
            flags,
            opts,
            payload,
        );
        #[cfg(not(target_arch = "aarch64"))]
        super::rtl8139::send(&frame[..n]);
        #[cfg(target_arch = "aarch64")]
        let _ = (&frame[..n], n);
    }

    fn connect(&mut self, dst_ip: Ip4, dst_port: u16, dst_mac: Mac) {
        self.dst_ip = dst_ip;
        self.dst_port = dst_port;
        self.dst_mac = dst_mac;
        let ticks = crate::scheduler::pit::get_ticks();
        self.src_port = 49152 | ((ticks as u16) & 0x3FFF);
        self.snd_nxt = ticks as u32;
        self.snd_una = self.snd_nxt;
        self.rcv_nxt = 0;
        self.rx_start = 0;
        self.rx_end = 0;
        self.tx_len = 0;
        let mss = [0x02u8, 0x04, 0x05, 0xB4]; // MSS=1460
        self.emit(TCP_SYN, &mss, &[]);
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        self.state = TcpState::SynSent;
    }

    fn send_data(&mut self, data: &[u8]) -> usize {
        if self.state != TcpState::Established {
            return 0;
        }
        let chunk = data.len().min(1460).min(TCP_TX_BUF - self.tx_len);
        if chunk == 0 {
            return 0;
        }
        self.tx_unack[self.tx_len..self.tx_len + chunk].copy_from_slice(&data[..chunk]);
        self.tx_len += chunk;
        self.emit(TCP_PSH | TCP_ACK, &[], &data[..chunk]);
        self.snd_nxt = self.snd_nxt.wrapping_add(chunk as u32);
        chunk
    }

    fn send_ack(&self) {
        self.emit(TCP_ACK, &[], &[]);
    }

    fn send_fin(&mut self) {
        self.emit(TCP_FIN | TCP_ACK, &[], &[]);
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        self.state = TcpState::FinWait1;
    }

    fn feed_frame(&mut self, frame: &[u8]) -> bool {
        if frame.len() < ETH_HDR + IPV4_HDR + TCP_HDR {
            return false;
        }
        if frame[12..14] != [0x08, 0x00] {
            return false;
        }
        let local_ip = unsafe { LOCAL_IP };
        if frame[ETH_HDR + 16..ETH_HDR + 20] != local_ip {
            return false;
        }
        if frame[ETH_HDR + 9] != 6 {
            return false;
        }
        let ihl = ((frame[ETH_HDR] & 0xF) as usize) * 4;
        let ts = ETH_HDR + ihl;
        if frame.len() < ts + TCP_HDR {
            return false;
        }
        let sport = u16::from_be_bytes([frame[ts], frame[ts + 1]]);
        let dport = u16::from_be_bytes([frame[ts + 2], frame[ts + 3]]);
        if dport != self.src_port || sport != self.dst_port {
            return false;
        }

        let seq = u32::from_be_bytes(frame[ts + 4..ts + 8].try_into().unwrap_or([0; 4]));
        let ack = u32::from_be_bytes(frame[ts + 8..ts + 12].try_into().unwrap_or([0; 4]));
        let doff = ((frame[ts + 12] >> 4) as usize) * 4;
        let flags = frame[ts + 13];
        let ip_total = u16::from_be_bytes([frame[ETH_HDR + 2], frame[ETH_HDR + 3]]) as usize;
        let pay_start = ts + doff;
        let pay_end = (ETH_HDR + ip_total).min(frame.len());

        self.dst_mac.copy_from_slice(&frame[6..12]);

        if flags & TCP_RST != 0 {
            self.state = TcpState::Closed;
            return true;
        }

        match self.state {
            TcpState::SynSent => {
                if flags & (TCP_SYN | TCP_ACK) == (TCP_SYN | TCP_ACK) {
                    self.rcv_nxt = seq.wrapping_add(1);
                    self.snd_una = ack;
                    self.snd_nxt = ack;
                    self.state = TcpState::Established;
                    self.send_ack();
                }
            }
            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 => {
                if flags & TCP_ACK != 0 {
                    let adv = ack.wrapping_sub(self.snd_una);
                    if adv > 0 && adv < 0x8000_0000 {
                        let trim = (adv as usize).min(self.tx_len);
                        self.tx_unack.copy_within(trim..self.tx_len, 0);
                        self.tx_len -= trim;
                        self.snd_una = ack;
                    }
                }
                if pay_end > pay_start && seq == self.rcv_nxt {
                    let data = &frame[pay_start..pay_end];
                    let space = TCP_RX_BUF - self.rx_end;
                    let copy = data.len().min(space);
                    if copy > 0 {
                        self.rx_buf[self.rx_end..self.rx_end + copy].copy_from_slice(&data[..copy]);
                        self.rx_end += copy;
                        self.rcv_nxt = self.rcv_nxt.wrapping_add(copy as u32);
                        self.send_ack();
                    }
                }
                if flags & TCP_FIN != 0 {
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                    self.send_ack();
                    self.state = match self.state {
                        TcpState::FinWait1 => TcpState::FinWait2,
                        TcpState::FinWait2 => TcpState::TimeWait,
                        _ => {
                            self.send_fin();
                            TcpState::CloseWait
                        }
                    };
                }
            }
            _ => {}
        }
        true
    }

    fn read(&mut self, buf: &mut [u8]) -> usize {
        let avail = self.rx_end - self.rx_start;
        if avail == 0 {
            return 0;
        }
        let copy = avail.min(buf.len());
        buf[..copy].copy_from_slice(&self.rx_buf[self.rx_start..self.rx_start + copy]);
        self.rx_start += copy;
        if self.rx_start == self.rx_end {
            self.rx_start = 0;
            self.rx_end = 0;
        }
        copy
    }

    fn is_connected(&self) -> bool {
        self.state == TcpState::Established
    }
    fn is_open(&self) -> bool {
        matches!(
            self.state,
            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
        )
    }
}

fn derive_secret(secret: &[u8; 32], label: &[u8], th: &[u8; 32]) -> [u8; 32] {
    hkdf_expand_label_sha256(secret, label, th)
}

// ============================================================================
// Traffic keys
// ============================================================================

#[derive(Clone)]
struct TrafficKeys {
    write_key: [u8; 16],
    write_iv: [u8; 12],
    read_key: [u8; 16],
    read_iv: [u8; 12],
    write_seq: u64,
    read_seq: u64,
}

impl TrafficKeys {
    const fn zeroed() -> Self {
        TrafficKeys {
            write_key: [0; 16],
            write_iv: [0; 12],
            read_key: [0; 16],
            read_iv: [0; 12],
            write_seq: 0,
            read_seq: 0,
        }
    }

    fn derive(ws: &[u8; 32], rs: &[u8; 32]) -> Self {
        let wk: [u8; 16] = hkdf_expand_label_sha256(ws, b"key", b"");
        let wi: [u8; 12] = hkdf_expand_label_sha256(ws, b"iv", b"");
        let rk: [u8; 16] = hkdf_expand_label_sha256(rs, b"key", b"");
        let ri: [u8; 12] = hkdf_expand_label_sha256(rs, b"iv", b"");
        let mut tk = TrafficKeys::zeroed();
        tk.write_key.copy_from_slice(&wk[..16]);
        tk.write_iv.copy_from_slice(&wi[..12]);
        tk.read_key.copy_from_slice(&rk[..16]);
        tk.read_iv.copy_from_slice(&ri[..12]);
        tk
    }

    fn write_nonce(&self) -> [u8; 12] {
        let mut n = self.write_iv;
        let s = self.write_seq.to_be_bytes();
        for i in 0..8 {
            n[4 + i] ^= s[i];
        }
        n
    }

    fn read_nonce(&self) -> [u8; 12] {
        let mut n = self.read_iv;
        let s = self.read_seq.to_be_bytes();
        for i in 0..8 {
            n[4 + i] ^= s[i];
        }
        n
    }
}

// ============================================================================
// Handshake state machine
// ============================================================================

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum HandshakeState {
    Idle = 0,
    TcpConnecting = 1,
    SendClientHello = 2,
    WaitServerHello = 3,
    WaitEncryptedExts = 4,
    WaitCertificate = 5,
    WaitCertVerify = 6,
    WaitFinished = 7,
    SendFinished = 8,
    Connected = 9,
    Closed = 10,
    Error = 11,
}

// ============================================================================
// TlsSession
// ============================================================================

const RECV_BUF_SIZE: usize = 16_640;
const APP_BUF_SIZE: usize = 16_384;
const HS_SCRATCH: usize = 8_192;
const MAX_SESSIONS: usize = 4;

pub struct TlsSession {
    pub state: HandshakeState,
    tcp: TcpConn,
    private_key: [u8; 32],
    pub_key: [u8; 32],
    peer_pub_key: [u8; 32],
    early_secret: [u8; 32],
    handshake_secret: [u8; 32],
    c_hs_traffic: [u8; 32],
    s_hs_traffic: [u8; 32],
    master_secret: [u8; 32],
    hs_keys: TrafficKeys,
    app_keys: TrafficKeys,
    transcript: Sha256,
    recv_buf: [u8; RECV_BUF_SIZE],
    recv_len: usize,
    hs_buf: [u8; HS_SCRATCH],
    app_buf: [u8; APP_BUF_SIZE],
    app_start: usize,
    app_end: usize,
    client_random: [u8; 32],
    host: [u8; 253],
    host_len: u8,
    port: u16,
    server_ip: Ip4,
    error_msg: [u8; 64],
    error_len: u8,
    pub active: bool,
}

impl TlsSession {
    const fn empty() -> Self {
        TlsSession {
            state: HandshakeState::Idle,
            tcp: TcpConn::empty(),
            private_key: [0; 32],
            pub_key: [0; 32],
            peer_pub_key: [0; 32],
            early_secret: [0; 32],
            handshake_secret: [0; 32],
            c_hs_traffic: [0; 32],
            s_hs_traffic: [0; 32],
            master_secret: [0; 32],
            hs_keys: TrafficKeys::zeroed(),
            app_keys: TrafficKeys::zeroed(),
            transcript: Sha256::new(),
            recv_buf: [0; RECV_BUF_SIZE],
            recv_len: 0,
            hs_buf: [0; HS_SCRATCH],
            app_buf: [0; APP_BUF_SIZE],
            app_start: 0,
            app_end: 0,
            client_random: [0; 32],
            host: [0; 253],
            host_len: 0,
            port: 443,
            server_ip: [0; 4],
            error_msg: [0; 64],
            error_len: 0,
            active: false,
        }
    }

    fn set_error(&mut self, msg: &[u8]) {
        let l = msg.len().min(63);
        self.error_msg[..l].copy_from_slice(&msg[..l]);
        self.error_len = l as u8;
        self.state = HandshakeState::Error;
    }

    fn gen_keys(&mut self) {
        let t = crate::scheduler::pit::get_ticks();
        let mut seed = [0u8; 16];
        seed[..8].copy_from_slice(&t.to_le_bytes());
        seed[8..].copy_from_slice(&(t ^ 0xA5A5_A5A5_A5A5_A5A5u64).to_le_bytes());
        let k = sha256(&seed);
        let mut priv_key = k;
        priv_key[0] &= 248;
        priv_key[31] &= 127;
        priv_key[31] |= 64;
        self.private_key = priv_key;
        self.pub_key = x25519_public_key(&priv_key);
        let t2 = t ^ 0xDEAD_BEEF_CAFE_1234u64;
        let mut rs = [0u8; 16];
        rs[..8].copy_from_slice(&t2.to_le_bytes());
        rs[8..].copy_from_slice(&t2.wrapping_mul(6364136223846793005u64).to_le_bytes());
        self.client_random.copy_from_slice(&sha256(&rs));
    }

    fn derive_handshake_keys(&mut self, server_pub: &[u8; 32], th: &[u8; 32]) {
        let shared = x25519_shared_secret(&self.private_key, server_pub);
        let zeros = [0u8; 32];
        self.early_secret = hkdf_extract(&zeros, &zeros);
        let derived = derive_secret(&self.early_secret, b"derived", &sha256(b""));
        self.handshake_secret = hkdf_extract(&derived, &shared);
        self.c_hs_traffic = derive_secret(&self.handshake_secret, b"c hs traffic", th);
        self.s_hs_traffic = derive_secret(&self.handshake_secret, b"s hs traffic", th);
        self.hs_keys = TrafficKeys::derive(&self.c_hs_traffic, &self.s_hs_traffic);
    }

    fn derive_app_keys(&mut self, th: &[u8; 32]) {
        let zeros = [0u8; 32];
        let derived = derive_secret(&self.handshake_secret, b"derived", &sha256(b""));
        self.master_secret = hkdf_extract(&derived, &zeros);
        let c_ap = derive_secret(&self.master_secret, b"c ap traffic", th);
        let s_ap = derive_secret(&self.master_secret, b"s ap traffic", th);
        self.app_keys = TrafficKeys::derive(&c_ap, &s_ap);
    }

    fn encrypt_record(keys: &mut TrafficKeys, pt: &[u8], ct_byte: u8, out: &mut [u8]) -> usize {
        let inner_len = pt.len() + 1;
        let record_ct_len = inner_len + 16;
        let aad: [u8; 5] = [
            RT_APPLICATION_DATA,
            (TLS_VERSION_1_2 >> 8) as u8,
            TLS_VERSION_1_2 as u8,
            (record_ct_len >> 8) as u8,
            record_ct_len as u8,
        ];
        let nonce = keys.write_nonce();
        let mut inner = [0u8; TLS_RECORD_MAX + 4];
        inner[..pt.len()].copy_from_slice(pt);
        inner[pt.len()] = ct_byte;
        let mut ct_buf = [0u8; TLS_RECORD_MAX + 4];
        let tag = aes128_gcm_encrypt(
            &keys.write_key,
            &nonce,
            &aad,
            &inner[..inner_len],
            &mut ct_buf[..inner_len],
        );
        out[..5].copy_from_slice(&aad);
        out[5..5 + inner_len].copy_from_slice(&ct_buf[..inner_len]);
        out[5 + inner_len..5 + inner_len + 16].copy_from_slice(&tag);
        keys.write_seq += 1;
        5 + record_ct_len
    }

    fn decrypt_record(
        keys: &mut TrafficKeys,
        record: &[u8],
        out: &mut [u8],
    ) -> Result<(u8, usize), ()> {
        if record.len() < 5 + 16 {
            return Err(());
        }
        let ct_field = u16::from_be_bytes([record[3], record[4]]) as usize;
        if ct_field < 16 {
            return Err(());
        }
        let payload_end = 5 + ct_field;
        if payload_end > record.len() {
            return Err(());
        }
        let ciphertext = &record[5..payload_end - 16];
        let tag: [u8; 16] = record[payload_end - 16..payload_end]
            .try_into()
            .map_err(|_| ())?;
        let aad = &record[..5];
        let nonce = keys.read_nonce();
        aes128_gcm_decrypt(
            &keys.read_key,
            &nonce,
            aad,
            ciphertext,
            &tag,
            &mut out[..ciphertext.len()],
        )?;
        keys.read_seq += 1;
        let plain_len = ciphertext.len();
        if plain_len == 0 {
            return Err(());
        }
        Ok((out[plain_len - 1], plain_len - 1))
    }

    fn build_client_hello(&self, out: &mut [u8]) -> usize {
        let host = &self.host[..self.host_len as usize];
        let mut p = 0usize;

        macro_rules! u8b {
            ($v:expr) => {
                out[p] = $v as u8;
                p += 1;
            };
        }
        macro_rules! u16b {
            ($v:expr) => {
                let x = $v as u16;
                out[p] = (x >> 8) as u8;
                out[p + 1] = x as u8;
                p += 2;
            };
        }
        macro_rules! bytes {
            ($b:expr) => {
                let l = $b.len();
                out[p..p + l].copy_from_slice($b);
                p += l;
            };
        }

        u8b!(RT_HANDSHAKE);
        u16b!(TLS_VERSION_1_2);
        let rec_len_pos = p;
        p += 2;

        let hs_start = p;
        u8b!(HS_CLIENT_HELLO);
        let hs_len_pos = p;
        p += 3;
        let body_start = p;

        u16b!(TLS_VERSION_1_2);
        bytes!(&self.client_random);
        u8b!(0); // session_id length = 0
        u16b!(2);
        u16b!(CS_AES128_GCM_SHA256);
        u8b!(1);
        u8b!(0); // compression methods

        let ext_len_pos = p;
        p += 2;
        let ext_start = p;

        // supported_versions: TLS 1.3 only
        u16b!(EXT_SUPPORTED_VERSIONS);
        u16b!(3);
        u8b!(2);
        u16b!(TLS_VERSION_1_3);
        // supported_groups: X25519
        u16b!(EXT_SUPPORTED_GROUPS);
        u16b!(4);
        u16b!(2);
        u16b!(GROUP_X25519);
        // key_share
        u16b!(EXT_KEY_SHARE);
        let ks_len_pos = p;
        p += 2;
        let ks_start = p;
        u16b!(36);
        u16b!(GROUP_X25519);
        u16b!(32);
        bytes!(&self.pub_key);
        let ks_len = (p - ks_start) as u16;
        out[ks_len_pos] = (ks_len >> 8) as u8;
        out[ks_len_pos + 1] = ks_len as u8;
        // sig_algs: ecdsa_secp256r1_sha256
        u16b!(EXT_SIG_ALGS);
        u16b!(4);
        u16b!(2);
        u16b!(0x0403u16);
        // SNI
        if !host.is_empty() {
            u16b!(EXT_SERVER_NAME);
            let sni_data_len = 3 + host.len();
            u16b!(sni_data_len as u16);
            u16b!((1 + 2 + host.len()) as u16);
            u8b!(0);
            u16b!(host.len() as u16);
            bytes!(host);
        }
        // renegotiation_info: empty
        u16b!(EXT_RENEGOTIATION_INFO);
        u16b!(1);
        u8b!(0);

        let ext_len = (p - ext_start) as u16;
        out[ext_len_pos] = (ext_len >> 8) as u8;
        out[ext_len_pos + 1] = ext_len as u8;

        let body_len = (p - body_start) as u32;
        out[hs_len_pos] = (body_len >> 16) as u8;
        out[hs_len_pos + 1] = (body_len >> 8) as u8;
        out[hs_len_pos + 2] = body_len as u8;

        let rec_len = (p - hs_start) as u16;
        out[rec_len_pos] = (rec_len >> 8) as u8;
        out[rec_len_pos + 1] = rec_len as u8;
        p
    }

    fn parse_server_hello(&mut self, body: &[u8]) {
        if body.len() < 36 {
            self.set_error(b"short ServerHello");
            return;
        }
        let mut p = 34; // skip legacy_version(2) + server_random(32)
        let sid_len = body.get(p).copied().unwrap_or(0) as usize;
        p += 1 + sid_len + 2 + 1;
        if p + 2 > body.len() {
            return;
        }
        let exts_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
        p += 2;
        let exts_end = (p + exts_len).min(body.len());
        while p + 4 <= exts_end {
            let ext_type = u16::from_be_bytes([body[p], body[p + 1]]);
            let ext_len = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
            p += 4;
            if ext_type == EXT_KEY_SHARE && ext_len >= 4 && p + ext_len <= exts_end {
                let kx_len = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
                if kx_len == 32 && p + 4 + 32 <= exts_end {
                    self.peer_pub_key.copy_from_slice(&body[p + 4..p + 4 + 32]);
                }
            }
            p += ext_len;
        }
        let th = self.transcript.clone().finalize();
        let ppk = self.peer_pub_key;
        self.derive_handshake_keys(&ppk, &th);
        self.state = HandshakeState::WaitEncryptedExts;
    }

    fn verify_server_finished(&self, verify_data: &[u8], th: &[u8; 32]) -> bool {
        if verify_data.len() != 32 {
            return false;
        }
        let fin_key: [u8; 32] = hkdf_expand_label_sha256(&self.s_hs_traffic, b"finished", b"");
        let expected = hmac_sha256(&fin_key, th);
        crate::crypto::ct_eq(&expected, verify_data)
    }

    fn build_client_finished(&mut self, th: &[u8; 32], out: &mut [u8]) -> usize {
        let fin_key: [u8; 32] = hkdf_expand_label_sha256(&self.c_hs_traffic, b"finished", b"");
        let verify = hmac_sha256(&fin_key, th);
        let mut msg = [0u8; 36];
        msg[0] = HS_FINISHED;
        msg[3] = 32;
        msg[4..36].copy_from_slice(&verify);
        self.transcript.update(&msg);
        let mut hs_keys = self.hs_keys.clone();
        let n = Self::encrypt_record(&mut hs_keys, &msg, RT_HANDSHAKE, out);
        self.hs_keys = hs_keys;
        n
    }

    fn process_tls_stream(&mut self) {
        let mut tmp = [0u8; 4096];
        let n = self.tcp.read(&mut tmp);
        if n > 0 {
            let copy = n.min(RECV_BUF_SIZE - self.recv_len);
            self.recv_buf[self.recv_len..self.recv_len + copy].copy_from_slice(&tmp[..copy]);
            self.recv_len += copy;
        }
        loop {
            if self.recv_len < 5 {
                break;
            }
            let rec_len = u16::from_be_bytes([self.recv_buf[3], self.recv_buf[4]]) as usize;
            let total = 5 + rec_len;
            if self.recv_len < total {
                break;
            }

            let mut rec = [0u8; RECV_BUF_SIZE];
            rec[..total].copy_from_slice(&self.recv_buf[..total]);
            self.recv_buf.copy_within(total..self.recv_len, 0);
            self.recv_len -= total;

            match rec[0] {
                RT_CHANGE_CIPHER_SPEC => {}
                RT_ALERT => {
                    let level = rec.get(5).copied().unwrap_or(2);
                    let desc = rec.get(6).copied().unwrap_or(0);
                    if level == 1 && desc == 0 {
                        self.state = HandshakeState::Closed;
                    } else {
                        self.set_error(b"server alert");
                    }
                    return;
                }
                RT_HANDSHAKE => {
                    self.handle_plaintext_hs(&rec[..total]);
                }
                RT_APPLICATION_DATA => {
                    self.handle_ciphertext_record(&rec[..total]);
                }
                _ => {}
            }

            if matches!(self.state, HandshakeState::Error | HandshakeState::Closed) {
                break;
            }
        }
    }

    fn handle_plaintext_hs(&mut self, record: &[u8]) {
        if record.len() < 9 {
            return;
        }
        let hs_type = record[5];
        let hs_len = u32::from_be_bytes([0, record[6], record[7], record[8]]) as usize;
        let end = (9 + hs_len).min(record.len());
        self.transcript.update(&record[5..end]);
        if hs_type == HS_SERVER_HELLO && self.state == HandshakeState::WaitServerHello {
            self.parse_server_hello(&record[9..end]);
        }
    }

    fn handle_ciphertext_record(&mut self, record: &[u8]) {
        match self.state {
            HandshakeState::WaitEncryptedExts
            | HandshakeState::WaitCertificate
            | HandshakeState::WaitCertVerify
            | HandshakeState::WaitFinished => self.handle_encrypted_hs(record),
            HandshakeState::Connected => {
                let mut ak = self.app_keys.clone();
                let mut plain = [0u8; TLS_RECORD_MAX + 4];
                if let Ok((inner_ct, len)) = Self::decrypt_record(&mut ak, record, &mut plain) {
                    self.app_keys = ak;
                    if inner_ct == RT_APPLICATION_DATA {
                        let space = APP_BUF_SIZE - self.app_end;
                        let copy = len.min(space);
                        if copy > 0 {
                            self.app_buf[self.app_end..self.app_end + copy]
                                .copy_from_slice(&plain[..copy]);
                            self.app_end += copy;
                        }
                    } else if inner_ct == RT_ALERT {
                        self.state = HandshakeState::Closed;
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_encrypted_hs(&mut self, record: &[u8]) {
        let mut hs_keys = self.hs_keys.clone();
        let mut plain = [0u8; HS_SCRATCH];
        let result = Self::decrypt_record(&mut hs_keys, record, &mut plain);
        let (inner_ct, plain_len) = match result {
            Ok(v) => v,
            Err(_) => return,
        };
        self.hs_keys = hs_keys;
        if inner_ct != RT_HANDSHAKE {
            return;
        }

        let mut off = 0;
        while off + 4 <= plain_len {
            let hs_type = plain[off];
            let hs_len =
                u32::from_be_bytes([0, plain[off + 1], plain[off + 2], plain[off + 3]]) as usize;
            let msg_end = off + 4 + hs_len;
            if msg_end > plain_len {
                break;
            }

            // Snapshot transcript BEFORE adding this message (needed for server Finished).
            let th_before = self.transcript.clone().finalize();

            let mut msg_copy = [0u8; HS_SCRATCH];
            let msg_len = msg_end - off;
            msg_copy[..msg_len].copy_from_slice(&plain[off..msg_end]);
            self.transcript.update(&msg_copy[..msg_len]);

            let body = &plain[off + 4..msg_end];

            match (hs_type, self.state) {
                (HS_ENCRYPTED_EXTS, HandshakeState::WaitEncryptedExts) => {
                    self.state = HandshakeState::WaitCertificate;
                }
                (HS_CERTIFICATE, HandshakeState::WaitCertificate) => {
                    self.state = HandshakeState::WaitCertVerify;
                }
                (HS_CERTIFICATE_VERIFY, HandshakeState::WaitCertVerify) => {
                    self.state = HandshakeState::WaitFinished;
                }
                (HS_FINISHED, HandshakeState::WaitFinished) => {
                    if !self.verify_server_finished(body, &th_before) {
                        self.set_error(b"bad server Finished");
                        return;
                    }
                    let th_after = self.transcript.clone().finalize();
                    self.derive_app_keys(&th_after);
                    self.state = HandshakeState::SendFinished;
                }
                _ => {}
            }
            off = msg_end;
        }
    }

    pub fn tick(&mut self) {
        #[cfg(not(target_arch = "aarch64"))]
        let mut frame = [0u8; 1600];
        #[cfg(target_arch = "aarch64")]
        let frame = [0u8; 1600];
        #[cfg(not(target_arch = "aarch64"))]
        let n = super::rtl8139::recv(&mut frame);
        #[cfg(target_arch = "aarch64")]
        let n = 0usize;
        if n > 0 {
            self.tcp.feed_frame(&frame[..n]);
        }

        match self.state {
            HandshakeState::Idle => {}

            HandshakeState::TcpConnecting => {
                if self.tcp.is_connected() {
                    self.state = HandshakeState::SendClientHello;
                }
            }

            HandshakeState::SendClientHello => {
                self.gen_keys();
                let mut ch = [0u8; 512];
                let ch_len = self.build_client_hello(&mut ch);
                self.transcript = Sha256::new();
                if ch_len > 5 {
                    self.transcript.update(&ch[5..ch_len]);
                }
                self.tcp.send_data(&ch[..ch_len]);
                self.state = HandshakeState::WaitServerHello;
            }

            HandshakeState::WaitServerHello
            | HandshakeState::WaitEncryptedExts
            | HandshakeState::WaitCertificate
            | HandshakeState::WaitCertVerify
            | HandshakeState::WaitFinished => {
                self.process_tls_stream();
            }

            HandshakeState::SendFinished => {
                let th = self.transcript.clone().finalize();
                let mut rec = [0u8; 128];
                let n = self.build_client_finished(&th, &mut rec);
                if self.tcp.send_data(&rec[..n]) > 0 {
                    self.state = HandshakeState::Connected;
                } else {
                    self.set_error(b"send Finished failed");
                }
            }

            HandshakeState::Connected => {
                self.process_tls_stream();
            }

            HandshakeState::Closed | HandshakeState::Error => {}
        }
    }

    pub fn write(&mut self, data: &[u8]) -> usize {
        if self.state != HandshakeState::Connected {
            return 0;
        }
        let mut sent = 0;
        let mut offset = 0;
        while offset < data.len() {
            let chunk = (data.len() - offset).min(TLS_RECORD_MAX - 1);
            let mut rec = [0u8; TLS_RECORD_MAX + 32];
            let mut ak = self.app_keys.clone();
            let rec_len = Self::encrypt_record(
                &mut ak,
                &data[offset..offset + chunk],
                RT_APPLICATION_DATA,
                &mut rec,
            );
            self.app_keys = ak;
            if self.tcp.send_data(&rec[..rec_len]) == 0 {
                break;
            }
            sent += chunk;
            offset += chunk;
        }
        sent
    }

    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let avail = self.app_end - self.app_start;
        if avail == 0 {
            return 0;
        }
        let copy = avail.min(buf.len());
        buf[..copy].copy_from_slice(&self.app_buf[self.app_start..self.app_start + copy]);
        self.app_start += copy;
        if self.app_start == self.app_end {
            self.app_start = 0;
            self.app_end = 0;
        }
        copy
    }

    pub fn close(&mut self) {
        if self.state == HandshakeState::Connected {
            let mut rec = [0u8; 32];
            let mut ak = self.app_keys.clone();
            let n = Self::encrypt_record(&mut ak, &[1u8, 0u8], RT_ALERT, &mut rec);
            self.app_keys = ak;
            self.tcp.send_data(&rec[..n]);
        }
        if self.tcp.is_open() {
            self.tcp.send_fin();
        }
        self.state = HandshakeState::Closed;
    }

    pub fn error_str(&self) -> &[u8] {
        &self.error_msg[..self.error_len as usize]
    }
    pub fn handshake_done(&self) -> bool {
        self.state == HandshakeState::Connected
    }
}

// ============================================================================
// Session pool
// ============================================================================

const EMPTY_SESSION: TlsSession = TlsSession::empty();
static mut SESSIONS: [TlsSession; MAX_SESSIONS] = [EMPTY_SESSION; MAX_SESSIONS];

pub fn alloc_session(host: &[u8], port: u16, server_ip: Ip4) -> i32 {
    unsafe {
        let sessions = core::ptr::addr_of_mut!(SESSIONS) as *mut TlsSession;
        for i in 0..MAX_SESSIONS {
            let s = &mut *sessions.add(i);
            if !s.active {
                *s = TlsSession::empty();
                s.active = true;
                let hl = host.len().min(253);
                s.host[..hl].copy_from_slice(&host[..hl]);
                s.host_len = hl as u8;
                s.port = port;
                s.server_ip = server_ip;
                let gw_mac = GATEWAY_MAC;
                s.tcp.connect(server_ip, port, gw_mac);
                s.state = HandshakeState::TcpConnecting;
                return i as i32;
            }
        }
    }
    -1
}

pub fn session_mut(handle: i32) -> Option<&'static mut TlsSession> {
    if handle < 0 || handle as usize >= MAX_SESSIONS {
        return None;
    }
    unsafe {
        let s = &mut SESSIONS[handle as usize];
        if s.active {
            Some(s)
        } else {
            None
        }
    }
}

pub fn free_session(handle: i32) {
    if let Some(s) = session_mut(handle) {
        s.close();
        s.active = false;
    }
}

pub fn tick_all() {
    unsafe {
        let sessions = core::ptr::addr_of_mut!(SESSIONS) as *mut TlsSession;
        for i in 0..MAX_SESSIONS {
            let s = &mut *sessions.add(i);
            if s.active && !matches!(s.state, HandshakeState::Closed | HandshakeState::Error) {
                s.tick();
            }
        }
    }
}
