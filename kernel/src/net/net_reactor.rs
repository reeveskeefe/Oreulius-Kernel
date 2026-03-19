/*!
 * Oreulia Kernel Project
 *
 * License-Identifier: Oreulia Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulia.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
 *
 * ---------------------------------------------------------------------------
 */

//! Network Reactor: single-owner, event-driven network processing.
//!
//! This module moves all network stack access into a dedicated task.
//! IRQ/timer contexts only set atomic flags; the reactor drains them safely.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::capnet::CapabilityTokenV1;
use super::netstack::{Ipv4Addr, MacAddr, NetworkStack};

const MAX_STR: usize = 128;
const RX_BUDGET: usize = 64;
const MAX_TCP_IO: usize = 65_535;
/// Max bytes per `NetRequest::TcpSend` variant — raised to 16 KiB so a
/// typical 64 KiB window fits in 4 reactor dispatches instead of 16.
const MAX_TCP_SEND_CHUNK: usize = 16_384;
/// Number of per-burst RX frame slots used by `recv_frames_burst`.
/// Must be ≤ RX_BUDGET and fits in a single poll cycle.
const RX_BURST_BUFS: usize = RX_BUDGET;
const MAX_TEMPORAL_SOCKET_PREVIEW: usize = crate::temporal::TEMPORAL_SOCKET_PAYLOAD_PREVIEW_BYTES;
const TEMPORAL_NETWORK_CONFIG_BYTES: usize = 32;

#[derive(Clone, Copy)]
enum NetRequest {
    None,
    DnsResolve {
        len: u8,
        data: [u8; MAX_STR],
    },
    TcpConnect {
        remote_ip: Ipv4Addr,
        remote_port: u16,
    },
    TcpSend {
        conn_id: u16,
        len: u16,
        data: [u8; MAX_TCP_SEND_CHUNK],
    },
    TcpRecv {
        conn_id: u16,
        max_len: u16,
    },
    TcpClose {
        conn_id: u16,
    },
    TemporalApplyTcpListener {
        listener_id: u16,
        port: u16,
        event: u8,
    },
    TemporalApplyTcpConnection {
        conn_id: u16,
        state: u8,
        local_ip: Ipv4Addr,
        local_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        event: u8,
        aux: u32,
        preview_len: u16,
        preview: [u8; MAX_TEMPORAL_SOCKET_PREVIEW],
    },
    TemporalApplyNetworkConfig {
        my_ip: Ipv4Addr,
        my_mac: [u8; 6],
        gateway_ip: Ipv4Addr,
        dns_server: Ipv4Addr,
        flags: u8,
        event: u8,
    },
    HttpServerStart {
        port: u16,
    },
    HttpServerStop,
    GetInfo,
    CapNetHello {
        peer_device_id: u64,
        dest_ip: Ipv4Addr,
        dest_port: u16,
    },
    CapNetHeartbeat {
        peer_device_id: u64,
        dest_ip: Ipv4Addr,
        dest_port: u16,
        ack: u32,
        ack_only: bool,
    },
    CapNetTokenOffer {
        peer_device_id: u64,
        dest_ip: Ipv4Addr,
        dest_port: u16,
        token: CapabilityTokenV1,
    },
    CapNetTokenAccept {
        peer_device_id: u64,
        dest_ip: Ipv4Addr,
        dest_port: u16,
        token_id: u64,
        ack: u32,
    },
    CapNetTokenRevoke {
        peer_device_id: u64,
        dest_ip: Ipv4Addr,
        dest_port: u16,
        token_id: u64,
    },
    CapNetAttest {
        peer_device_id: u64,
        dest_ip: Ipv4Addr,
        dest_port: u16,
        ack: u32,
    },
}

#[derive(Clone, Copy)]
pub struct NetInfo {
    pub ready: bool,
    pub ip: Ipv4Addr,
    pub tcp_conns: usize,
    pub tcp_listeners: usize,
    pub http_running: bool,
    pub http_port: u16,
}

#[derive(Clone, Copy)]
enum NetResponse {
    None,
    Ok,
    U64(u64),
    TcpData { len: u16, data: [u8; MAX_TCP_IO] },
    Err(&'static str),
    DnsResult(Ipv4Addr),
    Info(NetInfo),
}

struct ReqSlot {
    req: UnsafeCell<NetRequest>,
    resp: UnsafeCell<NetResponse>,
}

unsafe impl Sync for ReqSlot {}

static REQ_SLOT: ReqSlot = ReqSlot {
    req: UnsafeCell::new(NetRequest::None),
    resp: UnsafeCell::new(NetResponse::None),
};

// 0 = idle, 1 = pending, 2 = response ready
static REQ_STATE: AtomicUsize = AtomicUsize::new(0);

static NET_IRQ_PENDING: AtomicUsize = AtomicUsize::new(0);

// Single-owner network stack storage (static to avoid small task stack overflow).
static mut NET_STACK: NetworkStack = NetworkStack::new();

/// IRQ hook: ack device and mark pending RX work.
pub fn on_irq() {
    #[cfg(not(target_arch = "aarch64"))]
    super::e1000::handle_irq();
    NET_IRQ_PENDING.fetch_add(1, Ordering::Relaxed);
}

/// Static storage for burst RX frame data (avoids stack allocations in the
/// reactor task which has limited stack space).
static mut BURST_BUFS: [[u8; 2048]; RX_BURST_BUFS] = [[0u8; 2048]; RX_BURST_BUFS];
static mut BURST_LENS: [usize; RX_BURST_BUFS] = [0usize; RX_BURST_BUFS];

/// Drain up to `RX_BUDGET` frames from the NIC in a single lock window,
/// then dispatch each frame through the network stack.
/// Returns the number of frames processed (used for yield/ITR decisions).
fn process_irq(stack: &mut NetworkStack) -> usize {
    let pending = NET_IRQ_PENDING.swap(0, Ordering::AcqRel);
    if pending == 0 {
        return 0;
    }

    // Drain up to RX_BUDGET frames with one spinlock acquire + one RDT write.
    let received = {
        #[cfg(not(target_arch = "aarch64"))]
        {
            let mut driver = super::e1000::E1000_DRIVER.lock();
            match driver.as_mut() {
                None => 0,
                Some(nic) => unsafe {
                    nic.recv_frames_burst(&mut BURST_BUFS, &mut BURST_LENS, RX_BURST_BUFS)
                },
            }
        }
        #[cfg(target_arch = "aarch64")]
        { 0usize }
    };

    // Update adaptive ITR based on observed burst depth.
    #[cfg(not(target_arch = "aarch64"))]
    {
        let mut driver = super::e1000::E1000_DRIVER.lock();
        if let Some(nic) = driver.as_mut() {
            nic.set_itr_adaptive(received);
        }
    }

    // Process each frame through the network stack (no NIC lock held).
    for i in 0..received {
        let len = unsafe { BURST_LENS[i] };
        if len < 14 { continue; }
        let _ = stack.dispatch_frame(unsafe { &BURST_BUFS[i][..len] });
    }

    // If we hit the budget ceiling there may be more frames; re-arm the pending
    // counter so the next loop iteration drains them too.
    if received >= RX_BURST_BUFS {
        NET_IRQ_PENDING.fetch_add(1, Ordering::Relaxed);
    }

    received
}

fn handle_request(stack: &mut NetworkStack) -> bool {
    if REQ_STATE.load(Ordering::Acquire) != 1 {
        return false;
    }
    let req = unsafe { *REQ_SLOT.req.get() };
    let resp = match req {
        NetRequest::None => NetResponse::Ok,
        NetRequest::DnsResolve { len, data } => {
            let len = len as usize;
            let domain = core::str::from_utf8(&data[..len]).unwrap_or("");
            match stack.dns_resolve(domain) {
                Ok(ip) => NetResponse::DnsResult(ip),
                Err(e) => NetResponse::Err(e),
            }
        }
        NetRequest::TcpConnect {
            remote_ip,
            remote_port,
        } => match stack.tcp_connect(remote_ip, remote_port) {
            Ok(conn_id) => NetResponse::U64(conn_id as u64),
            Err(e) => NetResponse::Err(e),
        },
        NetRequest::TcpSend { conn_id, len, data } => {
            let len = core::cmp::min(len as usize, data.len());
            match stack.tcp_send(conn_id, &data[..len]) {
                Ok(sent) => NetResponse::U64(sent as u64),
                Err(e) => NetResponse::Err(e),
            }
        }
        NetRequest::TcpRecv { conn_id, max_len } => {
            let mut out = [0u8; MAX_TCP_IO];
            let limit = core::cmp::min(max_len as usize, out.len());
            match stack.tcp_recv(conn_id, &mut out[..limit]) {
                Ok(read_len) => NetResponse::TcpData {
                    len: read_len as u16,
                    data: out,
                },
                Err(e) => NetResponse::Err(e),
            }
        }
        NetRequest::TcpClose { conn_id } => match stack.tcp_close(conn_id) {
            Ok(()) => NetResponse::Ok,
            Err(e) => NetResponse::Err(e),
        },
        NetRequest::TemporalApplyTcpListener {
            listener_id,
            port,
            event,
        } => match stack.temporal_apply_tcp_listener_event(listener_id, port, event) {
            Ok(()) => NetResponse::Ok,
            Err(e) => NetResponse::Err(e),
        },
        NetRequest::TemporalApplyTcpConnection {
            conn_id,
            state,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            event,
            aux,
            preview_len,
            preview,
        } => {
            let preview_len = core::cmp::min(preview_len as usize, preview.len());
            match stack.temporal_apply_tcp_connection_event(
                conn_id,
                state,
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                event,
                aux,
                &preview[..preview_len],
            ) {
                Ok(()) => NetResponse::Ok,
                Err(e) => NetResponse::Err(e),
            }
        }
        NetRequest::TemporalApplyNetworkConfig {
            my_ip,
            my_mac,
            gateway_ip,
            dns_server,
            flags,
            event,
        } => match stack.temporal_apply_network_config_event(
            my_ip,
            MacAddr(my_mac),
            gateway_ip,
            dns_server,
            flags,
            event,
        ) {
            Ok(()) => NetResponse::Ok,
            Err(e) => NetResponse::Err(e),
        },
        NetRequest::HttpServerStart { port } => match stack.http_server_start(port) {
            Ok(()) => NetResponse::Ok,
            Err(e) => NetResponse::Err(e),
        },
        NetRequest::HttpServerStop => {
            stack.http_server_stop();
            NetResponse::Ok
        }
        NetRequest::GetInfo => {
            let (tcp_conns, tcp_listeners) = stack.tcp_stats();
            let (http_running, http_port) = stack.http_server_status();
            NetResponse::Info(NetInfo {
                ready: stack.is_ready(),
                ip: stack.get_ip(),
                tcp_conns,
                tcp_listeners,
                http_running,
                http_port,
            })
        }
        NetRequest::CapNetHello {
            peer_device_id,
            dest_ip,
            dest_port,
        } => match stack.capnet_send_hello(dest_ip, dest_port, peer_device_id) {
            Ok(seq) => NetResponse::U64(seq as u64),
            Err(e) => NetResponse::Err(e),
        },
        NetRequest::CapNetHeartbeat {
            peer_device_id,
            dest_ip,
            dest_port,
            ack,
            ack_only,
        } => match stack.capnet_send_heartbeat(dest_ip, dest_port, peer_device_id, ack, ack_only) {
            Ok(seq) => NetResponse::U64(seq as u64),
            Err(e) => NetResponse::Err(e),
        },
        NetRequest::CapNetTokenOffer {
            peer_device_id,
            dest_ip,
            dest_port,
            token,
        } => match stack.capnet_send_token_offer(dest_ip, dest_port, peer_device_id, token) {
            Ok(token_id) => NetResponse::U64(token_id),
            Err(e) => NetResponse::Err(e),
        },
        NetRequest::CapNetTokenAccept {
            peer_device_id,
            dest_ip,
            dest_port,
            token_id,
            ack,
        } => {
            match stack.capnet_send_token_accept(dest_ip, dest_port, peer_device_id, token_id, ack)
            {
                Ok(seq) => NetResponse::U64(seq as u64),
                Err(e) => NetResponse::Err(e),
            }
        }
        NetRequest::CapNetTokenRevoke {
            peer_device_id,
            dest_ip,
            dest_port,
            token_id,
        } => match stack.capnet_send_token_revoke(dest_ip, dest_port, peer_device_id, token_id) {
            Ok(seq) => NetResponse::U64(seq as u64),
            Err(e) => NetResponse::Err(e),
        },
        NetRequest::CapNetAttest {
            peer_device_id,
            dest_ip,
            dest_port,
            ack,
        } => match stack.capnet_send_attest(dest_ip, dest_port, peer_device_id, ack) {
            Ok(seq) => NetResponse::U64(seq as u64),
            Err(e) => NetResponse::Err(e),
        },
    };

    unsafe {
        *REQ_SLOT.resp.get() = resp;
    }
    REQ_STATE.store(2, Ordering::Release);
    true
}

fn request(req: NetRequest) -> Result<NetResponse, &'static str> {
    if REQ_STATE
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("Network busy");
    }
    unsafe {
        *REQ_SLOT.req.get() = req;
    }

    let start = crate::pit::get_ticks();
    loop {
        if REQ_STATE.load(Ordering::Acquire) == 2 {
            break;
        }
        if crate::pit::get_ticks().saturating_sub(start) > 500 {
            REQ_STATE.store(0, Ordering::Release);
            return Err("Network reactor timeout");
        }
        crate::quantum_scheduler::yield_now();
    }

    let resp = unsafe { *REQ_SLOT.resp.get() };
    REQ_STATE.store(0, Ordering::Release);
    Ok(resp)
}

/// Run the network reactor loop (call from network task).
pub fn run() -> ! {
    // SAFETY: The network reactor task is the sole owner of the stack.
    let stack = unsafe { &mut NET_STACK };
    let mut marked_ready = false;
    let mut last_tick = crate::pit::get_ticks();

    loop {
        if !marked_ready && stack.is_ready() {
            stack.mark_ready();
            marked_ready = true;
        }

        // Track whether this iteration did any real work.
        let mut did_work = false;

        if handle_request(stack) {
            did_work = true;
        }

        // --- Unconditional RX poll (one frame via existing path) --------------
        // Catches frames that arrived between the last IRQ and now.
        if stack.poll_once().is_ok() {
            // poll_once returns Ok(()) whether or not a frame was received;
            // rely on process_irq for work-done accounting.
        }

        // --- Burst RX drain (IRQ-signalled frames, single lock) ---------------
        let burst_frames = process_irq(stack);
        if burst_frames > 0 {
            did_work = true;
        }

        let now = crate::pit::get_ticks();
        while last_tick < now {
            stack.tick();
            last_tick += 1;
        }

        // --- Smart yield -----------------------------------------------------
        // Only yield when this iteration produced zero work AND no new IRQ or
        // request has arrived.  During bulk transfers `did_work` stays true
        // continuously so we never surrender the CPU unnecessarily.
        if !did_work
            && NET_IRQ_PENDING.load(Ordering::Relaxed) == 0
            && REQ_STATE.load(Ordering::Relaxed) == 0
        {
            crate::quantum_scheduler::yield_now();
        }
    }
}

pub fn dns_resolve(domain: &str) -> Result<Ipv4Addr, &'static str> {
    let mut data = [0u8; MAX_STR];
    let bytes = domain.as_bytes();
    if bytes.len() > MAX_STR {
        return Err("Domain too long");
    }
    let len = bytes.len();
    data[..len].copy_from_slice(&bytes[..len]);
    match request(NetRequest::DnsResolve {
        len: len as u8,
        data,
    })? {
        NetResponse::DnsResult(ip) => Ok(ip),
        NetResponse::Err(e) => Err(e),
        _ => Err("Unexpected response"),
    }
}

pub fn tcp_connect(remote_ip: Ipv4Addr, remote_port: u16) -> Result<u16, &'static str> {
    match request(NetRequest::TcpConnect {
        remote_ip,
        remote_port,
    })? {
        NetResponse::U64(v) => Ok(v as u16),
        NetResponse::Err(e) => Err(e),
        _ => Err("Unexpected response"),
    }
}

pub fn tcp_send(conn_id: u16, data: &[u8]) -> Result<usize, &'static str> {
    let mut sent_total = 0usize;
    while sent_total < data.len() {
        let remain = data.len() - sent_total;
        let chunk_len = core::cmp::min(remain, MAX_TCP_SEND_CHUNK);
        let mut chunk = [0u8; MAX_TCP_SEND_CHUNK];
        chunk[..chunk_len].copy_from_slice(&data[sent_total..sent_total + chunk_len]);
        match request(NetRequest::TcpSend {
            conn_id,
            len: chunk_len as u16,
            data: chunk,
        })? {
            NetResponse::U64(sent) => {
                let sent = sent as usize;
                if sent == 0 {
                    break;
                }
                sent_total = sent_total.saturating_add(sent);
                if sent < chunk_len {
                    break;
                }
            }
            NetResponse::Err(e) => return Err(e),
            _ => return Err("Unexpected response"),
        }
    }
    Ok(sent_total)
}

pub fn tcp_recv(conn_id: u16, out: &mut [u8]) -> Result<usize, &'static str> {
    if out.is_empty() {
        return Ok(0);
    }
    let request_len = core::cmp::min(out.len(), MAX_TCP_IO);
    match request(NetRequest::TcpRecv {
        conn_id,
        max_len: request_len as u16,
    })? {
        NetResponse::TcpData { len, data } => {
            let len = core::cmp::min(len as usize, request_len);
            out[..len].copy_from_slice(&data[..len]);
            Ok(len)
        }
        NetResponse::Err(e) => Err(e),
        _ => Err("Unexpected response"),
    }
}

pub fn tcp_close(conn_id: u16) -> Result<(), &'static str> {
    match request(NetRequest::TcpClose { conn_id })? {
        NetResponse::Ok => Ok(()),
        NetResponse::Err(e) => Err(e),
        _ => Err("Unexpected response"),
    }
}

pub fn temporal_apply_tcp_listener_event(
    listener_id: u32,
    port: u16,
    event: u8,
) -> Result<(), &'static str> {
    if listener_id > u16::MAX as u32 {
        return Err("Temporal listener id out of range");
    }
    match request(NetRequest::TemporalApplyTcpListener {
        listener_id: listener_id as u16,
        port,
        event,
    })? {
        NetResponse::Ok => Ok(()),
        NetResponse::Err(e) => Err(e),
        _ => Err("Unexpected response"),
    }
}

pub fn temporal_apply_tcp_connection_event(
    conn_id: u32,
    state: u8,
    local_ip: [u8; 4],
    local_port: u16,
    remote_ip: [u8; 4],
    remote_port: u16,
    event: u8,
    aux: u32,
    preview: &[u8],
) -> Result<(), &'static str> {
    if conn_id > u16::MAX as u32 {
        return Err("Temporal connection id out of range");
    }
    let mut preview_buf = [0u8; MAX_TEMPORAL_SOCKET_PREVIEW];
    let preview_len = core::cmp::min(preview.len(), preview_buf.len());
    preview_buf[..preview_len].copy_from_slice(&preview[..preview_len]);

    match request(NetRequest::TemporalApplyTcpConnection {
        conn_id: conn_id as u16,
        state,
        local_ip: Ipv4Addr(local_ip),
        local_port,
        remote_ip: Ipv4Addr(remote_ip),
        remote_port,
        event,
        aux,
        preview_len: preview_len as u16,
        preview: preview_buf,
    })? {
        NetResponse::Ok => Ok(()),
        NetResponse::Err(e) => Err(e),
        _ => Err("Unexpected response"),
    }
}

pub fn temporal_apply_network_config_payload(payload: &[u8]) -> Result<(), &'static str> {
    if payload.len() < TEMPORAL_NETWORK_CONFIG_BYTES {
        return Err("Temporal network payload too short");
    }
    if payload[0] != crate::temporal::TEMPORAL_OBJECT_ENCODING_V1
        || payload[1] != crate::temporal::TEMPORAL_NETWORK_CONFIG_OBJECT
    {
        return Err("Temporal network payload type mismatch");
    }
    let mut my_mac = [0u8; 6];
    my_mac.copy_from_slice(&payload[8..14]);
    match request(NetRequest::TemporalApplyNetworkConfig {
        my_ip: Ipv4Addr([payload[4], payload[5], payload[6], payload[7]]),
        my_mac,
        gateway_ip: Ipv4Addr([payload[14], payload[15], payload[16], payload[17]]),
        dns_server: Ipv4Addr([payload[18], payload[19], payload[20], payload[21]]),
        flags: payload[3],
        event: payload[2],
    })? {
        NetResponse::Ok => Ok(()),
        NetResponse::Err(e) => Err(e),
        _ => Err("Unexpected response"),
    }
}

pub fn http_server_start(port: u16) -> Result<(), &'static str> {
    match request(NetRequest::HttpServerStart { port })? {
        NetResponse::Ok => Ok(()),
        NetResponse::Err(e) => Err(e),
        _ => Err("Unexpected response"),
    }
}

pub fn http_server_stop() -> Result<(), &'static str> {
    match request(NetRequest::HttpServerStop)? {
        NetResponse::Ok => Ok(()),
        NetResponse::Err(e) => Err(e),
        _ => Err("Unexpected response"),
    }
}

pub fn get_info() -> Result<NetInfo, &'static str> {
    match request(NetRequest::GetInfo)? {
        NetResponse::Info(info) => Ok(info),
        NetResponse::Err(e) => Err(e),
        _ => Err("Unexpected response"),
    }
}

pub fn capnet_send_hello(
    peer_device_id: u64,
    dest_ip: Ipv4Addr,
    dest_port: u16,
) -> Result<u32, &'static str> {
    match request(NetRequest::CapNetHello {
        peer_device_id,
        dest_ip,
        dest_port,
    })? {
        NetResponse::U64(v) => Ok(v as u32),
        NetResponse::Err(e) => Err(e),
        _ => Err("Unexpected response"),
    }
}

pub fn capnet_send_heartbeat(
    peer_device_id: u64,
    dest_ip: Ipv4Addr,
    dest_port: u16,
    ack: u32,
    ack_only: bool,
) -> Result<u32, &'static str> {
    match request(NetRequest::CapNetHeartbeat {
        peer_device_id,
        dest_ip,
        dest_port,
        ack,
        ack_only,
    })? {
        NetResponse::U64(v) => Ok(v as u32),
        NetResponse::Err(e) => Err(e),
        _ => Err("Unexpected response"),
    }
}

pub fn capnet_send_token_offer(
    peer_device_id: u64,
    dest_ip: Ipv4Addr,
    dest_port: u16,
    token: CapabilityTokenV1,
) -> Result<u64, &'static str> {
    match request(NetRequest::CapNetTokenOffer {
        peer_device_id,
        dest_ip,
        dest_port,
        token,
    })? {
        NetResponse::U64(v) => Ok(v),
        NetResponse::Err(e) => Err(e),
        _ => Err("Unexpected response"),
    }
}

pub fn capnet_send_token_revoke(
    peer_device_id: u64,
    dest_ip: Ipv4Addr,
    dest_port: u16,
    token_id: u64,
) -> Result<u32, &'static str> {
    match request(NetRequest::CapNetTokenRevoke {
        peer_device_id,
        dest_ip,
        dest_port,
        token_id,
    })? {
        NetResponse::U64(v) => Ok(v as u32),
        NetResponse::Err(e) => Err(e),
        _ => Err("Unexpected response"),
    }
}

/// Send a CapNet `Attest` control frame to `peer_device_id` at `dest_ip:dest_port`.
///
/// Used by `fleet::cmd_fleet_attest` to transmit an attestation bundle to a
/// registered peer over UDP.
pub fn capnet_send_attest(
    peer_device_id: u64,
    dest_ip: Ipv4Addr,
    dest_port: u16,
    ack: u32,
) -> Result<u32, &'static str> {
    match request(NetRequest::CapNetAttest {
        peer_device_id,
        dest_ip,
        dest_port,
        ack,
    })? {
        NetResponse::U64(v) => Ok(v as u32),
        NetResponse::Err(e) => Err(e),
        _ => Err("Unexpected response"),
    }
}

pub fn capnet_send_token_accept(
    peer_device_id: u64,
    dest_ip: Ipv4Addr,
    dest_port: u16,
    token_id: u64,
    ack: u32,
) -> Result<u32, &'static str> {
    match request(NetRequest::CapNetTokenAccept {
        peer_device_id,
        dest_ip,
        dest_port,
        token_id,
        ack,
    })? {
        NetResponse::U64(v) => Ok(v as u32),
        NetResponse::Err(e) => Err(e),
        _ => Err("Unexpected response"),
    }
}
