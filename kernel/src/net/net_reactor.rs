// Copyright (c) 2026 Keefe Reeves
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this file is governed by the Business Source License 1.1
// included in the LICENSE file at the root of this repository.
//
// Additional Use Grant: Personal use, research, education, evaluation,
// benchmarking, and internal non-production testing are permitted.
// Production use, commercial deployment, embedded commercial products,
// and paid hosted services require a separate commercial license.
//
// Change Date: 2030-04-15
// Change License: Apache License 2.0

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
// Keep reactor-side TCP receive staging modest so inline legacy-x86 request
// handling does not carry a 64 KiB response object through small kernel stacks.
// Current HTTP and browser transport callers read in small chunks anyway.
const MAX_TCP_IO: usize = 2048;
/// Max bytes per `NetRequest::TcpSend` variant.
///
/// Keep this bounded to avoid blowing the legacy x86 shell thread stack when
/// the inline reactor path stages a send request locally.
const MAX_TCP_SEND_CHUNK: usize = 2048;
/// Number of per-burst RX frame slots used by `recv_frames_burst`.
/// Must be ≤ RX_BUDGET and fits in a single poll cycle.
const RX_BURST_BUFS: usize = RX_BUDGET;
const MAX_TEMPORAL_SOCKET_PREVIEW: usize = crate::temporal::TEMPORAL_SOCKET_PAYLOAD_PREVIEW_BYTES;
pub const TEMPORAL_NETWORK_CONFIG_BYTES: usize = 32;

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
    ConfigureStatic {
        ip: Ipv4Addr,
        gw: Ipv4Addr,
    },
}

#[derive(Clone, Copy)]
pub struct NetInfo {
    pub ready: bool,
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
    pub dns_server: Ipv4Addr,
    pub link_up: bool,
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
static mut TCP_SEND_STAGE: [u8; MAX_TCP_SEND_CHUNK] = [0u8; MAX_TCP_SEND_CHUNK];
static mut TCP_RECV_STAGE: [u8; MAX_TCP_IO] = [0u8; MAX_TCP_IO];

// 0 = idle, 1 = claim in progress, 2 = request pending, 3 = response ready
static REQ_STATE: AtomicUsize = AtomicUsize::new(0);

static NET_IRQ_PENDING: AtomicUsize = AtomicUsize::new(0);
static REACTOR_STARTED: AtomicUsize = AtomicUsize::new(0);

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
        {
            0usize
        }
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
        if len < 14 {
            continue;
        }
        let _ = stack.dispatch_frame(unsafe { &BURST_BUFS[i][..len] });
    }

    // If we hit the budget ceiling there may be more frames; re-arm the pending
    // counter so the next loop iteration drains them too.
    if received >= RX_BURST_BUFS {
        NET_IRQ_PENDING.fetch_add(1, Ordering::Relaxed);
    }

    received
}

fn drive_runtime_progress(stack: &mut NetworkStack, last_tick: &mut u64) -> bool {
    let mut did_work = false;

    if let Ok(polled) = stack.poll_once() {
        if polled {
            did_work = true;
        }
    }

    let burst_frames = process_irq(stack);
    if burst_frames > 0 {
        did_work = true;
    }

    let now = crate::scheduler::pit::get_ticks();
    if *last_tick < now {
        while *last_tick < now {
            stack.tick();
            *last_tick += 1;
        }
        did_work = true;
    }

    did_work
}

fn wait_for_runtime_progress() {
    crate::scheduler::slice_scheduler::yield_now();
}

fn dispatch_request(
    stack: &mut NetworkStack,
    req: &NetRequest,
    last_tick: &mut u64,
) -> NetResponse {
    match req {
        NetRequest::None => NetResponse::Ok,
        NetRequest::DnsResolve { len, data } => {
            let len = *len as usize;
            let domain = core::str::from_utf8(&data[..len]).unwrap_or("");
            match stack.dns_resolve_with_progress(domain, |stack| {
                if !drive_runtime_progress(stack, last_tick) {
                    wait_for_runtime_progress();
                }
            }) {
                Ok(ip) => NetResponse::DnsResult(ip),
                Err(e) => NetResponse::Err(e),
            }
        }
        NetRequest::TcpConnect {
            remote_ip,
            remote_port,
        } => match stack.tcp_connect(*remote_ip, *remote_port) {
            Ok(conn_id) => {
                let timeout_ticks = (crate::scheduler::pit::get_frequency() as u64)
                    .saturating_mul(5)
                    .max(1);
                let start_ticks = crate::scheduler::pit::get_ticks();
                loop {
                    match stack.tcp_connection_state(conn_id) {
                        Some(4) | Some(7) => {
                            break NetResponse::U64(conn_id as u64);
                        }
                        Some(_) => {}
                        None => break NetResponse::Err("TCP connect failed"),
                    }

                    if crate::scheduler::pit::get_ticks().saturating_sub(start_ticks) > timeout_ticks {
                        break NetResponse::Err("TCP connect timeout");
                    }

                    if !drive_runtime_progress(stack, last_tick) {
                        wait_for_runtime_progress();
                    }
                }
            }
            Err(e) => NetResponse::Err(e),
        },
        NetRequest::TcpSend { conn_id, len } => {
            let len = core::cmp::min(*len as usize, MAX_TCP_SEND_CHUNK);
            let data = unsafe { &TCP_SEND_STAGE[..len] };
            match stack.tcp_send(*conn_id, data) {
                Ok(sent) => NetResponse::U64(sent as u64),
                Err(e) => NetResponse::Err(e),
            }
        }
        NetRequest::TcpRecv { conn_id, max_len } => {
            let limit = core::cmp::min(*max_len as usize, MAX_TCP_IO);
            let timeout_ticks = (crate::scheduler::pit::get_frequency() as u64)
                .saturating_mul(2)
                .max(1);
            let start_ticks = crate::scheduler::pit::get_ticks();
            loop {
                let out = unsafe { &mut TCP_RECV_STAGE[..limit] };
                match stack.tcp_recv(*conn_id, out) {
                    Ok(read_len) if read_len > 0 => {
                        break NetResponse::U64(read_len as u64);
                    }
                    Ok(_) => {
                        if stack.tcp_connection_eof(*conn_id) {
                            break NetResponse::U64(0);
                        }
                        if crate::scheduler::pit::get_ticks().saturating_sub(start_ticks) > timeout_ticks {
                            break NetResponse::U64(0);
                        }
                        if !drive_runtime_progress(stack, last_tick) {
                            wait_for_runtime_progress();
                        }
                    }
                    Err(e) => {
                        if e == "Connection not found" || stack.tcp_connection_eof(*conn_id) {
                            break NetResponse::U64(0);
                        }
                        break NetResponse::Err(e);
                    }
                }
            }
        }
        NetRequest::TcpClose { conn_id } => match stack.tcp_close(*conn_id) {
            Ok(()) => NetResponse::Ok,
            Err(e) => NetResponse::Err(e),
        },
        NetRequest::TemporalApplyTcpListener {
            listener_id,
            port,
            event,
        } => match stack.temporal_apply_tcp_listener_event(*listener_id, *port, *event) {
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
            let preview_len = core::cmp::min(*preview_len as usize, preview.len());
            match stack.temporal_apply_tcp_connection_event(
                *conn_id,
                *state,
                *local_ip,
                *local_port,
                *remote_ip,
                *remote_port,
                *event,
                *aux,
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
            *my_ip,
            MacAddr(*my_mac),
            *gateway_ip,
            *dns_server,
            *flags,
            *event,
        ) {
            Ok(()) => NetResponse::Ok,
            Err(e) => NetResponse::Err(e),
        },
        NetRequest::HttpServerStart { port } => match stack.http_server_start(*port) {
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
            #[cfg(target_arch = "x86")]
            let _ = super::e1000::ensure_runtime_link();
            let link_up = stack.link_up();
            NetResponse::Info(NetInfo {
                ready: REACTOR_STARTED.load(Ordering::Acquire) != 0 && stack.is_ready(),
                ip: stack.get_ip(),
                mac: stack.get_mac(),
                dns_server: stack.get_dns_server(),
                link_up,
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
        } => match stack.capnet_send_hello(*dest_ip, *dest_port, *peer_device_id) {
            Ok(seq) => NetResponse::U64(seq as u64),
            Err(e) => NetResponse::Err(e),
        },
        NetRequest::CapNetHeartbeat {
            peer_device_id,
            dest_ip,
            dest_port,
            ack,
            ack_only,
        } => match stack.capnet_send_heartbeat(
            *dest_ip,
            *dest_port,
            *peer_device_id,
            *ack,
            *ack_only,
        ) {
            Ok(seq) => NetResponse::U64(seq as u64),
            Err(e) => NetResponse::Err(e),
        },
        NetRequest::CapNetTokenOffer {
            peer_device_id,
            dest_ip,
            dest_port,
            token,
        } => match stack.capnet_send_token_offer(*dest_ip, *dest_port, *peer_device_id, *token) {
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
            match stack.capnet_send_token_accept(
                *dest_ip,
                *dest_port,
                *peer_device_id,
                *token_id,
                *ack,
            ) {
                Ok(seq) => NetResponse::U64(seq as u64),
                Err(e) => NetResponse::Err(e),
            }
        }
        NetRequest::CapNetTokenRevoke {
            peer_device_id,
            dest_ip,
            dest_port,
            token_id,
        } => match stack.capnet_send_token_revoke(*dest_ip, *dest_port, *peer_device_id, *token_id)
        {
            Ok(seq) => NetResponse::U64(seq as u64),
            Err(e) => NetResponse::Err(e),
        },
        NetRequest::CapNetAttest {
            peer_device_id,
            dest_ip,
            dest_port,
            ack,
        } => match stack.capnet_send_attest(*dest_ip, *dest_port, *peer_device_id, *ack) {
            Ok(seq) => NetResponse::U64(seq as u64),
            Err(e) => NetResponse::Err(e),
        },
        NetRequest::ConfigureStatic { ip, gw } => {
            stack.configure_static(*ip, *gw);
            NetResponse::Ok
        }
    }
}

fn handle_request(stack: &mut NetworkStack, last_tick: &mut u64) -> bool {
    if REQ_STATE.load(Ordering::Acquire) != 2 {
        return false;
    }
    let req = unsafe { &*REQ_SLOT.req.get() };
    let resp = dispatch_request(stack, req, last_tick);
    unsafe {
        *REQ_SLOT.resp.get() = resp;
    }
    REQ_STATE.store(3, Ordering::Release);
    true
}

fn request(req: NetRequest) -> Result<NetResponse, &'static str> {
    if REACTOR_STARTED.load(Ordering::Acquire) == 0 {
        return Err("Network reactor not started");
    }
    if REQ_STATE
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("Network busy");
    }
    unsafe {
        *REQ_SLOT.req.get() = req;
        *REQ_SLOT.resp.get() = NetResponse::None;
    }
    core::sync::atomic::fence(Ordering::Release);
    REQ_STATE.store(2, Ordering::Release);

    let timeout_ticks = (crate::scheduler::pit::get_frequency() as u64)
        .saturating_mul(5)
        .max(500);
    let start = crate::scheduler::pit::get_ticks();
    loop {
        if REQ_STATE.load(Ordering::Acquire) == 3 {
            break;
        }
        if crate::scheduler::pit::get_ticks().saturating_sub(start) > timeout_ticks {
            REQ_STATE.store(0, Ordering::Release);
            return Err("Network reactor request timeout");
        }
        wait_for_runtime_progress();
    }

    let resp = unsafe { *REQ_SLOT.resp.get() };
    REQ_STATE.store(0, Ordering::Release);
    Ok(resp)
}

/// Run the network reactor loop (call from network task).
pub fn run() -> ! {
    // SAFETY: The network reactor task is the sole owner of the stack.
    #[allow(unused_unsafe)]
    let stack_ptr = unsafe { core::ptr::addr_of_mut!(NET_STACK) };
    let stack = unsafe { &mut *stack_ptr };
    #[cfg(target_arch = "aarch64")]
    {
        if let Some(base) = crate::arch::aarch64::aarch64_virt::discovered_virtio_net_base() {
            match super::virtio_net::init(base) {
                Ok(mac) => {
                    if stack.seed_aarch64_qemu_defaults(mac) {
                        crate::serial_println!("[NET] aarch64 reactor seeded runtime defaults");
                    }
                }
                Err(e) => {
                    crate::serial_println!("[NET] aarch64 virtio-net init failed: {}", e);
                }
            }
        } else {
            crate::serial_println!("[NET] aarch64 virtio-net not discovered");
        }
    }
    #[cfg(target_arch = "x86")]
    {
        if super::e1000::driver_present() && stack.seed_legacy_x86_qemu_defaults() {
            crate::serial_println!("[NET] legacy-x86 reactor seeded runtime defaults");
        }
        super::e1000::enable_runtime_interrupts();
        let _ = super::e1000::ensure_runtime_link();
    }
    REACTOR_STARTED.store(1, Ordering::Release);
    let mut marked_ready = false;
    let mut last_tick = crate::scheduler::pit::get_ticks();

    loop {
        if !marked_ready && stack.readiness_prereqs_met() {
            stack.mark_ready();
            marked_ready = true;
        }

        // Track whether this iteration did any real work.
        let mut did_work = false;

        if handle_request(stack, &mut last_tick) {
            did_work = true;
        }

        if drive_runtime_progress(stack, &mut last_tick) {
            did_work = true;
        }

        // --- Smart yield -----------------------------------------------------
        // Only yield when this iteration produced zero work AND no new IRQ or
        // request has arrived.  During bulk transfers `did_work` stays true
        // continuously so we never surrender the CPU unnecessarily.
        if !did_work
            && NET_IRQ_PENDING.load(Ordering::Relaxed) == 0
            && REQ_STATE.load(Ordering::Relaxed) != 2
        {
            crate::scheduler::slice_scheduler::yield_now();
        }
    }
}

pub fn dns_resolve(domain: &str) -> Result<Ipv4Addr, &'static str> {
    let info = get_info()?;
    let dns_ready = info.ip.0 != [0, 0, 0, 0] && info.dns_server.0 != [0, 0, 0, 0];
    if !dns_ready {
        return Err("DNS not configured");
    }
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
    let info = get_info()?;
    let tcp_usable = info.ready || info.ip.0 != [0, 0, 0, 0];
    if !tcp_usable {
        return Err("Network not ready");
    }
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
        unsafe {
            TCP_SEND_STAGE[..chunk_len].copy_from_slice(&data[sent_total..sent_total + chunk_len]);
        }
        match request(NetRequest::TcpSend {
            conn_id,
            len: chunk_len as u16,
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
            NetResponse::Err(e) => {
                return Err(e);
            }
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
        NetResponse::U64(v) => {
            let len = core::cmp::min(v as usize, request_len);
            if len > 0 {
                let data = unsafe { &TCP_RECV_STAGE[..len] };
                out[..len].copy_from_slice(data);
            }
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

#[cfg(target_arch = "x86")]
pub fn seed_legacy_x86_qemu_defaults() {
    let stack = unsafe { &mut NET_STACK };
    let _ = stack.seed_legacy_x86_qemu_defaults();
}

pub fn configure_static(ip: Ipv4Addr, gw: Ipv4Addr) -> Result<(), &'static str> {
    match request(NetRequest::ConfigureStatic { ip, gw })? {
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
