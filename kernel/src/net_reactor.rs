//! Network Reactor: single-owner, event-driven network processing.
//!
//! This module moves all network stack access into a dedicated task.
//! IRQ/timer contexts only set atomic flags; the reactor drains them safely.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::netstack::{Ipv4Addr, NetworkStack};

const MAX_STR: usize = 128;
const RX_BUDGET: usize = 16;

#[derive(Clone, Copy)]
enum NetRequest {
    None,
    DnsResolve { len: u8, data: [u8; MAX_STR] },
    HttpServerStart { port: u16 },
    HttpServerStop,
    GetInfo,
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
    crate::e1000::handle_irq();
    NET_IRQ_PENDING.fetch_add(1, Ordering::Relaxed);
}

fn process_irq(stack: &mut NetworkStack) {
    let mut pending = NET_IRQ_PENDING.swap(0, Ordering::AcqRel);
    let mut budget = RX_BUDGET;
    while pending > 0 && budget > 0 {
        let _ = stack.poll_once();
        pending -= 1;
        budget -= 1;
    }
    if pending > 0 {
        NET_IRQ_PENDING.fetch_add(pending, Ordering::Relaxed);
    }
}

fn handle_request(stack: &mut NetworkStack) {
    if REQ_STATE.load(Ordering::Acquire) != 1 {
        return;
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
    };

    unsafe {
        *REQ_SLOT.resp.get() = resp;
    }
    REQ_STATE.store(2, Ordering::Release);
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

        handle_request(stack);
        process_irq(stack);

        let now = crate::pit::get_ticks();
        while last_tick < now {
            stack.tick();
            last_tick += 1;
        }

        crate::quantum_scheduler::yield_now();
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
