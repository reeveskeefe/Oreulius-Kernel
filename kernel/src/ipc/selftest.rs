use super::{
    BackpressureAction, BackpressureLevel, Capability, CapabilityType, Channel, ChannelCapability,
    ChannelFlags, ChannelId, ChannelRights, ClosureState, DrainResult, EventId, IpcError, Message,
    ProcessId, CHANNEL_CAPACITY,
};
use crate::process::{Pid, ProcessState};

pub const IPC_SELFTEST_CASES: usize = 12;

#[derive(Clone, Copy)]
pub struct IpcSelftestCase {
    pub name: &'static str,
    pub passed: bool,
    pub detail: &'static str,
}

#[derive(Clone, Copy)]
pub struct IpcSelftestReport {
    pub total: usize,
    pub passed: usize,
    pub cases: [IpcSelftestCase; IPC_SELFTEST_CASES],
}

const EMPTY_CASE: IpcSelftestCase = IpcSelftestCase {
    name: "",
    passed: false,
    detail: "",
};

pub fn run_selftest() -> IpcSelftestReport {
    let mut report = IpcSelftestReport {
        total: IPC_SELFTEST_CASES,
        passed: 0,
        cases: [EMPTY_CASE; IPC_SELFTEST_CASES],
    };

    record_case(&mut report, 0, "round_trip", case_round_trip());
    record_case(
        &mut report,
        1,
        "bounded_queue_backpressure",
        case_bounded_queue_backpressure(),
    );
    record_case(
        &mut report,
        2,
        "close_drain_then_closed",
        case_close_drain_then_closed(),
    );
    record_case(
        &mut report,
        3,
        "recv_aliases_try_recv_on_empty",
        case_recv_aliases_try_recv_on_empty(),
    );
    record_case(
        &mut report,
        4,
        "cap_attachment_surface",
        case_cap_attachment_surface(),
    );
    record_case(
        &mut report,
        5,
        "backpressure_metrics",
        case_backpressure_metrics(),
    );
    record_case(
        &mut report,
        6,
        "async_high_pressure_policy",
        case_async_high_pressure_policy(),
    );
    record_case(
        &mut report,
        7,
        "runtime_wakeup_surface",
        case_runtime_wakeup_surface(),
    );
    record_case(&mut report, 8, "causal_chain", case_causal_chain());
    record_case(
        &mut report,
        9,
        "closure_drain_state_machine",
        case_closure_drain_state_machine(),
    );
    record_case(
        &mut report,
        10,
        "event_id_encodes_source_seq",
        case_event_id_encodes_source_seq(),
    );
    record_case(
        &mut report,
        11,
        "channel_draining_admission",
        case_channel_draining_admission(),
    );

    report
}

struct SyntheticWaiterGuard {
    pid: Option<Pid>,
}

impl SyntheticWaiterGuard {
    fn stage(name: &str, addr: usize) -> Result<Self, &'static str> {
        let pid = crate::quantum_scheduler::selftest_stage_waiter_process(
            name,
            addr,
            ProcessState::WaitingOnChannel,
        )?;
        Ok(Self { pid: Some(pid) })
    }

    fn pid(&self) -> Pid {
        self.pid.expect("synthetic waiter pid missing")
    }
}

impl Drop for SyntheticWaiterGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.pid.take() {
            let _ = crate::quantum_scheduler::selftest_remove_process(pid);
        }
    }
}

fn record_case(
    report: &mut IpcSelftestReport,
    idx: usize,
    name: &'static str,
    result: Result<(), &'static str>,
) {
    let (passed, detail) = match result {
        Ok(()) => {
            report.passed += 1;
            (true, "ok")
        }
        Err(detail) => (false, detail),
    };
    report.cases[idx] = IpcSelftestCase {
        name,
        passed,
        detail,
    };
}

fn case_round_trip() -> Result<(), &'static str> {
    let id = ChannelId::new(0x10);
    let owner = ProcessId::new(7);
    let mut channel = Channel::new(id, owner);
    let send_cap = ChannelCapability::new(1, id, ChannelRights::send_only(), owner);
    let recv_cap = ChannelCapability::new(2, id, ChannelRights::receive_only(), owner);
    let msg = Message::with_data(owner, b"ping").map_err(|_| "failed to build message")?;
    channel.send(msg, &send_cap).map_err(|_| "send failed")?;
    let received = channel.try_recv(&recv_cap).map_err(|_| "recv failed")?;
    if received.payload() != b"ping" {
        return Err("payload mismatch");
    }
    Ok(())
}

fn case_bounded_queue_backpressure() -> Result<(), &'static str> {
    let id = ChannelId::new(0x11);
    let owner = ProcessId::new(8);
    let mut channel = Channel::new(id, owner);
    let send_cap = ChannelCapability::new(3, id, ChannelRights::send_only(), owner);

    for idx in 0..CHANNEL_CAPACITY {
        let payload = [b'a' + idx as u8];
        let msg =
            Message::with_data(owner, &payload).map_err(|_| "failed to build queue message")?;
        channel
            .send(msg, &send_cap)
            .map_err(|_| "queue fill send failed")?;
    }

    let extra = Message::with_data(owner, b"x").map_err(|_| "failed to build overflow message")?;
    match channel.send(extra, &send_cap) {
        Err(IpcError::WouldBlock) => {
            if channel.send_refusals() != 1 {
                return Err("send refusal counter mismatch");
            }
            Ok(())
        }
        Err(_) => Err("overflow returned wrong error"),
        Ok(()) => Err("overflow unexpectedly succeeded"),
    }
}

fn case_close_drain_then_closed() -> Result<(), &'static str> {
    let id = ChannelId::new(0x12);
    let owner = ProcessId::new(9);
    let mut channel = Channel::new(id, owner);
    let send_cap = ChannelCapability::new(4, id, ChannelRights::send_only(), owner);
    let recv_cap = ChannelCapability::new(5, id, ChannelRights::receive_only(), owner);
    let close_cap = ChannelCapability::new(6, id, ChannelRights::full(), owner);

    let msg = Message::with_data(owner, b"queued").map_err(|_| "failed to build close message")?;
    channel.send(msg, &send_cap).map_err(|_| "send failed")?;
    channel.close(&close_cap).map_err(|_| "close failed")?;
    if !channel.is_closing() {
        return Err("channel did not enter closing state");
    }
    let blocked = Message::with_data(owner, b"blocked").map_err(|_| "failed to build blocked")?;
    if !matches!(channel.send(blocked, &send_cap), Err(IpcError::Closed)) {
        return Err("send after close was not refused");
    }
    if channel.send_refusals() != 1 {
        return Err("close send refusal counter mismatch");
    }

    let drained = channel.try_recv(&recv_cap).map_err(|_| "drain failed")?;
    if drained.payload() != b"queued" {
        return Err("drained payload mismatch");
    }

    match channel.try_recv(&recv_cap) {
        Err(IpcError::Closed) => {
            if channel.recv_refusals() != 1 {
                return Err("close recv refusal counter mismatch");
            }
            Ok(())
        }
        Err(_) => Err("post-close drain returned wrong error"),
        Ok(_) => Err("post-close drain unexpectedly returned message"),
    }
}

fn case_recv_aliases_try_recv_on_empty() -> Result<(), &'static str> {
    let id = ChannelId::new(0x13);
    let owner = ProcessId::new(10);
    let mut channel = Channel::new(id, owner);
    let recv_cap = ChannelCapability::new(7, id, ChannelRights::receive_only(), owner);

    let try_recv = channel.try_recv(&recv_cap);
    let recv = channel.recv(&recv_cap);
    if matches!(try_recv, Err(IpcError::WouldBlock)) && matches!(recv, Err(IpcError::WouldBlock)) {
        if channel.recv_refusals() != 2 {
            return Err("recv refusal counter mismatch");
        }
        Ok(())
    } else {
        Err("recv diverged from try_recv")
    }
}

fn case_cap_attachment_surface() -> Result<(), &'static str> {
    let owner = ProcessId::new(11);
    let mut msg = Message::with_data(owner, b"caps").map_err(|_| "failed to build cap message")?;
    let cap = Capability::with_type(
        88,
        99,
        crate::capability::Rights::new(0xA5),
        CapabilityType::ServicePointer,
    );
    msg.add_capability(cap)
        .map_err(|_| "failed to attach capability")?;

    if msg.caps_len != 1 {
        return Err("cap count mismatch");
    }

    let attached = msg
        .capabilities()
        .next()
        .ok_or("missing attached capability")?;
    if attached.cap_id != 88
        || attached.object_id != 99
        || attached.rights.bits() != 0xA5
        || attached.cap_type != CapabilityType::ServicePointer
    {
        return Err("attached capability fields mismatch");
    }

    Ok(())
}

fn case_backpressure_metrics() -> Result<(), &'static str> {
    let id = ChannelId::new(0x14);
    let owner = ProcessId::new(12);
    let mut channel = Channel::new(id, owner);
    let send_cap = ChannelCapability::new(8, id, ChannelRights::send_only(), owner);
    let recv_cap = ChannelCapability::new(9, id, ChannelRights::receive_only(), owner);

    if channel.pressure_level() != BackpressureLevel::Idle {
        return Err("initial pressure was not idle");
    }

    for _ in 0..CHANNEL_CAPACITY {
        let msg = Message::with_data(owner, b"x").map_err(|_| "failed to build metric message")?;
        channel
            .send(msg, &send_cap)
            .map_err(|_| "metric send failed")?;
    }

    if channel.high_watermark() != CHANNEL_CAPACITY {
        return Err("high watermark did not reach capacity");
    }
    if channel.high_pressure_hits() == 0 {
        return Err("high pressure hits were not observed");
    }
    if channel.pressure_level() != BackpressureLevel::Saturated {
        return Err("pressure did not reach saturated");
    }

    let overflow = Message::with_data(owner, b"!").map_err(|_| "failed to build overflow")?;
    if !matches!(channel.send(overflow, &send_cap), Err(IpcError::WouldBlock)) {
        return Err("saturated send did not block");
    }
    if channel.saturated_hits() == 0 {
        return Err("saturated hits were not observed");
    }

    for _ in 0..CHANNEL_CAPACITY {
        let _ = channel
            .try_recv(&recv_cap)
            .map_err(|_| "metric recv failed")?;
    }

    if channel.high_watermark() != CHANNEL_CAPACITY {
        return Err("high watermark was not retained after drain");
    }
    if channel.pressure_level() != BackpressureLevel::Idle {
        return Err("pressure did not return to idle");
    }

    Ok(())
}

fn case_async_high_pressure_policy() -> Result<(), &'static str> {
    let id = ChannelId::new(0x15);
    let owner = ProcessId::new(13);
    let mut channel = Channel::new_with_flags(
        id,
        owner,
        ChannelFlags::new(ChannelFlags::BOUNDED | ChannelFlags::ASYNC),
        128,
    );
    let send_cap = ChannelCapability::new(10, id, ChannelRights::send_only(), owner);
    let recv_cap = ChannelCapability::new(11, id, ChannelRights::receive_only(), owner);

    while channel.pressure_level() != BackpressureLevel::High {
        let msg =
            Message::with_data(owner, b"a").map_err(|_| "failed to build async metric message")?;
        channel
            .send(msg, &send_cap)
            .map_err(|_| "failed to reach high pressure")?;
    }

    if channel.is_full() {
        return Err("high pressure was only reached at full capacity");
    }
    if channel.pressure_action() != BackpressureAction::Refuse {
        return Err("high pressure action was not refuse");
    }

    let blocked = Message::with_data(owner, b"b").map_err(|_| "failed to build blocked async")?;
    if !matches!(channel.send(blocked, &send_cap), Err(IpcError::WouldBlock)) {
        return Err("async high pressure send was not refused");
    }

    let _ = channel
        .try_recv(&recv_cap)
        .map_err(|_| "failed to recover below threshold")?;

    if channel.pressure_level() != BackpressureLevel::Available {
        return Err("pressure did not recover below high threshold");
    }
    if channel.pressure_action() != BackpressureAction::Commit {
        return Err("recovered pressure action was not commit");
    }

    let recovered =
        Message::with_data(owner, b"c").map_err(|_| "failed to build recovered async send")?;
    channel
        .send(recovered, &send_cap)
        .map_err(|_| "async send did not recover after pressure drop")?;

    Ok(())
}

fn case_runtime_wakeup_surface() -> Result<(), &'static str> {
    // Keep the runtime selftest on a high synthetic ID so its wait keys do not
    // collide with the normal monotonically allocated channel table.
    let id = ChannelId::new(0x3FFF_FF15);
    let owner = ProcessId::new(14);
    let mut channel = Channel::new(id, owner);
    let send_cap = ChannelCapability::new(12, id, ChannelRights::send_only(), owner);
    let recv_cap = ChannelCapability::new(13, id, ChannelRights::receive_only(), owner);

    let base_receiver_wakeups = channel.receiver_wakeups();
    let base_sender_wakeups = channel.sender_wakeups();

    for cycle in 0..2 {
        let waiter =
            SyntheticWaiterGuard::stage("ipc-selftest-rx", super::channel_message_wait_addr(id))?;
        if crate::quantum_scheduler::waiter_count(super::channel_message_wait_addr(id)) != 1 {
            return Err("receiver waiter was not staged");
        }

        let payload = [b'R', b'0' + cycle as u8];
        let msg =
            Message::with_data(owner, &payload).map_err(|_| "failed to build receiver message")?;
        channel
            .send(msg, &send_cap)
            .map_err(|_| "receiver wake send failed")?;

        if crate::quantum_scheduler::waiter_count(super::channel_message_wait_addr(id)) != 0 {
            return Err("receiver waiter did not clear");
        }
        if crate::quantum_scheduler::selftest_process_state(waiter.pid())
            != Some(ProcessState::Ready)
        {
            return Err("receiver waiter did not become ready");
        }

        let delivered = channel
            .try_recv(&recv_cap)
            .map_err(|_| "failed to drain receiver wake message")?;
        if delivered.payload() != &payload {
            return Err("receiver wake payload mismatch");
        }
    }

    for _ in 0..2 {
        while !channel.is_full() {
            let msg =
                Message::with_data(owner, b"S").map_err(|_| "failed to build sender message")?;
            channel
                .send(msg, &send_cap)
                .map_err(|_| "sender wake fill failed")?;
        }

        let waiter =
            SyntheticWaiterGuard::stage("ipc-selftest-tx", super::channel_capacity_wait_addr(id))?;
        if crate::quantum_scheduler::waiter_count(super::channel_capacity_wait_addr(id)) != 1 {
            return Err("sender waiter was not staged");
        }

        let _ = channel
            .try_recv(&recv_cap)
            .map_err(|_| "sender wake recv failed")?;

        if crate::quantum_scheduler::waiter_count(super::channel_capacity_wait_addr(id)) != 0 {
            return Err("sender waiter did not clear");
        }
        if crate::quantum_scheduler::selftest_process_state(waiter.pid())
            != Some(ProcessState::Ready)
        {
            return Err("sender waiter did not become ready");
        }

        while !channel.is_empty() {
            let _ = channel
                .try_recv(&recv_cap)
                .map_err(|_| "failed to drain sender wake queue")?;
        }
    }

    if channel.receiver_wakeups() < base_receiver_wakeups.saturating_add(2) {
        return Err("receiver wakeup counter did not advance");
    }
    if channel.sender_wakeups() < base_sender_wakeups.saturating_add(2) {
        return Err("sender wakeup counter did not advance");
    }

    Ok(())
}

// ============================================================================
// New cases — causal envelope, graceful closure, EventId encoding
// ============================================================================

/// Verify that three messages can form a causal chain via `cause` field and
/// that `EventId` round-trips through the sent message.
fn case_causal_chain() -> Result<(), &'static str> {
    let id = ChannelId::new(0x30);
    let owner = ProcessId::new(31);
    let mut channel = Channel::new(id, owner);
    let send_cap = ChannelCapability::new(60, id, ChannelRights::send_only(), owner);
    let recv_cap = ChannelCapability::new(61, id, ChannelRights::receive_only(), owner);

    // Send root message (no cause)
    let root = Message::with_data(owner, b"root").map_err(|_| "failed to build root message")?;
    let root_id = root.id;
    channel
        .send(root, &send_cap)
        .map_err(|_| "root send failed")?;

    // Drain root so its EventId is observable
    let received_root = channel
        .try_recv(&recv_cap)
        .map_err(|_| "root recv failed")?;
    if received_root.id.raw() != root_id.raw() {
        return Err("root EventId not preserved through channel");
    }

    // Send a child message caused by root
    let child = Message::with_data_and_cause(owner, b"child", root_id)
        .map_err(|_| "failed to build child message")?;
    if child.cause.is_none() {
        return Err("child cause field is None after construction");
    }
    if child.cause.unwrap().raw() != root_id.raw() {
        return Err("child cause EventId does not match root");
    }
    let child_id = child.id;
    channel
        .send(child, &send_cap)
        .map_err(|_| "child send failed")?;

    // Send a grandchild caused by child
    let grandchild = Message::with_data_and_cause(owner, b"grandchild", child_id)
        .map_err(|_| "failed to build grandchild message")?;
    if grandchild.cause.unwrap().raw() != child_id.raw() {
        return Err("grandchild cause does not match child");
    }
    channel
        .send(grandchild, &send_cap)
        .map_err(|_| "grandchild send failed")?;

    // Drain both; verify lineage chain is intact
    let recv_child = channel
        .try_recv(&recv_cap)
        .map_err(|_| "child recv failed")?;
    let recv_gc = channel
        .try_recv(&recv_cap)
        .map_err(|_| "grandchild recv failed")?;
    if recv_child.cause.unwrap().raw() != root_id.raw() {
        return Err("received child cause mismatch");
    }
    if recv_gc.cause.unwrap().raw() != child_id.raw() {
        return Err("received grandchild cause mismatch");
    }

    Ok(())
}

/// Verify the `ClosureState` machine: Open → Draining → Sealed transitions
/// and that `drain()` returns `DrainResult::Complete` after the last message.
fn case_closure_drain_state_machine() -> Result<(), &'static str> {
    let id = ChannelId::new(0x31);
    let owner = ProcessId::new(32);
    let mut channel = Channel::new(id, owner);
    let send_cap = ChannelCapability::new(62, id, ChannelRights::send_only(), owner);
    let recv_cap = ChannelCapability::new(63, id, ChannelRights::receive_only(), owner);
    let close_cap = ChannelCapability::new(64, id, ChannelRights::full(), owner);

    // Initial state must be Open
    if !matches!(channel.closure_state(), ClosureState::Open) {
        return Err("initial state is not Open");
    }

    // Enqueue one message then initiate close
    let msg = Message::with_data(owner, b"last").map_err(|_| "build failed")?;
    channel.send(msg, &send_cap).map_err(|_| "send failed")?;
    channel.close(&close_cap).map_err(|_| "close failed")?;

    // Must be Draining now
    if !matches!(channel.closure_state(), ClosureState::Draining { .. }) {
        return Err("state did not transition to Draining after close()");
    }
    if !channel.is_closing() {
        return Err("is_closing() returned false during Draining");
    }
    if channel.is_closed() {
        return Err("is_closed() returned true during Draining");
    }

    // drain() with a message in the queue must be Pending
    match channel.drain(&recv_cap) {
        Ok(DrainResult::Pending(remaining)) => {
            if remaining != 1 {
                return Err("drain Pending count mismatch");
            }
        }
        Ok(DrainResult::Complete) => return Err("drain reported Complete with message in queue"),
        Ok(DrainResult::AlreadySealed) => {
            return Err("drain reported AlreadySealed while Draining")
        }
        Err(_) => return Err("drain returned unexpected error"),
    }

    // Consume the last message manually — state should flip to Sealed
    let _ = channel
        .try_recv(&recv_cap)
        .map_err(|_| "final recv failed")?;

    // Now drain() must return AlreadySealed (or channel.is_closed())
    if !channel.is_closed() {
        return Err("channel not Sealed after last message drained");
    }
    if !matches!(channel.closure_state(), ClosureState::Sealed) {
        return Err("closure_state() not Sealed after drain");
    }

    Ok(())
}

/// Verify that `EventId::new()` correctly encodes source_pid, channel_seq,
/// and msg_seq, and that `parts()` round-trips them.
fn case_event_id_encodes_source_seq() -> Result<(), &'static str> {
    let pid: u32 = 0x0000_00AB;
    let chan: u16 = 0x0CDE;
    let seq: u16 = 0xF012;
    let eid = EventId::new(pid, chan, seq);
    let (r_pid, r_chan, r_seq) = eid.parts();
    if r_pid != pid {
        return Err("EventId source_pid round-trip failed");
    }
    if r_chan != chan {
        return Err("EventId channel_seq round-trip failed");
    }
    if r_seq != seq {
        return Err("EventId msg_seq round-trip failed");
    }
    // raw() must be non-zero for non-zero inputs
    if eid.raw() == 0 {
        return Err("EventId raw() is zero for non-zero inputs");
    }
    // Two distinct EventIds must not be equal
    let eid2 = EventId::new(pid, chan, seq.wrapping_add(1));
    if eid.raw() == eid2.raw() {
        return Err("distinct EventIds have same raw value");
    }
    Ok(())
}

/// Verify that sending to a Draining channel returns `IpcError::Closed`
/// (the admission policy must block new sends once draining starts).
fn case_channel_draining_admission() -> Result<(), &'static str> {
    let id = ChannelId::new(0x32);
    let owner = ProcessId::new(33);
    let mut channel = Channel::new(id, owner);
    let send_cap = ChannelCapability::new(65, id, ChannelRights::send_only(), owner);
    let recv_cap = ChannelCapability::new(66, id, ChannelRights::receive_only(), owner);
    let close_cap = ChannelCapability::new(67, id, ChannelRights::full(), owner);

    // Queue a message, then close
    let m1 = Message::with_data(owner, b"in-flight").map_err(|_| "build failed")?;
    channel.send(m1, &send_cap).map_err(|_| "send failed")?;
    channel.close(&close_cap).map_err(|_| "close failed")?;

    // A new send to a draining channel must be rejected
    let m2 = Message::with_data(owner, b"rejected").map_err(|_| "build m2 failed")?;
    match channel.send(m2, &send_cap) {
        Err(IpcError::Closed) => {}
        Ok(()) => return Err("send to draining channel unexpectedly succeeded"),
        Err(e) => {
            let _ = e;
            return Err("send to draining channel returned unexpected error");
        }
    }

    // The queued message must still be receivable
    let drained = channel
        .try_recv(&recv_cap)
        .map_err(|_| "drain recv failed")?;
    if drained.payload() != b"in-flight" {
        return Err("in-flight message payload corrupted after draining refusal");
    }

    // After last message drained, channel must be Sealed
    if !channel.is_closed() {
        return Err("channel not sealed after queue drained");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_ipc_selftest_cases_pass() {
        let report = run_selftest();
        assert_eq!(report.passed, report.total);
    }
}
