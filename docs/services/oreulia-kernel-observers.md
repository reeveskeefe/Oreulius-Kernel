# Oreulius Kernel Observers

**Status:** Implemented as a lightweight WASM-observer event bus over IPC.

Primary implementation surfaces:

- [`kernel/src/execution/wasm.rs`](../../kernel/src/execution/wasm.rs)
- [`kernel/src/security/mod.rs`](../../kernel/src/security/mod.rs)
- [`kernel/src/capability/mod.rs`](../../kernel/src/capability/mod.rs)
- [`wasm/sdk/src/observer.rs`](../../wasm/sdk/src/observer.rs)

Host ABI:

- `106` `observer_subscribe`
- `107` `observer_unsubscribe`
- `108` `observer_query`

---

## 1. What the observer system currently is

Kernel observers let a WASM module subscribe to selected kernel event classes and receive those events asynchronously over a dedicated IPC channel. In SDK terms, this is the `subscribe` / `query` / `events` vocabulary: `query` drains the channel directly, while `events()` presents the same feed as a small batch iterator.

This is intentionally simple:

- at most `4` observer slots
- fixed 32-byte event messages
- best-effort delivery
- no kernel blocking on a full observer channel

The subsystem is real and useful, but it is lower-bandwidth and less normalized than some of the older docs implied.

---

## 2. Current subscription model

The runtime maintains:

- `MAX_OBSERVER_SLOTS = 4`

Each active observer entry stores:

- `instance_id`
- `channel_id`
- `event_mask`
- `owner_pid`

When a module subscribes:

1. the kernel creates an IPC channel
2. the observer slot is populated with the instance id and mask
3. the returned value is the raw channel id used for event delivery

When a module unsubscribes:

- the slot is marked inactive
- the channel is closed on a best-effort basis

---

## 3. Event mask definitions

The currently defined event bits are:

| Constant | Meaning |
| --- | --- |
| `CAPABILITY_OP` | capability-related event |
| `PROCESS_LIFECYCLE` | process or instance lifecycle event |
| `ANOMALY_DETECTED` | security manager anomaly event |
| `IPC_ACTIVITY` | IPC-like transport activity event |
| `MEMORY_PRESSURE` | reserved memory-pressure event bit |
| `POLYGLOT_LINK` | polyglot link or related observer/mesh event |
| `ALL` | all bits currently defined |

Two important accuracy notes:

- `MEMORY_PRESSURE` is defined in the event mask table, but I did not find an active emitter for it in the current tree.
- `IPC_ACTIVITY` is **not** currently a universal "every channel send/recv" feed. It is used for specific transport-style emissions, such as mesh token/frame export.

---

## 4. Event encoding and delivery

Observers receive fixed 32-byte messages over IPC.

Current encoding:

- bytes `0..4`: `event_type` as `u32 LE`
- bytes `4..32`: event-specific payload, zero-padded

The SDK decodes those bytes into:

- `event_type`
- `field_a`
- `field_b`
- `20` reserved bytes

That decode is useful, but the meaning of `field_a` and `field_b` is **not globally normalized across all producers**. Different producers pack different payloads into the 28-byte body.

So the stable contract today is:

- fixed 32-byte event frame
- event type in the first word
- producer-specific compact payload in the remaining bytes

### Delivery semantics

Delivery is best-effort:

- matching observers are discovered from the registry
- the registry lock is dropped before IPC send
- the kernel attempts to send one IPC message per observer
- failures are ignored

If an observer channel is full, the event is dropped for that observer.

---

## 5. Active event producers in the current tree

The observer system is implemented, but the active producers are narrower than the older doc claimed.

### 5.1 `CAPABILITY_OP`

Currently emitted from capability-related paths, including:

- capability grant notifications
- capability revoke notifications
- temporal capability auto-revocation

The payload format is producer-specific. For example:

- capability grant/revoke paths pack PID plus compact capability metadata
- temporal auto-revoke emits PID plus a small revoke tag

So consumers should treat the body as a compact tagged payload, not as a single globally stable schema.

### 5.2 `PROCESS_LIFECYCLE`

Currently emitted from the WASM/runtime process lifecycle path when new process or instance lifecycle events are staged.

### 5.3 `ANOMALY_DETECTED`

Currently emitted by the security subsystem when it records anomalous behavior.

### 5.4 `IPC_ACTIVITY`

Currently used for transport-style event publication, especially mesh/capnet-related frame export paths.

It should not be described as "all IPC activity" at this point.

### 5.5 `POLYGLOT_LINK`

Currently emitted from several places, including:

- actual polyglot link establishment
- observer subscription bootstrap notification
- mesh migration queue flush notifications

So the name `POLYGLOT_LINK` is historically rooted, but in practice the bit is already reused for a broader class of integration notifications.

### 5.6 `MEMORY_PRESSURE`

Defined, but not currently backed by an active emitter in the code I inspected.

---

## 6. Host ABI behavior

### 6.1 `observer_subscribe`

`observer_subscribe(event_mask) -> i32`

Current behavior:

- returns `-1` for zero mask
- returns `-2` if channel creation fails
- returns `-3` if the observer table is full
- otherwise returns the observer channel id (`> 0`)

After successful registration, the runtime emits a `POLYGLOT_LINK` notification containing the new observer's mask as a bootstrap signal.

### 6.2 `observer_unsubscribe`

`observer_unsubscribe() -> i32`

Current behavior:

- returns `-1` if the caller was not subscribed
- otherwise deactivates the observer slot and best-effort closes the channel
- returns `0` on success

### 6.3 `observer_query`

`observer_query(buf_ptr, buf_len) -> i32`

Current behavior:

- resolves the caller's observer channel from the registry
- drains up to `buf_len / 32` events
- returns the number of events written
- returns `-1` if the caller is not registered

The SDK wrapper preserves the error result rather than collapsing it into `0`, so SDK-level callers can distinguish "no events" from "not subscribed."

---

## 7. SDK surface

The SDK wrapper in [`wasm/sdk/src/observer.rs`](../../wasm/sdk/src/observer.rs) currently exposes:

- `subscribe(event_mask) -> Result<u32, i32>`
- `unsubscribe() -> Result<(), i32>`
- `query(&mut [ObserverEvent]) -> Result<usize, i32>`
- `events() -> ObserverEventIter`

It also exposes the event-bit constants and the `ObserverEvent` struct used to decode the 32-byte frame.

This SDK is a good description of the current consumer-facing API, but callers still need to remember that `field_a` and `field_b` are only lightly structured producer payload words, not a universal schema.

---

## 8. What is implemented today

Accurate claims:

- observer subscriptions are implemented
- delivery uses dedicated IPC channels
- multiple kernel subsystems emit real events
- delivery is asynchronous and best-effort
- the SDK wrapper is present and usable

Claims that should not be made:

- that every defined event bit already has an active producer
- that `IPC_ACTIVITY` means all channel sends/receives system-wide
- that every event type already shares one fully normalized payload schema

The correct public description is that Oreulius has a working observer bus for WASM modules, but it is intentionally small and still evolving toward a richer event taxonomy.
