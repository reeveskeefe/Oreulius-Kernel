warning: unused import: `alloc::vec::Vec`
  --> src/hardened_allocator.rs:13:5
   |
13 | use alloc::vec::Vec; // Used for allocation tracking
   |     ^^^^^^^^^^^^^^^
   |
   = note: `#[warn(unused_imports)]` on by default

Plan:
- Add allocation tracking storage (e.g., Vec<AllocationRecord>) to the allocator state.
- Push a record on allocation and remove/update it on deallocation.
- Expose allocator stats (count, high‑water mark, leaks) via a debug command or log hook.

Plan:
- Use Vec for allocation tracking (e.g., store active allocations or leak detection). If tracking is deferred, gate it behind a feature flag and keep the import with a TODO explaining the intended tracking structure.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unused doc comment
   --> src/quantum_scheduler.rs:538:1
    |
538 | /// Global scheduler instance
    | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ rustdoc does not generate documentation for macro invocations
    |
    = help: to document an item produced by a macro, the macro must produce the documentation as part of its expansion
    = note: `#[warn(unused_doc_comments)]` on by default

Plan:
- Move the doc comment into the macro expansion using #[doc = "..."] on the generated item.
- Ensure the doc comment is attached to the actual static or struct that the macro emits.
- Rebuild and verify rustdoc no longer warns about unused doc comments.

Plan:
- Move the doc comment into the macro expansion (use #[doc = "..."] on the generated item) or place the comment directly on the generated static/struct inside the macro.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unused variable: `object_id`
   --> src/capability.rs:498:5
    |
498 |     object_id: u64,
    |     ^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_object_id`
    |
    = note: `#[warn(unused_variables)]` on by default

Plan:
- Look up the capability record by object_id in the process capability table.
- Validate that the record exists and is active before proceeding.
- Return a precise error when the object_id does not resolve or is revoked.

Plan:
- Use object_id in the capability lookup (validate the capability references the intended object) or store it for audit logs. Until wired, rename to _object_id with a TODO to implement the lookup.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unused variable: `cap_type`
   --> src/capability.rs:499:5
    |
499 |     cap_type: CapabilityType,
    |     ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_cap_type`

Plan:
- Compare cap_type against the stored capability type in the table.
- Reject mismatched types with a CapabilityTypeMismatch error.
- Add a unit test covering a mismatched type failure.

Plan:
- Use cap_type to verify the capability type matches the request (e.g., CapabilityType::X). Until implemented, rename to _cap_type and add a TODO for type enforcement.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unused variable: `required_rights`
   --> src/capability.rs:500:5
    |
500 |     required_rights: Rights,
    |     ^^^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_required_rights`

Plan:
- Compare required_rights to the capability’s granted rights (bitflags).
- Fail fast when required rights are missing.
- Add tests for allow/deny paths with mixed rights.

Plan:
- Use required_rights to validate rights against the capability table; if not ready, rename to _required_rights and add TODO for rights enforcement.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unused variable: `cap2`
    --> src/commands.rs:1382:16
     |
1382 |     let (cap1, cap2) = match channel_result {
     |                ^^^^ help: if this is intentional, prefix it with an underscore: `_cap2`

Plan:
- Return both cap1 and cap2 to the caller (print both IDs or store both handles).
- Update command output to show both endpoints (read/write or tx/rx).
- Add a small usage example in the CLI help for channel creation.

Plan:
- Use cap2 to return/store the second endpoint capability (e.g., display both IDs or install both in the caller). If only cap1 is needed today, document why cap2 is intentionally unused and keep a TODO for multi-endpoint usage.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unused variable: `cap2`
    --> src/commands.rs:1562:16
     |
1562 |     let (cap1, cap2) = match channel_result {
     |                ^^^^ help: if this is intentional, prefix it with an underscore: `_cap2`

Plan:
- Wire cap2 into the command’s return path or capability registry.
- Expose both ends to the user so they can pass either endpoint to subsequent commands.
- Add a minimal test or log output confirming both IDs are live.

Plan:
- Use cap2 to return/store the second endpoint capability (mirrors the earlier command). If not needed yet, mark as _cap2 and add a TODO describing the intended use.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unused variable: `layout`
   --> src/hardened_allocator.rs:168:55
    |
168 |     pub unsafe fn deallocate(&mut self, ptr: *mut u8, layout: Layout) {
    |                                                       ^^^^^^ help: if this is intentional, prefix it with an underscore: `_layout`

Plan:
- Use layout to validate deallocation size/alignment against the recorded allocation.
- Update allocator statistics using layout.size() and layout.align().
- Panic or log on mismatched deallocation to detect memory corruption.

Plan:
- Use layout to verify deallocation size/alignment, update stats, or detect mismatched frees. If not used yet, rename to _layout and add a TODO for size validation.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unused variable: `efficiency`
   --> src/hardened_allocator.rs:246:13
    |
246 |         let efficiency = if total_heap > 0 {
    |             ^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_efficiency`

Plan:
- Compute efficiency and store it in the allocator stats struct.
- Expose efficiency via a debug command or periodic log.
- Use it to trigger warnings when fragmentation exceeds a threshold.

Plan:
- Use efficiency to compute/report allocator health (e.g., log to debug console or store in stats struct). If reporting is deferred, keep the calculation and wire it into a metrics output path.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unused variable: `request`
   --> src/net.rs:469:13
    |
469 |         let request = self.build_http_request(method, host, path);
    |             ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_request`

Plan:
- Send the built HTTP request over the active TCP socket (write/send path).
- Ensure the request bytes are queued or transmitted before reading the response.
- Add a basic integration test that performs a GET and checks response parsing.

Plan:
- Use request to send the HTTP payload over the socket or log it for debug. If the request build is preparatory, add TODO and integrate it into the transmit path.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: value assigned to `action` is never read
   --> src/netstack.rs:999:21
    |
999 | ...   let mut action: Option<(TcpEndpoint, u32, u32, u16, [u8; 256], usi...
    |               ^^^^^^
    |
    = help: maybe it is overwritten before being read?
    = note: `#[warn(unused_assignments)]` on by default

Plan:
- Use the action variable as the final decision for state transition or output.
- Assign action once per branch and consume it in the subsequent logic.
- Add a debug log showing the chosen action for traceability.

Plan:
- Use action to drive the state transition/output decision. If it is overwritten later, remove the initial assignment or restructure so the default action is meaningful.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unused variable: `ip_start`
    --> src/netstack.rs:1089:9
     |
1089 |     let ip_start = off;
     |         ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_ip_start`

Plan:
- Use ip_start to validate header boundaries and compute checksum offsets.
- Add bounds checks using ip_start + header_len against packet length.
- Log or return an error if the offset is invalid.

Plan:
- Use ip_start when parsing or validating header offsets (e.g., for checksum or bounds checks). If it is only for debug, log it under a debug flag.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: variable does not need to be mutable
   --> src/quantum_scheduler.rs:276:13
    |
276 |         let mut prev = self.current_pid;
    |             ----^^^^
    |             |
    |             help: remove this `mut`
    |
    = note: `#[warn(unused_mut)]` on by default

Plan:
- Remove the unnecessary mut from prev.
- Confirm no mutation is required in subsequent logic.
- Rebuild to confirm no warnings remain.

Plan:
- Remove mut from prev unless it will be updated later. If you intend to modify it, add the mutation where the value actually changes.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unused variable: `args`
   --> src/syscall.rs:251:15
    |
251 | fn sys_getpid(args: SyscallArgs, caller_pid: capability::ProcessId) -> S...
    |               ^^^^ help: if this is intentional, prefix it with an underscore: `_args`

Plan:
- Validate that args fields are zeroed for sys_getpid (no parameters expected).
- Return EINVAL if unexpected arguments are provided.
- Document the argument contract in syscall docs.

Plan:
- Use args to validate or ignore extra parameters consistently (e.g., ensure zeroed). If no args are expected, rename to _args and document that sys_getpid ignores parameters.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unused variable: `args`
   --> src/syscall.rs:313:23
    |
313 | fn sys_channel_create(args: SyscallArgs, caller_pid: capability::Process...
    |                       ^^^^ help: if this is intentional, prefix it with an underscore: `_args`

Plan:
- Parse args for channel options (buffer size, flags, policy).
- Pass parsed options into the channel creation routine.
- Add validation for unsupported flags and return EINVAL.

Plan:
- Use args to accept channel options (buffer size, flags). If not implemented yet, rename to _args and add a TODO for argument parsing.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: variable does not need to be mutable
   --> src/terminal.rs:298:13
    |
298 |         let mut get = |idx: usize, default: u16| -> u16 {
    |             ----^^^
    |             |
    |             help: remove this `mut`

Plan:
- Remove the unnecessary mut from the closure.
- Keep the closure pure and side‑effect free.
- Rebuild to confirm warning is resolved.

Plan:
- Remove mut from the closure if it is not mutated. If you intended to reassign the closure, add the mutation explicitly.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unused variable: `blank`
   --> src/vga.rs:251:9
    |
251 |     let blank = ScreenChar {
    |         ^^^^^ help: if this is intentional, prefix it with an underscore: `_blank`

Plan:
- Use blank as the fill value when clearing the screen buffer.
- Replace any repeated literal ScreenChar construction with this variable.
- Ensure scroll and clear paths both reuse the blank value.

Plan:
- Use blank to fill the screen buffer when clearing or scrolling. If not needed, remove the variable and inline a literal in the fill loop.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: variable does not need to be mutable
   --> src/vfs.rs:685:25
    |
685 |                     let mut text = generate_partition_text()?;
    |                         ----^^^^
    |                         |
    |                         help: remove this `mut`

Plan:
- Append additional generated metadata to text (e.g., partition summary).
- Use text.push_str(...) to incorporate extra details.
- Return the enriched string for display or logging.

Plan:
- Remove mut from text if it is not mutated. If you plan to modify the generated text, add the mutation explicitly.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: value assigned to `oldest` is never read
   --> src/virtio_blk.rs:217:17
    |
217 |                 oldest = 0;
    |                 ^^^^^^
    |
    = help: maybe it is overwritten before being read?

Plan:
- Track the oldest request index during traversal.
- Use oldest to evict or retry when the queue is full.
- Add a debug log when an eviction decision is made.

Plan:
- Use oldest to track the LRU/oldest request for eviction. If the algorithm is incomplete, add TODO and wire oldest into the selection step.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: variable does not need to be mutable
   --> src/virtio_blk.rs:413:9
    |
413 |     let mut driver = VirtioBlk {
    |         ----^^^^^^
    |         |
    |         help: remove this `mut`

Plan:
- Remove the unnecessary mut from driver initialization.
- Keep the driver immutable unless configuration changes occur.
- Rebuild to confirm warning is resolved.

Plan:
- Remove mut if driver is not mutated after initialization. If mutation is intended, add the changes where they occur.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unreachable pattern
   --> src/wasm_jit.rs:124:41
    |
124 | ...   Opcode::If | Opcode::Else | Opcode::End | Opcode::Br | Opcode::BrI...
    |                                   ^^^^^^^^^^^
    |
    = note: `#[warn(unreachable_patterns)]` on by default

Plan:
- Remove the duplicate opcode pattern or reorder match arms to avoid overlap.
- Group control‑flow opcodes under a single arm with explicit handling.
- Add a small opcode dispatch test to confirm correct matching.

Plan:
- Fix the match by removing the duplicate pattern or reordering patterns so each opcode is handled once. Add a test case to confirm control-flow ops map correctly.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unused variable: `channel`
   --> src/wifi.rs:453:38
    |
453 | ...probe_request(&mut self, channel: u8) -> Result<(), WifiError> {
    |                             ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_channel`

Plan:
- Set the hardware channel before issuing a probe request.
- Use the channel argument to iterate or select specific band/channel.
- Record scan results per channel for later selection.

Plan:
- Use channel to select the active channel for probe requests. If auto-scan is planned, use channel as the loop variable and track per-channel results.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unused variable: `password`
   --> src/wifi.rs:756:38
    |
756 | ...rm_connection(&mut self, password: Option<&str>) -> Result<(), WifiEr...
    |                             ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_password`

Plan:
- Use password to derive a PSK (PBKDF2) for WPA/WPA2 authentication.
- Pass the derived key into the handshake state machine.
- Return a clear error if password is missing for secured networks.

Plan:
- Use password for authentication (WPA/WPA2 handshake). If not implemented, store it temporarily and add TODO for key derivation/handshake.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unused variable: `init_pid`
  --> src/tasks.rs:92:9
   |
92 |     let init_pid = match process::current_pid() {
   |         ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_init_pid`

Plan:
- Use init_pid for logging and scheduler bookkeeping.
- Register init_pid as the primary system process in the scheduler.
- Expose init_pid in a debug command for verification.

Plan:
- Use init_pid for logging, scheduling, or capability setup of the init task. If not needed, rename to _init_pid and document why.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unused variable: `stack`
   --> src/lib.rs:218:29
    |
218 |             if let Some(mut stack) = netstack::NETWORK_STACK.try_lock() {
    |                             ^^^^^ help: if this is intentional, prefix it with an underscore: `_stack`

Plan:
- Use stack to poll or process pending network events.
- Drain outbound queues and service inbound packets while the lock is held.
- Add a short log for activity to verify the path is exercised.

Plan:
- Use stack to actually send/receive network packets or drain queues. If try_lock is only a probe, rename to _stack and add a TODO explaining the planned call path.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: variable does not need to be mutable
   --> src/lib.rs:218:25
    |
218 |             if let Some(mut stack) = netstack::NETWORK_STACK.try_lock() {
    |                         ----^^^^^
    |                         |
    |                         help: remove this `mut`

Plan:
- Use stack to poll or process pending network events.
- Drain outbound queues and service inbound packets while the lock is held.
- Add a short log for activity to verify the path is exercised.

Plan:
- Use stack to actually send/receive network packets or drain queues. If try_lock is only a probe, rename to _stack and add a TODO explaining the planned call path.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: variable `max_len` is assigned to, but never used
   --> src/lib.rs:252:13
    |
252 |     let mut max_len = vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);
    |             ^^^^^^^
    |
    = note: consider using `_max_len` instead

Plan:
- Use max_len to cap user input length in the line editor.
- Clamp cursor movement to the prompt region using max_len.
- Add a test or debug log confirming truncation behavior.

Plan:
- Use max_len to enforce input length or truncate user input. If unused, remove the calculation and rely on screen width directly.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: value assigned to `max_len` is never read
   --> src/lib.rs:298:21
    |
298 | ...   max_len = vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);
    |       ^^^^^^^
    |
    = help: maybe it is overwritten before being read?

Plan:
- Use max_len to constrain redraw length after edits.
- Recompute max_len only when prompt position changes.
- Remove dead assignments that are immediately overwritten.

Plan:
- Use max_len in the input-edit path (truncate/scroll) or remove the overwritten assignment to avoid dead code.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: value assigned to `max_len` is never read
   --> src/lib.rs:327:21
    |
327 | ...   max_len = vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);
    |       ^^^^^^^
    |
    = help: maybe it is overwritten before being read?

Plan:
- Use max_len to limit insertions in the current line.
- Prevent buffer growth beyond the screen width.
- Add a log when input is clamped.

Plan:
- Use max_len for bounds checking during editing; if unused, remove the assignment.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: value assigned to `max_len` is never read
   --> src/lib.rs:376:21
    |
376 | ...   max_len = vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);
    |       ^^^^^^^
    |
    = help: maybe it is overwritten before being read?

Plan:
- Use max_len during backspace/erase to keep the cursor within bounds.
- Update redraw logic to respect max_len.
- Verify no out‑of‑bounds writes occur in the VGA buffer.

Plan:
- Use max_len to constrain redraw lengths; if unused, remove the assignment.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: value assigned to `max_len` is never read
   --> src/lib.rs:386:21
    |
386 | ...   max_len = vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);
    |       ^^^^^^^
    |
    = help: maybe it is overwritten before being read?

Plan:
- Use max_len to cap prompt editing region when rendering input.
- Guard cursor advancement against max_len.
- Ensure prompt redraw respects the cap.

Plan:
- Use max_len to cap prompt editing region; if unused, remove the assignment.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unnecessary `unsafe` block
   --> src/keyboard.rs:364:5
    |
364 |     unsafe { crate::asm_bindings::disable_interrupts(); }
    |     ^^^^^^ unnecessary `unsafe` block
    |
    = note: `#[warn(unused_unsafe)]` on by default

Plan:
- Remove the unnecessary unsafe block around disable_interrupts.
- Call the safe wrapper directly or expose a safe API.
- Document the safety invariants near asm_bindings if needed.

Plan:
- Remove unnecessary unsafe block if asm_bindings::disable_interrupts is safe. If it must be unsafe, mark the function unsafe and keep the block minimal.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unnecessary `unsafe` block
   --> src/keyboard.rs:366:5
    |
366 |     unsafe { crate::asm_bindings::enable_interrupts(); }
    |     ^^^^^^ unnecessary `unsafe` block

Plan:
- Remove the unnecessary unsafe block around enable_interrupts.
- Call the safe wrapper directly or expose a safe API.
- Document the safety invariants near asm_bindings if needed.

Plan:
- Remove unnecessary unsafe block if asm_bindings::enable_interrupts is safe. If it must be unsafe, mark the function unsafe and keep the block minimal.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unnecessary `unsafe` block
   --> src/keyboard.rs:373:5
    |
373 |     unsafe { crate::asm_bindings::disable_interrupts(); }
    |     ^^^^^^ unnecessary `unsafe` block

Plan:
- Remove the unnecessary unsafe block around disable_interrupts.
- Call the safe wrapper directly or expose a safe API.
- Document the safety invariants near asm_bindings if needed.

Plan:
- Remove unnecessary unsafe block if asm_bindings::disable_interrupts is safe. If it must be unsafe, mark the function unsafe and keep the block minimal.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unnecessary `unsafe` block
   --> src/keyboard.rs:375:5
    |
375 |     unsafe { crate::asm_bindings::enable_interrupts(); }
    |     ^^^^^^ unnecessary `unsafe` block

Plan:
- Remove the unnecessary unsafe block around enable_interrupts.
- Call the safe wrapper directly or expose a safe API.
- Document the safety invariants near asm_bindings if needed.

Plan:
- Remove unnecessary unsafe block if asm_bindings::enable_interrupts is safe. If it must be unsafe, mark the function unsafe and keep the block minimal.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unnecessary `unsafe` block
   --> src/scheduler.rs:269:17
    |
269 |                 unsafe {
    |                 ^^^^^^ unnecessary `unsafe` block

Plan:
- Remove the unnecessary unsafe block if no unsafe operations are inside.
- If an unsafe call exists, wrap only that call.
- Add a short safety comment describing invariants.

Plan:
- Remove unnecessary unsafe if no unsafe operations are performed; if needed, tighten the unsafe scope to just the unsafe call.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unnecessary `unsafe` block
    --> src/syscall.rs:1025:5
     |
1025 |     unsafe {
     |     ^^^^^^ unnecessary `unsafe` block

Plan:
- Remove the unnecessary unsafe block if no unsafe operations are inside.
- If needed, narrow the unsafe scope to the exact operation.
- Add a safety comment documenting invariants.

Plan:
- Remove unnecessary unsafe if not calling FFI/asm; otherwise, restrict unsafe to the exact unsafe operation.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unnecessary `unsafe` block
  --> src/tasks.rs:13:5
   |
13 |     unsafe { crate::asm_bindings::enable_interrupts(); }
   |     ^^^^^^ unnecessary `unsafe` block

Plan:
- Remove the unnecessary unsafe block around enable_interrupts.
- Use the safe wrapper if available.
- Add a safety comment only if the function remains unsafe.

Plan:
- Remove unnecessary unsafe if enable_interrupts is safe; otherwise mark it unsafe and narrow scope.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unnecessary `unsafe` block
  --> src/tasks.rs:27:5
   |
27 |     unsafe { crate::asm_bindings::enable_interrupts(); }
   |     ^^^^^^ unnecessary `unsafe` block

Plan:
- Remove the unnecessary unsafe block around enable_interrupts.
- Use the safe wrapper if available.
- Add a safety comment only if the function remains unsafe.

Plan:
- Remove unnecessary unsafe if enable_interrupts is safe; otherwise mark it unsafe and narrow scope.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unnecessary `unsafe` block
  --> src/tasks.rs:43:5
   |
43 |     unsafe { crate::asm_bindings::enable_interrupts(); }
   |     ^^^^^^ unnecessary `unsafe` block

Plan:
- Remove the unnecessary unsafe block around enable_interrupts.
- Use the safe wrapper if available.
- Add a safety comment only if the function remains unsafe.

Plan:
- Remove unnecessary unsafe if enable_interrupts is safe; otherwise mark it unsafe and narrow scope.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: unnecessary `unsafe` block
  --> src/tasks.rs:57:5
   |
57 |     unsafe { crate::asm_bindings::enable_interrupts(); }
   |     ^^^^^^ unnecessary `unsafe` block

Plan:
- Remove the unnecessary unsafe block around enable_interrupts.
- Use the safe wrapper if available.
- Add a safety comment only if the function remains unsafe.

Plan:
- Remove unnecessary unsafe if enable_interrupts is safe; otherwise mark it unsafe and narrow scope.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: field `rsdp_addr` is never read
   --> src/acpi_asm.rs:112:5
    |
111 | pub struct Acpi {
    |            ---- field in this struct
112 |     rsdp_addr: u32,
    |     ^^^^^^^^^
    |
    = note: `#[warn(dead_code)]` on by default

Plan:
- Expose rsdp_addr via a getter on Acpi or a debug method.
- Use rsdp_addr to locate and validate ACPI tables.
- Log the RSDP address during boot for diagnostics.

Plan:
- Use rsdp_addr for ACPI diagnostics or expose it via a getter for debugging. If intentionally unused, add #[allow(dead_code)] with a TODO for ACPI table parsing.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: function `parse_url_simple` is never used
    --> src/commands.rs:3264:4
     |
3264 | fn parse_url_simple(url: &str) -> (&str, &str) {
     |    ^^^^^^^^^^^^^^^^

Plan:
- Use parse_url_simple in the HTTP or network command path.
- Replace any ad‑hoc URL splitting with this helper.
- Add a small test set for common URL shapes.

Plan:
- Wire parse_url_simple into network/HTTP commands or remove it if superseded. If intended for future, add a TODO and test case.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: field `owner` is never read
  --> src/console_service.rs:25:5
   |
23 | struct Console {
   |        ------- field in this struct
24 |     object_id: u64,
25 |     owner: ProcessId,
   |     ^^^^^
   |
   = note: `Console` has derived impls for the traits `Clone` and `Debug`, but these are intentionally ignored during dead code analysis

Plan:
- Use owner to enforce console ownership on read/write operations.
- Reject access from non‑owner processes.
- Log ownership violations for auditability.

Plan:
- Use owner to enforce console ownership checks on read/write or auditing. If ownership model is deferred, keep the field with a TODO.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: constant `E1000_REG_EEPROM` is never used
  --> src/e1000.rs:13:7
   |
13 | const E1000_REG_EEPROM: u32 = 0x0014;    // EEPROM Read
   |       ^^^^^^^^^^^^^^^^

Plan:
- Read the EEPROM via E1000_REG_EEPROM during device init.
- Use values to verify MAC address or feature flags.
- Add a debug print of EEPROM status.

Plan:
- Use E1000_REG_EEPROM when implementing EEPROM access or feature detection. If unused now, add #[allow(dead_code)] and a TODO for EEPROM init.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: constant `E1000_REG_CTRL_EXT` is never used
  --> src/e1000.rs:14:7
   |
14 | const E1000_REG_CTRL_EXT: u32 = 0x0018;  // Extended Device Control
   |       ^^^^^^^^^^^^^^^^^^

Plan:
- Use E1000_REG_CTRL_EXT to configure extended device features.
- Set or clear flags based on desired link behavior.
- Verify changes via register readback.

Plan:
- Use E1000_REG_CTRL_EXT for advanced device control when enabling features. If unused now, annotate and add TODO.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: constant `E1000_REG_MTA` is never used
  --> src/e1000.rs:29:7
   |
29 | const E1000_REG_MTA: u32 = 0x5200;       // Multicast Table Array
   |       ^^^^^^^^^^^^^

Plan:
- Use E1000_REG_MTA to program multicast filters.
- Populate MTA for required multicast addresses.
- Add a test that joins a multicast group and receives packets.

Plan:
- Use E1000_REG_MTA for multicast filtering support. If unused now, annotate and add TODO.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: constant `E1000_TCTL_CT` is never used
  --> src/e1000.rs:47:7
   |
47 | const E1000_TCTL_CT: u32 = 0x00000FF0;   // Collision Threshold
   |       ^^^^^^^^^^^^^

Plan:
- Use E1000_TCTL_CT to tune transmit collision threshold.
- Set a sensible default based on link speed.
- Document the chosen value and rationale.

Plan:
- Use E1000_TCTL_CT for transmit tuning. If unused now, annotate and add TODO.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: constant `E1000_TCTL_COLD` is never used
  --> src/e1000.rs:48:7
   |
48 | const E1000_TCTL_COLD: u32 = 0x003FF000; // Collision Distance
   |       ^^^^^^^^^^^^^^^

Plan:
- Use E1000_TCTL_COLD to tune collision distance.
- Set a default matching the PHY configuration.
- Document the chosen value and rationale.

Plan:
- Use E1000_TCTL_COLD for transmit tuning. If unused now, annotate and add TODO.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: method `len` is never used
  --> src/keyboard.rs:47:12
   |
17 | impl KeyBuffer {
   | -------------- method in this implementation
...
47 |     pub fn len(&self) -> usize {
   |            ^^^

Plan:
- Use len() to expose buffer depth in debug stats.
- Use it to prevent buffer overflow on input enqueue.
- Add a debug log when buffer nears capacity.

Plan:
- Use len() to implement buffer depth checks or flow control. If intentionally unused, add TODO near callers to adopt it.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: function `is_data_available` is never used
   --> src/keyboard.rs:263:4
    |
263 | fn is_data_available() -> bool {
    |    ^^^^^^^^^^^^^^^^^

Plan:
- Call is_data_available in the keyboard ISR or polling loop.
- Use it to avoid reading when no data is present.
- Log or count spurious polls for diagnostics.

Plan:
- Use is_data_available in the input loop to avoid blocking reads or in an IRQ handler. If unused, add TODO to wire it into read path.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: function `read_scancode` is never used
   --> src/keyboard.rs:268:4
    |
268 | fn read_scancode() -> u8 {
    |    ^^^^^^^^^^^^^

Plan:
- Use read_scancode in the keyboard handler to fetch scan codes.
- Translate scan codes into key events.
- Push events into the keyboard queue.

Plan:
- Use read_scancode in the keyboard ISR or poll loop. If unused, add TODO to integrate into input queue.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: function `page_fault_handler` is never used
  --> src/paging.rs:26:8
   |
26 |     fn page_fault_handler();
   |        ^^^^^^^^^^^^^^^^^^

Plan:
- Register page_fault_handler in the IDT for the page fault vector.
- Implement a minimal handler that logs CR2 and fault code.
- Integrate with the pager or kill the offending process.

Plan:
- Wire page_fault_handler into IDT/page fault path or remove if handled elsewhere. If future work, add TODO and allow(dead_code).

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: function `copy_page_physical` is never used
  --> src/paging.rs:29:8
   |
29 |     fn copy_page_physical(src_phys: u32, dst_phys: u32);
   |        ^^^^^^^^^^^^^^^^^^

Plan:
- Use copy_page_physical in COW clone path.
- Call it when duplicating pages during fork.
- Add a test for page copying correctness.

Plan:
- Use copy_page_physical in COW or page cloning. Add TODO and hook into fork/COW path.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: function `zero_page` is never used
  --> src/paging.rs:31:8
   |
31 |     fn zero_page(addr: *mut u8);
   |        ^^^^^^^^^

Plan:
- Use zero_page when allocating new pages.
- Call it from the page allocator or mapping functions.
- Ensure the zeroed page is marked clean.

Plan:
- Use zero_page in page allocation or COW initialization. Add TODO to call from allocator.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: function `disable_paging` is never used
  --> src/paging.rs:44:8
   |
44 |     fn disable_paging();
   |        ^^^^^^^^^^^^^^

Plan:
- Use disable_paging in low‑level boot when switching page tables.
- Guard it with checks to ensure safe transitions.
- Add debug logs around paging transitions.

Plan:
- Use disable_paging in low-level boot or debug toggles; otherwise add TODO or remove.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: function `set_page_flags` is never used
  --> src/paging.rs:48:8
   |
48 |     fn set_page_flags(pte_addr: *mut u32, flags: u32);
   |        ^^^^^^^^^^^^^^

Plan:
- Use set_page_flags when mapping pages (present/readonly/user).
- Call it during PTE setup.
- Add tests to verify page permissions.

Plan:
- Use set_page_flags when updating PTEs; integrate into page mapping functions.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: function `clear_page_flags` is never used
  --> src/paging.rs:49:8
   |
49 |     fn clear_page_flags(pte_addr: *mut u32, flags: u32);
   |        ^^^^^^^^^^^^^^^^

Plan:
- Use clear_page_flags when unmapping or changing permissions.
- Call it in unmap or protection change paths.
- Add a check to flush TLB when needed.

Plan:
- Use clear_page_flags for unmapping/permission changes; integrate into page mapping functions.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: function `atomic_set_page_flags` is never used
  --> src/paging.rs:57:8
   |
57 |     fn atomic_set_page_flags(pte_addr: *mut u32, flags: u32);
   |        ^^^^^^^^^^^^^^^^^^^^^

Plan:
- Use atomic_set_page_flags for SMP‑safe updates to PTEs.
- Call it in concurrent mapping paths.
- Validate ordering with a barrier after updates.

Plan:
- Use atomic_set_page_flags where concurrent PTE updates occur; integrate into SMP-safe paging updates.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: function `atomic_clear_page_flags` is never used
  --> src/paging.rs:58:8
   |
58 |     fn atomic_clear_page_flags(pte_addr: *mut u32, flags: u32);
   |        ^^^^^^^^^^^^^^^^^^^^^^^

Plan:
- Use atomic_clear_page_flags for SMP‑safe unmaps.
- Call it where concurrent page updates occur.
- Add a TLB shootdown hook if SMP is enabled.

Plan:
- Use atomic_clear_page_flags for SMP-safe permission updates; integrate into page updates.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: function `atomic_inc_refcount` is never used
  --> src/paging.rs:59:8
   |
59 |     fn atomic_inc_refcount(refcount_addr: *mut u32) -> u32;
   |        ^^^^^^^^^^^^^^^^^^^

Plan:
- Use atomic_inc_refcount in shared page tracking.
- Call it during fork/COW setup.
- Verify counts are decremented on unmap.

Plan:
- Use atomic_inc_refcount in COW or shared page tracking. Add TODO to use in fork path.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: function `atomic_dec_refcount` is never used
  --> src/paging.rs:60:8
   |
60 |     fn atomic_dec_refcount(refcount_addr: *mut u32) -> u32;
   |        ^^^^^^^^^^^^^^^^^^^

Plan:
- Use atomic_dec_refcount on unmap/free.
- When refcount reaches zero, free the page.
- Add a debug assert for underflow.

Plan:
- Use atomic_dec_refcount in COW or page release. Add TODO to use in unmap/free path.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: function `memory_barrier` is never used
  --> src/paging.rs:63:8
   |
63 |     fn memory_barrier();
   |        ^^^^^^^^^^^^^^

Plan:
- Use memory_barrier after page table modifications.
- Place it before enabling paging or switching contexts.
- Document where ordering is required.

Plan:
- Use memory_barrier in page table update sequences where ordering matters; document call sites.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: function `load_barrier` is never used
  --> src/paging.rs:64:8
   |
64 |     fn load_barrier();
   |        ^^^^^^^^^^^^

Plan:
- Use load_barrier before reading page table entries.
- Call it in page fault handling paths.
- Document the ordering guarantee.

Plan:
- Use load_barrier in page fault handling or mapping reads; document call sites.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: function `store_barrier` is never used
  --> src/paging.rs:65:8
   |
65 |     fn store_barrier();
   |        ^^^^^^^^^^^^^

Plan:
- Use store_barrier after writing PTEs.
- Call it before returning to user mode.
- Document the ordering guarantee.

Plan:
- Use store_barrier after PTE writes to ensure ordering; document call sites.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: associated function `empty` is never used
   --> src/quantum_scheduler.rs:529:14
    |
528 | impl WaitQueue {
    | -------------- associated function in this implementation
529 |     const fn empty() -> Self {
    |              ^^^^^

Plan:
- Use WaitQueue::empty to initialize the wait queue array.
- Replace the current MaybeUninit pattern with array::from_fn.
- Add a test that ensures all queues start in a valid state.

Plan:
- Use WaitQueue::empty to initialize arrays or default values. This is especially useful to replace the current MaybeUninit pattern.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: constant `TIME_SLICE_MS` is never used
  --> src/scheduler.rs:17:7
   |
17 | const TIME_SLICE_MS: u32 = 10;
   |       ^^^^^^^^^^^^^

Plan:
- Use TIME_SLICE_MS to program the PIT frequency.
- Pass the value into the scheduler quantum configuration.
- Expose the time slice in debug output.

Plan:
- Use TIME_SLICE_MS to configure PIT or scheduler quantum; thread it into timer setup.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: constant `SCROLLBACK_MAX` is never used
  --> src/terminal.rs:32:7
   |
32 | const SCROLLBACK_MAX: usize = 1000;
   |       ^^^^^^^^^^^^^^

Plan:
- Use SCROLLBACK_MAX to cap scrollback growth.
- Truncate older lines when the cap is exceeded.
- Add a debug counter for dropped lines.

Plan:
- Use SCROLLBACK_MAX to cap scrollback growth when pushing new lines.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: field `scrollback` is never read
  --> src/terminal.rs:77:5
   |
75 | struct Terminal {
   |        -------- field in this struct
76 |     buffer: [[Cell; WIDTH]; HEIGHT],
77 |     scrollback: Vec<[Cell; WIDTH]>,
   |     ^^^^^^^^^^

Plan:
- Store lines in scrollback when the screen scrolls.
- Update rendering logic to include scrollback when needed.
- Add a method to view scrollback in the console.

Plan:
- Wire scrollback into output path to capture lines when screen scrolls.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: method `push_scrollback` is never used
   --> src/terminal.rs:199:8
    |
87  | impl Terminal {
    | ------------- method in this implementation
...
199 |     fn push_scrollback(&mut self) {
    |        ^^^^^^^^^^^^^^^

Plan:
- Call push_scrollback when a line scrolls off the screen.
- Use SCROLLBACK_MAX to bound stored lines.
- Test scrollback behavior with long output.

Plan:
- Call push_scrollback when output exceeds screen height; integrate with newline/scroll logic.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: the type `[WaitQueue; 64]` does not permit being left uninitialized
  --> src/quantum_scheduler.rs:82:13
   |
82 |             MaybeUninit::uninit().assume_init()
   |             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   |             |
   |             this code causes undefined behavior when executed
   |             help: use `MaybeUninit<T>` instead, and only call `assume_init` after initialization is done
   |
note: integers must be initialized (in this struct field)
  --> src/quantum_scheduler.rs:63:5
   |
63 |     pub addr: usize,               // Address/key for the wait queue (lik...
   |     ^^^^^^^^^^^^^^^
   = note: `#[warn(invalid_value)]` on by default

Plan:
- Initialize the WaitQueue array with array::from_fn(|_| WaitQueue::empty()).
- Remove MaybeUninit::assume_init from this path.
- Add a debug assert that all queues are valid.

Plan:
- Fix UB by initializing the WaitQueue array properly (e.g., array::from_fn(|_| WaitQueue::empty())) or using MaybeUninit::uninit_array and initializing each element before assume_init.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

warning: `oreulia-kernel` (lib) generated 71 warnings (run `cargo fix --lib -p oreulia-kernel` to apply 22 suggestions)

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.

Plan:
- Review this warning and decide whether to wire the item into the active path or explicitly mark it as intentionally unused with a TODO.

Plan:
- Review this warning and identify the intended behavior.
- Integrate the item into the relevant execution path.
- Add a minimal test or log to confirm the behavior.
