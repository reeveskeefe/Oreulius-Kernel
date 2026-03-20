import re
with open("/Users/keefereeves/Desktop/oreulia/kernel/src/temporal/mod.rs", "r") as f:
    text = f.read()

replacement = """fn apply_temporal_payload_to_object(
    path: &str,
    payload: &[u8],
    mode: TemporalRestoreMode,
) -> Result<(), TemporalError> {
    crate::serial_println!("[TEMPORAL_ADAPTER] apply_temporal_payload_to_object: path={:?}", path);
    let adapter = find_object_adapter(path).ok_or_else(|| {
        crate::serial_println!("[TEMPORAL_ADAPTER] apply_temporal_payload_to_object: find_object_adapter returned None");
        TemporalError::AdapterApplyFailed
    })?;
    let _replay_guard = TemporalReplayGuard::new();
    (adapter.apply)(path, payload, mode).map_err(|e| {
        crate::serial_println!("[TEMPORAL_ADAPTER] apply_temporal_payload_to_object: adapter.apply failed");
        TemporalError::AdapterApplyFailed
    })
}"""

search_pattern = r"""fn apply_temporal_payload_to_object\(
    path: &str,
    payload: &\[u8\],
    mode: TemporalRestoreMode,
\) -> Result<\(\), TemporalError> \{
    let adapter = find_object_adapter\(path\)\.ok_or\(TemporalError::AdapterApplyFailed\)\?;
    let _replay_guard = TemporalReplayGuard::new\(\);
    \(adapter\.apply\)\(path, payload, mode\)\.map_err\(\|\_\| TemporalError::AdapterApplyFailed\)
\}"""

text = re.sub(search_pattern, replacement, text)

with open("/Users/keefereeves/Desktop/oreulia/kernel/src/temporal/mod.rs", "w") as f:
    f.write(text)
