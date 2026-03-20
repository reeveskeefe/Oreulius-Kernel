import re
with open("/Users/keefereeves/Desktop/oreulia/kernel/src/temporal/mod.rs", "r") as f:
    text = f.read()

replacement = """fn temporal_apply_vfs_file_payload(
    path: &str,
    payload: &[u8],
    _mode: TemporalRestoreMode,
) -> Result<(), &'static str> {
    crate::serial_println!("[TEMPORAL_VFS_APPLY] path={:?}, payload_len={}", path, payload.len());
    match crate::vfs::temporal_try_apply_backend_payload(path, payload) {
        Ok(true) => {
            crate::serial_println!("[TEMPORAL_VFS_APPLY] temporal_try_apply_backend_payload returned Ok(true)");
            Ok(())
        }
        Ok(false) => {
            crate::serial_println!("[TEMPORAL_VFS_APPLY] temporal_try_apply_backend_payload returned Ok(false), calling write_path_untracked");
            crate::vfs::write_path_untracked(path, payload).map(|_| ()).map_err(|e| {
                crate::serial_println!("[TEMPORAL_VFS_APPLY] write_path_untracked failed");
                "write_path_untracked failed"
            })
        }
        Err(e) => {
            crate::serial_println!("[TEMPORAL_VFS_APPLY] temporal_try_apply_backend_payload failed with error: {:?}", e);
            Err(e)
        }
    }
}"""

search_pattern = r"""fn temporal_apply_vfs_file_payload\(
    path: &str,
    payload: &\[u8\],
    _mode: TemporalRestoreMode,
\) -> Result<\(\), &'static str> \{
    match crate::vfs::temporal_try_apply_backend_payload\(path, payload\) \{
        Ok\(true\) => Ok\(\(\)\),
        Ok\(false\) => crate::vfs::write_path_untracked\(path, payload\)\.map\(\|\_\| \(\)\),
        Err\(e\) => Err\(e\),
    \}
\}"""

text = re.sub(search_pattern, replacement, text)

with open("/Users/keefereeves/Desktop/oreulia/kernel/src/temporal/mod.rs", "w") as f:
    f.write(text)
