import re
with open("/Users/keefereeves/Desktop/oreulia/kernel/src/execution/wasm.rs", "r") as f:
    text = f.read()

replacement = """        let mut result_code = -1i32;
        let mut encoded = [0u8; TEMPORAL_ROLLBACK_BYTES];
        let mut encoded_len = 0usize;

        crate::serial_println!("[TEMPORAL_ROLLBACK] Start: target={:?}, version_id={}", path_bytes, version_id);

        if let Ok(path) = core::str::from_utf8(&path_bytes) {
            crate::serial_println!("[TEMPORAL_ROLLBACK] Valid UTF-8: {:?}", path);
            if let Ok(key) = fs::FileKey::new(path) {
                crate::serial_println!("[TEMPORAL_ROLLBACK] Valid FileKey: {:?}", key);
                crate::serial_println!("[TEMPORAL_ROLLBACK] Cap Rights: {:?}", fs_cap.rights);
                if fs_cap.rights.has(fs::FilesystemRights::WRITE) && fs_cap.can_access(&key) {
                    crate::serial_println!("[TEMPORAL_ROLLBACK] Write capability checks passed. Calling temporal::rollback_path");
                    match crate::temporal::rollback_path(path, version_id) {
                        Ok(rollback) => {
                            crate::serial_println!("[TEMPORAL_ROLLBACK] Rollback successful");
                            encoded = Self::encode_temporal_rollback(&rollback);
                            self.memory.write(out_ptr, &encoded)?;
                            encoded_len = TEMPORAL_ROLLBACK_BYTES;
                            result_code = 0;
                        }
                        Err(e) => {
                            crate::serial_println!("[TEMPORAL_ROLLBACK] Rollback failed with error: {:?}", e);
                        }
                    }
                } else {
                    crate::serial_println!("[TEMPORAL_ROLLBACK] Write capability or access check failed. Rights: {:?}, Can Access: {}", fs_cap.rights, fs_cap.can_access(&key));
                }
            } else {
                crate::serial_println!("[TEMPORAL_ROLLBACK] Invalid FileKey");
            }
        } else {
            crate::serial_println!("[TEMPORAL_ROLLBACK] Invalid UTF-8");
        }

        self.stack.push(Value::I32(result_code))?;"""

search_pattern = r"""        let mut result_code = -1i32;
        let mut encoded = \[0u8; TEMPORAL_ROLLBACK_BYTES\];
        let mut encoded_len = 0usize;

        if let Ok\(path\) = core::str::from_utf8\(&path_bytes\) \{
            if let Ok\(key\) = fs::FileKey::new\(path\) \{
                if fs_cap\.rights\.has\(fs::FilesystemRights::WRITE\) && fs_cap\.can_access\(&key\) \{
                    if let Ok\(rollback\) = crate::temporal::rollback_path\(path, version_id\) \{
                        encoded = Self::encode_temporal_rollback\(&rollback\);
                        self\.memory\.write\(out_ptr, &encoded\)\?;
                        encoded_len = TEMPORAL_ROLLBACK_BYTES;
                        result_code = 0;
                    \}
                \}
            \}
        \}

        self\.stack\.push\(Value::I32\(result_code\)\)\?;"""

text = re.sub(search_pattern, replacement, text)

with open("/Users/keefereeves/Desktop/oreulia/kernel/src/execution/wasm.rs", "w") as f:
    f.write(text)
