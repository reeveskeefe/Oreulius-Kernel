use crate::{hmac_sha256, hmac_sha256_trunc16, HmacSha256};

pub fn run_deterministic_tests() -> Vec<(&'static str, bool, String)> {
    let mut results = Vec::new();

    let key = b"secret key";
    let data = b"important data";

    let a = hmac_sha256(key, data);

    let mut h = HmacSha256::new(key);
    h.update(data);
    let b = h.finalize();

    if a == b {
        results.push(("hmac_consistency", true, "OK".to_string()));
    } else {
        results.push((
            "hmac_consistency",
            false,
            "mismatch between helper and stateful".to_string(),
        ));
    }

    let t = hmac_sha256_trunc16(key, data);
    let mut h2 = HmacSha256::new(key);
    h2.update(data);
    let u = h2.finalize_trunc16();

    if t == u {
        results.push(("hmac_trunc16", true, "OK".to_string()));
    } else {
        results.push(("hmac_trunc16", false, "trunc16 mismatch".to_string()));
    }

    results
}
