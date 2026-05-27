use crate::{x25519_public_key, x25519_shared_secret};

pub fn run_deterministic_tests() -> Vec<(&'static str, bool, String)> {
    let mut results = Vec::new();

    let priv1 = [0x77u8; 32];
    let priv2 = [0x88u8; 32];

    let pub1 = x25519_public_key(&priv1);
    let pub2 = x25519_public_key(&priv2);

    let s1 = x25519_shared_secret(&priv1, &pub2);
    let s2 = x25519_shared_secret(&priv2, &pub1);

    if s1 == s2 {
        results.push(("x25519_shared_secret_agreement", true, "OK".to_string()));
    } else {
        results.push((
            "x25519_shared_secret_agreement",
            false,
            "shared secrets differ".to_string(),
        ));
    }

    results
}
