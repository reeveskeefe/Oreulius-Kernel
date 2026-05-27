use crate::{hkdf_expand, hkdf_extract};

pub fn run_deterministic_tests() -> Vec<(&'static str, bool, String)> {
    let mut results = Vec::new();

    let salt = b"salt";
    let ikm = b"input key material";
    let info = b"info";

    let prk = hkdf_extract(salt, ikm);
    let out1 = hkdf_expand::<32>(&prk, info);
    let out2 = hkdf_expand::<32>(&prk, info);

    if out1 == out2 {
        results.push(("hkdf_repeatability", true, "OK".to_string()));
    } else {
        results.push((
            "hkdf_repeatability",
            false,
            "mismatch on repeated expand".to_string(),
        ));
    }

    results
}
