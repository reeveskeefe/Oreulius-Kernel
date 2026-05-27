use crate::ghash;

fn to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

pub fn run_deterministic_tests() -> Vec<(&'static str, bool, String)> {
    let mut results = Vec::new();

    let h = [0x66u8; 16];
    let aad = b"aad-data";
    let ct = b"ciphertext-bytes";

    let g1 = ghash(&h, aad, ct);
    let g2 = ghash(&h, aad, ct);

    if g1 == g2 {
        results.push(("ghash_repeatability", true, "OK".to_string()));
    } else {
        results.push((
            "ghash_repeatability",
            false,
            format!("g1={} g2={}", to_hex(&g1), to_hex(&g2)),
        ));
    }

    results
}
