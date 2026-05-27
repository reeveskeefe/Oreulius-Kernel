use crate::sha256;

fn to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

pub fn run_deterministic_tests() -> Vec<(&'static str, bool, String)> {
    let mut results = Vec::new();

    // Empty string
    let expected_empty: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];

    let got = sha256(&[]);
    if got == expected_empty {
        results.push(("sha256_empty", true, "OK".to_string()));
    } else {
        results.push(("sha256_empty", false, format!("got {}", to_hex(&got))));
    }

    // "abc"
    let expected_abc: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];

    let got2 = sha256(b"abc");
    if got2 == expected_abc {
        results.push(("sha256_abc", true, "OK".to_string()));
    } else {
        results.push(("sha256_abc", false, format!("got {}", to_hex(&got2))));
    }

    results
}
