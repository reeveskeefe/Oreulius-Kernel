use x25519_dalek::x25519 as dalek_x25519;

pub const BASE_U: [u8; 32] = {
    let mut u = [0u8; 32];
    u[0] = 9;
    u
};

pub fn x25519(k_bytes: &[u8; 32], u_bytes: &[u8; 32]) -> [u8; 32] {
    dalek_x25519(*k_bytes, *u_bytes)
}

pub fn x25519_public_key(priv_key: &[u8; 32]) -> [u8; 32] {
    dalek_x25519(*priv_key, BASE_U)
}

pub fn x25519_shared_secret(priv_key: &[u8; 32], peer: &[u8; 32]) -> [u8; 32] {
    dalek_x25519(*priv_key, *peer)
}
