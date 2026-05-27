use super::sha256::{sha256, Sha256};

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k0 = [0u8; 64];

    if key.len() > 64 {
        k0[..32].copy_from_slice(&sha256(key));
    } else {
        k0[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k0[i];
        opad[i] ^= k0[i];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}

pub fn hmac_sha256_trunc16(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mac = hmac_sha256(key, data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&mac[..16]);
    out
}

pub struct HmacSha256 {
    inner: Sha256,
    opad: [u8; 64],
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        let mut k0 = [0u8; 64];
        if key.len() > 64 {
            k0[..32].copy_from_slice(&sha256(key));
        } else {
            k0[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..64 {
            ipad[i] ^= k0[i];
            opad[i] ^= k0[i];
        }

        let mut inner = Sha256::new();
        inner.update(&ipad);

        Self { inner, opad }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        let inner_hash = self.inner.finalize();
        let mut outer = Sha256::new();
        outer.update(&self.opad);
        outer.update(&inner_hash);
        outer.finalize()
    }

    pub fn finalize_trunc16(self) -> [u8; 16] {
        let mac = self.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&mac[..16]);
        out
    }
}
