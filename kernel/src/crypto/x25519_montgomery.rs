/*!
 * X25519 Montgomery ladder extracted for reuse outside TLS.
 */

type Fe = [u64; 4];

const P: [u64; 4] = [
    0xFFFF_FFFF_FFFF_FFED,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0x7FFF_FFFF_FFFF_FFFF,
];
const A24: u64 = 121_665;

fn fe_from_bytes(b: &[u8; 32]) -> Fe {
    let mut f = [0u64; 4];
    for i in 0..4 {
        let mut v = 0u64;
        for j in 0..8 {
            v |= (b[i * 8 + j] as u64) << (j * 8);
        }
        f[i] = v;
    }
    f
}

fn fe_to_bytes(f: &Fe) -> [u8; 32] {
    let mut b = [0u8; 32];
    for i in 0..4 {
        let v = f[i];
        for j in 0..8 {
            b[i * 8 + j] = (v >> (j * 8)) as u8;
        }
    }
    b
}

fn fe_reduce(a: &Fe) -> Fe {
    let mut ge = true;
    for i in (0..4).rev() {
        if a[i] < P[i] {
            ge = false;
            break;
        }
        if a[i] > P[i] {
            break;
        }
    }
    if !ge {
        return *a;
    }
    let mut r = [0u64; 4];
    let mut borrow = 0i128;
    for i in 0..4 {
        let d = a[i] as i128 - P[i] as i128 + borrow;
        r[i] = d as u64;
        borrow = d >> 64;
    }
    r
}

fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let mut r = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let s = a[i] as u128 + b[i] as u128 + carry;
        r[i] = s as u64;
        carry = s >> 64;
    }
    fe_reduce(&r)
}

fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    let two_p: [u64; 4] = [
        0xFFFF_FFFF_FFFF_FFDA,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFE,
    ];
    let mut tmp = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let s = a[i] as u128 + two_p[i] as u128 + carry;
        tmp[i] = s as u64;
        carry = s >> 64;
    }
    let mut r = [0u64; 4];
    let mut borrow = 0i128;
    for i in 0..4 {
        let d = tmp[i] as i128 - b[i] as i128 + borrow;
        r[i] = d as u64;
        borrow = d >> 64;
    }
    fe_reduce(&r)
}

fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let mut t = [0u128; 8];
    for i in 0..4 {
        for j in 0..4 {
            t[i + j] += a[i] as u128 * b[j] as u128;
        }
    }
    let mut c = [0u64; 8];
    let mut carry = 0u128;
    for i in 0..8 {
        let s = t[i] + carry;
        c[i] = s as u64;
        carry = s >> 64;
    }
    let mut r = [0u64; 4];
    let mut c2 = 0u128;
    for i in 0..4 {
        let s = c[i] as u128 + c[i + 4] as u128 * 38 + c2;
        r[i] = s as u64;
        c2 = s >> 64;
    }
    let mut r2 = [0u64; 4];
    let mut c3 = 0u128;
    for i in 0..4 {
        let s = r[i] as u128 + (if i == 0 { c2 * 38 } else { 0 }) + c3;
        r2[i] = s as u64;
        c3 = s >> 64;
    }
    fe_reduce(&r2)
}

fn fe_sq(a: &Fe) -> Fe {
    fe_mul(a, a)
}

fn pow2k(a: &Fe, k: usize) -> Fe {
    let mut r = *a;
    for _ in 0..k {
        r = fe_sq(&r);
    }
    r
}

fn fe_inv(z: &Fe) -> Fe {
    let z2 = fe_sq(z);
    let z9 = fe_mul(&pow2k(&z2, 2), z);
    let z11 = fe_mul(&z9, &z2);
    let z2_5 = fe_mul(&fe_sq(&z11), &z9);
    let z2_10 = fe_mul(&pow2k(&z2_5, 5), &z2_5);
    let z2_20 = fe_mul(&pow2k(&z2_10, 10), &z2_10);
    let z2_40 = fe_mul(&pow2k(&z2_20, 20), &z2_20);
    let z2_50 = fe_mul(&pow2k(&z2_40, 10), &z2_10);
    let z2_100 = fe_mul(&pow2k(&z2_50, 50), &z2_50);
    let z2_200 = fe_mul(&pow2k(&z2_100, 100), &z2_100);
    let z2_250 = fe_mul(&pow2k(&z2_200, 50), &z2_50);
    fe_mul(&pow2k(&z2_250, 5), &z11)
}

fn cswap(swap: u64, a: &mut Fe, b: &mut Fe) {
    let mask = 0u64.wrapping_sub(swap & 1);
    for i in 0..4 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

pub const BASE_U: [u8; 32] = {
    let mut u = [0u8; 32];
    u[0] = 9;
    u
};

pub fn x25519(k_bytes: &[u8; 32], u_bytes: &[u8; 32]) -> [u8; 32] {
    let mut k = *k_bytes;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    let u = fe_from_bytes(u_bytes);
    let mut r0: Fe = [1, 0, 0, 0];
    let mut r1: Fe = u;
    let mut z0: Fe = [0; 4];
    let mut z1: Fe = [1, 0, 0, 0];
    let mut swap = 0u64;
    for t in (0..255).rev() {
        let k_t = ((k[t / 8] >> (t % 8)) & 1) as u64;
        swap ^= k_t;
        cswap(swap, &mut r0, &mut r1);
        cswap(swap, &mut z0, &mut z1);
        swap = k_t;
        let a = fe_add(&r0, &z0);
        let aa = fe_sq(&a);
        let b = fe_sub(&r0, &z0);
        let bb = fe_sq(&b);
        let e = fe_sub(&aa, &bb);
        let c = fe_add(&r1, &z1);
        let d = fe_sub(&r1, &z1);
        let da = fe_mul(&d, &a);
        let cb = fe_mul(&c, &b);
        r1 = fe_sq(&fe_add(&da, &cb));
        z1 = fe_mul(&u, &fe_sq(&fe_sub(&da, &cb)));
        r0 = fe_mul(&aa, &bb);
        z0 = fe_mul(&e, &fe_add(&aa, &fe_mul(&e, &[A24, 0, 0, 0])));
    }
    cswap(swap, &mut r0, &mut r1);
    cswap(swap, &mut z0, &mut z1);
    fe_to_bytes(&fe_mul(&r0, &fe_inv(&z0)))
}

pub fn x25519_public_key(priv_key: &[u8; 32]) -> [u8; 32] {
    x25519(priv_key, &BASE_U)
}

pub fn x25519_shared_secret(priv_key: &[u8; 32], peer: &[u8; 32]) -> [u8; 32] {
    x25519(priv_key, peer)
}

#[cfg(test)]
mod tests {
    use super::{x25519_public_key, x25519_shared_secret};

    #[test]
    fn x25519_rfc7748_iterated_vector() {
        let alice_secret = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let alice_public_expected = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];
        let bob_secret = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80,
            0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27,
            0xff, 0x88, 0xe0, 0xeb,
        ];
        let bob_public_expected = [
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4,
            0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14,
            0x6f, 0x88, 0x2b, 0x4f,
        ];
        let shared_expected = [
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35,
            0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c,
            0x1e, 0x16, 0x17, 0x42,
        ];

        assert_eq!(x25519_public_key(&alice_secret), alice_public_expected);
        assert_eq!(x25519_public_key(&bob_secret), bob_public_expected);
        assert_eq!(
            x25519_shared_secret(&alice_secret, &bob_public_expected),
            shared_expected
        );
        assert_eq!(
            x25519_shared_secret(&bob_secret, &alice_public_expected),
            shared_expected
        );
    }
}
