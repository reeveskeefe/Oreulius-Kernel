/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


/*!
 * Ed25519 signature verification on Edwards25519.
 *
 * This implementation is `no_std` friendly and self-contained. It prioritizes
 * correctness and integration simplicity over performance.
 */

use crate::crypto::{ct_eq, Sha512};

type Fe = [u64; 5];

const MASK51: u64 = (1u64 << 51) - 1;
const BASEPOINT_COMPRESSED: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];
const SCALAR_L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];
const INV_EXP: [u8; 32] = [
    0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];
const SQRT_EXP: [u8; 32] = [
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f,
];
const SQRT_M1_EXP: [u8; 32] = [
    0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f,
];

#[derive(Copy, Clone)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

#[inline]
fn load8(bytes: &[u8]) -> u64 {
    let mut out = 0u64;
    let mut i = 0usize;
    while i < 8 {
        out |= (bytes[i] as u64) << (8 * i);
        i += 1;
    }
    out
}

#[inline]
fn fe_zero() -> Fe {
    [0, 0, 0, 0, 0]
}

#[inline]
fn fe_one() -> Fe {
    [1, 0, 0, 0, 0]
}

#[inline]
fn fe_from_u64(x: u64) -> Fe {
    [x, 0, 0, 0, 0]
}

fn fe_carry(h: &Fe) -> Fe {
    let mut r = *h;

    let c0 = r[0] >> 51;
    r[0] &= MASK51;
    r[1] += c0;

    let c1 = r[1] >> 51;
    r[1] &= MASK51;
    r[2] += c1;

    let c2 = r[2] >> 51;
    r[2] &= MASK51;
    r[3] += c2;

    let c3 = r[3] >> 51;
    r[3] &= MASK51;
    r[4] += c3;

    let c4 = r[4] >> 51;
    r[4] &= MASK51;
    r[0] += c4 * 19;

    let c0 = r[0] >> 51;
    r[0] &= MASK51;
    r[1] += c0;

    r
}

fn fe_add(a: &Fe, b: &Fe) -> Fe {
    fe_carry(&[
        a[0] + b[0],
        a[1] + b[1],
        a[2] + b[2],
        a[3] + b[3],
        a[4] + b[4],
    ])
}

fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    let two_p0 = ((1u64 << 51) - 19) * 2;
    let two_pn = ((1u64 << 51) - 1) * 2;
    fe_carry(&[
        a[0] + two_p0 - b[0],
        a[1] + two_pn - b[1],
        a[2] + two_pn - b[2],
        a[3] + two_pn - b[3],
        a[4] + two_pn - b[4],
    ])
}

fn fe_neg(a: &Fe) -> Fe {
    fe_sub(&fe_zero(), a)
}

fn fe_mul_small(a: &Fe, c: u64) -> Fe {
    fe_carry(&[a[0] * c, a[1] * c, a[2] * c, a[3] * c, a[4] * c])
}

fn fe_mul(f: &Fe, g: &Fe) -> Fe {
    let f0 = f[0] as u128;
    let f1 = f[1] as u128;
    let f2 = f[2] as u128;
    let f3 = f[3] as u128;
    let f4 = f[4] as u128;

    let g0 = g[0] as u128;
    let g1 = g[1] as u128;
    let g2 = g[2] as u128;
    let g3 = g[3] as u128;
    let g4 = g[4] as u128;

    let g1_19 = g1 * 19;
    let g2_19 = g2 * 19;
    let g3_19 = g3 * 19;
    let g4_19 = g4 * 19;

    let mut h0 = f0 * g0 + f1 * g4_19 + f2 * g3_19 + f3 * g2_19 + f4 * g1_19;
    let mut h1 = f0 * g1 + f1 * g0 + f2 * g4_19 + f3 * g3_19 + f4 * g2_19;
    let mut h2 = f0 * g2 + f1 * g1 + f2 * g0 + f3 * g4_19 + f4 * g3_19;
    let mut h3 = f0 * g3 + f1 * g2 + f2 * g1 + f3 * g0 + f4 * g4_19;
    let mut h4 = f0 * g4 + f1 * g3 + f2 * g2 + f3 * g1 + f4 * g0;

    let c0 = h0 >> 51;
    h0 &= MASK51 as u128;
    h1 += c0;
    let c1 = h1 >> 51;
    h1 &= MASK51 as u128;
    h2 += c1;
    let c2 = h2 >> 51;
    h2 &= MASK51 as u128;
    h3 += c2;
    let c3 = h3 >> 51;
    h3 &= MASK51 as u128;
    h4 += c3;
    let c4 = h4 >> 51;
    h4 &= MASK51 as u128;
    h0 += c4 * 19;
    let c0 = h0 >> 51;
    h0 &= MASK51 as u128;
    h1 += c0;

    [
        h0 as u64,
        (h1 & MASK51 as u128) as u64,
        (h2 & MASK51 as u128) as u64,
        (h3 & MASK51 as u128) as u64,
        (h4 & MASK51 as u128) as u64,
    ]
}

fn fe_sq(f: &Fe) -> Fe {
    fe_mul(f, f)
}

fn fe_pow(base: &Fe, exp_le: &[u8]) -> Fe {
    let mut result = fe_one();
    let mut i = exp_le.len() * 8;
    while i > 0 {
        i -= 1;
        result = fe_sq(&result);
        if ((exp_le[i / 8] >> (i % 8)) & 1) != 0 {
            result = fe_mul(&result, base);
        }
    }
    result
}

fn fe_inv(x: &Fe) -> Fe {
    fe_pow(x, &INV_EXP)
}

fn fe_sqrt_m1() -> Fe {
    fe_pow(&fe_from_u64(2), &SQRT_M1_EXP)
}

fn fe_sqrt_ratio(u: &Fe, v: &Fe) -> Option<Fe> {
    let v_inv = fe_inv(v);
    let x2 = fe_mul(u, &v_inv);
    let mut x = fe_pow(&x2, &SQRT_EXP);
    if !fe_eq(&fe_sq(&x), &x2) {
        x = fe_mul(&x, &fe_sqrt_m1());
        if !fe_eq(&fe_sq(&x), &x2) {
            return None;
        }
    }
    Some(x)
}

fn fe_from_bytes(bytes: &[u8; 32]) -> Option<Fe> {
    let mut b = *bytes;
    b[31] &= 0x7f;
    let h0 = load8(&b[0..8]) & MASK51;
    let h1 = (load8(&b[6..14]) >> 3) & MASK51;
    let h2 = (load8(&b[12..20]) >> 6) & MASK51;
    let h3 = (load8(&b[19..27]) >> 1) & MASK51;
    let h4 = (load8(&b[24..32]) >> 12) & MASK51;
    let fe = fe_carry(&[h0, h1, h2, h3, h4]);
    let canon = fe_to_bytes(&fe);
    if !ct_eq(&canon[..31], &b[..31]) || canon[31] != b[31] {
        return None;
    }
    Some(fe)
}

fn fe_to_bytes(h: &Fe) -> [u8; 32] {
    let mut r = fe_carry(h);
    let q = (r[0] + 19) >> 51;
    r[0] += 19 * q;
    r = fe_carry(&r);

    let s0 = (r[0] as u128) | ((r[1] as u128) << 51);
    let s1 = ((r[1] >> 13) as u128) | ((r[2] as u128) << 38);
    let s2 = ((r[2] >> 26) as u128) | ((r[3] as u128) << 25);
    let s3 = ((r[3] >> 39) as u128) | ((r[4] as u128) << 12);

    let words = [s0 as u64, s1 as u64, s2 as u64, s3 as u64];
    let mut out = [0u8; 32];
    let mut i = 0usize;
    while i < 4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&words[i].to_le_bytes());
        i += 1;
    }
    out[31] &= 0x7f;
    out
}

fn fe_is_negative(x: &Fe) -> bool {
    (fe_to_bytes(x)[0] & 1) != 0
}

fn fe_eq(a: &Fe, b: &Fe) -> bool {
    ct_eq(&fe_to_bytes(a), &fe_to_bytes(b))
}

fn edwards_d() -> Fe {
    let minus_121665 = fe_neg(&fe_from_u64(121_665));
    let inv_121666 = fe_inv(&fe_from_u64(121_666));
    fe_mul(&minus_121665, &inv_121666)
}

fn point_identity() -> Point {
    Point {
        x: fe_zero(),
        y: fe_one(),
        z: fe_one(),
        t: fe_zero(),
    }
}

fn point_add(p: &Point, q: &Point) -> Point {
    let y1_minus_x1 = fe_sub(&p.y, &p.x);
    let y2_minus_x2 = fe_sub(&q.y, &q.x);
    let a = fe_mul(&y1_minus_x1, &y2_minus_x2);

    let y1_plus_x1 = fe_add(&p.y, &p.x);
    let y2_plus_x2 = fe_add(&q.y, &q.x);
    let b = fe_mul(&y1_plus_x1, &y2_plus_x2);

    let d2 = fe_mul_small(&edwards_d(), 2);
    let c = fe_mul(&fe_mul(&p.t, &q.t), &d2);
    let d = fe_mul_small(&fe_mul(&p.z, &q.z), 2);
    let e = fe_sub(&b, &a);
    let f = fe_sub(&d, &c);
    let g = fe_add(&d, &c);
    let h = fe_add(&b, &a);

    Point {
        x: fe_mul(&e, &f),
        y: fe_mul(&g, &h),
        z: fe_mul(&f, &g),
        t: fe_mul(&e, &h),
    }
}

fn point_double(p: &Point) -> Point {
    let a = fe_sq(&p.x);
    let b = fe_sq(&p.y);
    let c = fe_mul_small(&fe_sq(&p.z), 2);
    let d = fe_neg(&a);
    let e = fe_sub(&fe_sub(&fe_sq(&fe_add(&p.x, &p.y)), &a), &b);
    let g = fe_add(&d, &b);
    let f = fe_sub(&g, &c);
    let h = fe_sub(&d, &b);

    Point {
        x: fe_mul(&e, &f),
        y: fe_mul(&g, &h),
        z: fe_mul(&f, &g),
        t: fe_mul(&e, &h),
    }
}

fn point_mul_by_cofactor(p: &Point) -> Point {
    let mut out = *p;
    let mut i = 0;
    while i < 3 {
        out = point_double(&out);
        i += 1;
    }
    out
}

fn point_compress(p: &Point) -> [u8; 32] {
    let z_inv = fe_inv(&p.z);
    let x = fe_mul(&p.x, &z_inv);
    let y = fe_mul(&p.y, &z_inv);
    let mut out = fe_to_bytes(&y);
    if fe_is_negative(&x) {
        out[31] |= 0x80;
    }
    out
}

fn point_is_identity(p: &Point) -> bool {
    let enc = point_compress(p);
    enc[0] == 1 && enc[1..].iter().all(|&b| b == 0)
}

fn point_decompress(bytes: &[u8; 32]) -> Option<Point> {
    let sign = (bytes[31] >> 7) != 0;
    let y = fe_from_bytes(bytes)?;
    let y2 = fe_sq(&y);
    let u = fe_sub(&y2, &fe_one());
    let v = fe_add(&fe_mul(&edwards_d(), &y2), &fe_one());
    let mut x = fe_sqrt_ratio(&u, &v)?;
    if fe_is_negative(&x) != sign {
        x = fe_neg(&x);
    }

    let p = Point {
        x,
        y,
        z: fe_one(),
        t: fe_mul(&x, &y),
    };

    if !ct_eq(&point_compress(&p), bytes) {
        return None;
    }
    Some(p)
}

fn scalar_is_canonical(s: &[u8; 32]) -> bool {
    let mut i = 32usize;
    while i > 0 {
        i -= 1;
        if s[i] < SCALAR_L[i] {
            return true;
        }
        if s[i] > SCALAR_L[i] {
            return false;
        }
    }
    false
}

fn scalar_mul(p: &Point, scalar_le: &[u8]) -> Point {
    let mut acc = point_identity();
    let mut base = *p;
    let mut i = 0usize;
    while i < scalar_le.len() * 8 {
        if ((scalar_le[i / 8] >> (i % 8)) & 1) != 0 {
            acc = point_add(&acc, &base);
        }
        base = point_double(&base);
        i += 1;
    }
    acc
}

fn basepoint() -> Point {
    point_decompress(&BASEPOINT_COMPRESSED).unwrap()
}

pub fn ed25519_verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let a = match point_decompress(public_key) {
        Some(p) => p,
        None => return false,
    };
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let r = match point_decompress(&r_bytes) {
        Some(p) => p,
        None => return false,
    };

    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);
    if !scalar_is_canonical(&s_bytes) {
        return false;
    }

    if point_is_identity(&point_mul_by_cofactor(&a))
        || point_is_identity(&point_mul_by_cofactor(&r))
    {
        return false;
    }

    let mut h = Sha512::new();
    h.update(&signature[..32]);
    h.update(public_key);
    h.update(message);
    let k = h.finalize();

    let sb = scalar_mul(&basepoint(), &s_bytes);
    let ka = scalar_mul(&a, &k);
    let rhs = point_add(&r, &ka);

    let lhs8 = point_mul_by_cofactor(&sb);
    let rhs8 = point_mul_by_cofactor(&rhs);

    ct_eq(&point_compress(&lhs8), &point_compress(&rhs8))
}

#[cfg(test)]
mod tests {
    use super::ed25519_verify;

    #[test]
    fn ed25519_rfc8032_vector_empty_message() {
        let public_key = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let signature = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];
        assert!(ed25519_verify(&public_key, b"", &signature));
    }

    #[test]
    fn ed25519_rejects_tampered_message() {
        let public_key = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let signature = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];
        assert!(!ed25519_verify(&public_key, b"x", &signature));
    }
}
