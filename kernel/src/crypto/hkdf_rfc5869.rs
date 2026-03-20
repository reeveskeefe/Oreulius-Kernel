/*!
 * RFC 5869 HKDF using the kernel's HMAC-SHA256 primitive.
 */

use crate::crypto::hmac_sha256;

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

pub fn hkdf_expand<const N: usize>(prk: &[u8; 32], info: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    if N == 0 {
        return out;
    }

    let mut t = [0u8; 32];
    let mut t_len = 0usize;
    let mut offset = 0usize;
    let mut counter = 1u8;

    while offset < N {
        let mut msg = [0u8; 32 + 255 + 1];
        let mut msg_len = 0usize;
        if t_len != 0 {
            msg[..t_len].copy_from_slice(&t[..t_len]);
            msg_len += t_len;
        }
        let info_len = info.len().min(255);
        msg[msg_len..msg_len + info_len].copy_from_slice(&info[..info_len]);
        msg_len += info_len;
        msg[msg_len] = counter;
        msg_len += 1;

        t = hmac_sha256(prk, &msg[..msg_len]);
        t_len = 32;
        let take = core::cmp::min(32, N - offset);
        out[offset..offset + take].copy_from_slice(&t[..take]);
        offset += take;
        counter = counter.wrapping_add(1);
    }

    out
}

pub fn hkdf_expand_label_sha256<const N: usize>(
    secret: &[u8; 32],
    label: &[u8],
    ctx: &[u8],
) -> [u8; N] {
    let mut info = [0u8; 300];
    let mut p = 0usize;
    let length = N as u16;
    info[p] = (length >> 8) as u8;
    info[p + 1] = length as u8;
    p += 2;

    let prefix = b"tls13 ";
    let ll = core::cmp::min(label.len(), 64);
    info[p] = (prefix.len() + ll) as u8;
    p += 1;
    info[p..p + prefix.len()].copy_from_slice(prefix);
    p += prefix.len();
    info[p..p + ll].copy_from_slice(&label[..ll]);
    p += ll;

    let cl = core::cmp::min(ctx.len(), 64);
    info[p] = cl as u8;
    p += 1;
    info[p..p + cl].copy_from_slice(&ctx[..cl]);
    p += cl;

    hkdf_expand(secret, &info[..p])
}

#[cfg(test)]
mod tests {
    use super::{hkdf_expand, hkdf_extract};

    #[test]
    fn hkdf_rfc5869_case_1() {
        let ikm = [0x0bu8; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            prk,
            [
                0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
                0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
                0xd7, 0xc2, 0xb3, 0xe5,
            ]
        );
        let okm = hkdf_expand::<42>(&prk, &info);
        assert_eq!(
            okm,
            [
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
            ]
        );
    }
}
