use super::hmac::hmac_sha256;

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
        let take = std::cmp::min(32, N - offset);
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
    let ll = std::cmp::min(label.len(), 64);
    info[p] = (prefix.len() + ll) as u8;
    p += 1;
    info[p..p + prefix.len()].copy_from_slice(prefix);
    p += prefix.len();
    info[p..p + ll].copy_from_slice(&label[..ll]);
    p += ll;

    let cl = std::cmp::min(ctx.len(), 64);
    info[p] = cl as u8;
    p += 1;
    info[p..p + cl].copy_from_slice(&ctx[..cl]);
    p += cl;

    hkdf_expand(secret, &info[..p])
}
