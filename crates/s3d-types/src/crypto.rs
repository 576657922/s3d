use hmac::{Hmac, Mac};
use sha2::Sha256;

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const RCON: [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

#[inline]
fn sub_word(w: u32) -> u32 {
    let b = w.to_be_bytes();
    u32::from_be_bytes([
        SBOX[b[0] as usize],
        SBOX[b[1] as usize],
        SBOX[b[2] as usize],
        SBOX[b[3] as usize],
    ])
}

#[inline]
fn xtime(x: u8) -> u8 {
    let shifted = x << 1;
    if (x & 0x80) != 0 {
        shifted ^ 0x1b
    } else {
        shifted
    }
}

/// Expanded FIPS-197 AES-256 key schedule (14 rounds = 60 32-bit words).
#[derive(Clone)]
pub struct Aes256Cipher {
    rk: [u32; 60],
}

impl Aes256Cipher {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut rk = [0u32; 60];
        for i in 0..8 {
            rk[i] = u32::from_be_bytes([
                key[4 * i],
                key[4 * i + 1],
                key[4 * i + 2],
                key[4 * i + 3],
            ]);
        }
        for i in 8..60 {
            let mut temp = rk[i - 1];
            if i % 8 == 0 {
                temp = sub_word(temp.rotate_left(8)) ^ ((RCON[i / 8 - 1] as u32) << 24);
            } else if i % 8 == 4 {
                temp = sub_word(temp);
            }
            rk[i] = rk[i - 8] ^ temp;
        }
        Self { rk }
    }

    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut s = *block;
        self.add_round_key(&mut s, 0);

        for round in 1..14 {
            for b in &mut s {
                *b = SBOX[*b as usize];
            }
            shift_rows(&mut s);
            mix_columns(&mut s);
            self.add_round_key(&mut s, round);
        }

        for b in &mut s {
            *b = SBOX[*b as usize];
        }
        shift_rows(&mut s);
        self.add_round_key(&mut s, 14);
        s
    }

    #[inline]
    fn add_round_key(&self, s: &mut [u8; 16], round: usize) {
        for col in 0..4 {
            let kb = self.rk[round * 4 + col].to_be_bytes();
            s[col * 4] ^= kb[0];
            s[col * 4 + 1] ^= kb[1];
            s[col * 4 + 2] ^= kb[2];
            s[col * 4 + 3] ^= kb[3];
        }
    }
}

#[inline]
fn shift_rows(s: &mut [u8; 16]) {
    // Row 1: shift left by 1
    let t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t;

    // Row 2: shift left by 2
    s.swap(2, 10);
    s.swap(6, 14);

    // Row 3: shift left by 3
    let t = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = t;
}

#[inline]
fn mix_columns(s: &mut [u8; 16]) {
    for col in 0..4 {
        let idx = col * 4;
        let a0 = s[idx];
        let a1 = s[idx + 1];
        let a2 = s[idx + 2];
        let a3 = s[idx + 3];
        let t = a0 ^ a1 ^ a2 ^ a3;
        s[idx] = a0 ^ t ^ xtime(a0 ^ a1);
        s[idx + 1] = a1 ^ t ^ xtime(a1 ^ a2);
        s[idx + 2] = a2 ^ t ^ xtime(a2 ^ a3);
        s[idx + 3] = a3 ^ t ^ xtime(a3 ^ a0);
    }
}

/// Apply NIST SP 800-38A big-endian 128-bit AES-256-CTR stream cipher in-place at `byte_offset`.
pub fn aes256_ctr_xor(key: &[u8; 32], iv: &[u8; 16], byte_offset: u64, data: &mut [u8]) {
    if data.is_empty() {
        return;
    }
    let cipher = Aes256Cipher::new(key);
    aes256_ctr_xor_with_cipher(&cipher, iv, byte_offset, data);
}

/// Same as [`aes256_ctr_xor`] using a pre-expanded [`Aes256Cipher`].
pub fn aes256_ctr_xor_with_cipher(
    cipher: &Aes256Cipher,
    iv: &[u8; 16],
    byte_offset: u64,
    data: &mut [u8],
) {
    if data.is_empty() {
        return;
    }
    let base_ctr = u128::from_be_bytes(*iv);
    let mut block_idx = byte_offset / 16;
    let mut in_block = (byte_offset % 16) as usize;
    let mut pos = 0usize;

    while pos < data.len() {
        let ctr_bytes = base_ctr.wrapping_add(u128::from(block_idx)).to_be_bytes();
        let ks = cipher.encrypt_block(&ctr_bytes);
        let take = (16 - in_block).min(data.len() - pos);
        for i in 0..take {
            data[pos + i] ^= ks[in_block + i];
        }
        pos += take;
        block_idx += 1;
        in_block = 0;
    }
}

/// Derive a deterministic 32-byte SSE-S3 master key from a 16-byte storage instance UUID.
pub fn derive_sse_s3_master_key(instance_uuid: &[u8; 16]) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(b"s3d-sse-s3-master-key-v1")
        .expect("HMAC accepts arbitrary key length");
    mac.update(instance_uuid);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// Constant-time 16-byte digest equality check.
pub fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        for i in (0..bytes.len()).step_by(2) {
            let hi = (bytes[i] as char).to_digit(16).unwrap() as u8;
            let lo = (bytes[i + 1] as char).to_digit(16).unwrap() as u8;
            out.push((hi << 4) | lo);
        }
        out
    }

    #[test]
    fn nist_fips_197_appendix_c3_aes256() {
        let key: [u8; 32] = unhex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .try_into()
        .unwrap();
        let pt: [u8; 16] = unhex("00112233445566778899aabbccddeeff")
            .try_into()
            .unwrap();
        let expected: [u8; 16] = unhex("8ea2b7ca516745bfeafc49904b496089")
            .try_into()
            .unwrap();

        let cipher = Aes256Cipher::new(&key);
        assert_eq!(cipher.encrypt_block(&pt), expected);
    }

    #[test]
    fn nist_sp800_38a_f55_aes256_ctr_and_seekable_slices() {
        let key: [u8; 32] = unhex(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        )
        .try_into()
        .unwrap();
        let iv: [u8; 16] = unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
            .try_into()
            .unwrap();
        let pt = unhex(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710",
        ));
        let expected_ct = unhex(concat!(
            "601ec313775789a5b7a7f504bbf3d228",
            "f443e3ca4d62b59aca84e990cacaf5c5",
            "2b0930daa23de94ce87017ba2d84988d",
            "dfc9c58db67aada613c2dd08457941a6",
        ));

        let mut buf = pt.clone();
        aes256_ctr_xor(&key, &iv, 0, &mut buf);
        assert_eq!(buf, expected_ct);

        // Verify arbitrary unaligned Range decryption
        let cipher = Aes256Cipher::new(&key);
        for start in 0..pt.len() {
            for end in start..=pt.len() {
                let mut slice = expected_ct[start..end].to_vec();
                aes256_ctr_xor_with_cipher(&cipher, &iv, start as u64, &mut slice);
                assert_eq!(slice, &pt[start..end]);
            }
        }
    }
}
