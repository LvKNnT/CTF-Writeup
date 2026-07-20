#![allow(dead_code)]

use crate::utils::{
    add_mod_2_32, bits_to_bytes, bits_to_int, bytes_to_bits, int_to_bits, rol11, xor_bits,
};

const SIZE: usize = 23738715 / 2;
const MASK48: u64 = (1u64 << 48) - 1;
const CRC_POLY: u32 = 0xEDB88320;

pub const SBOX: [[u8; 16]; 8] = [
    [
        0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1,
    ],
    [
        0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF,
    ],
    [
        0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0,
    ],
    [
        0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB,
    ],
    [
        0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC,
    ],
    [
        0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0,
    ],
    [
        0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7,
    ],
    [
        0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2,
    ],
];

pub const ISBOX: [[u8; 16]; 8] = [
    [12, 15, 3, 13, 1, 5, 2, 11, 9, 7, 4, 6, 0, 10, 8, 14],
    [14, 8, 2, 3, 10, 6, 0, 11, 1, 4, 5, 12, 7, 13, 9, 15],
    [15, 9, 4, 1, 11, 2, 14, 10, 3, 13, 6, 0, 12, 7, 8, 5],
    [9, 3, 2, 12, 5, 11, 7, 8, 1, 14, 10, 15, 0, 4, 13, 6],
    [8, 5, 14, 10, 13, 2, 6, 0, 4, 9, 3, 12, 15, 7, 11, 1],
    [15, 11, 5, 13, 12, 0, 3, 9, 10, 4, 7, 8, 6, 1, 14, 2],
    [11, 6, 2, 14, 9, 3, 4, 15, 0, 5, 13, 10, 7, 12, 1, 8],
    [4, 0, 15, 7, 8, 5, 11, 1, 6, 12, 10, 14, 13, 3, 2, 9],
];

fn substitute_u32(value: u32, table: &[[u8; 16]; 8]) -> u32 {
    let mut out = 0u32;
    for i in 0..8 {
        let shift = 28 - 4 * i;
        let nibble = ((value >> shift) & 0xF) as usize;
        out |= u32::from(table[7 - i][nibble]) << shift;
    }
    out
}

pub fn substitution(bit32: &[u8]) -> Vec<u8> {
    let value = bits_to_int(bit32) as u32;
    int_to_bits(u64::from(substitute_u32(value, &SBOX)), 32)
}

pub fn isub(bit32: &[u8]) -> Vec<u8> {
    let value = bits_to_int(bit32) as u32;
    int_to_bits(u64::from(substitute_u32(value, &ISBOX)), 32)
}

pub fn f(key: &[u8], state: &[u8], swap: bool) -> Vec<u8> {
    assert_eq!(key.len(), 4);
    assert_eq!(state.len(), 8);

    let key_bits = bytes_to_bits(key);
    let state_hi = bytes_to_bits(&state[..4]);
    let mut state_lo = bytes_to_bits(&state[4..]);
    let mut out_state = state_hi.clone();
    out_state.extend_from_slice(&state_lo);

    state_lo = add_mod_2_32(&state_lo, &key_bits);
    state_lo = substitution(&state_lo);
    state_lo = rol11(&state_lo);
    state_lo = xor_bits(&state_lo, &state_hi);

    if swap {
        out_state[..32].copy_from_slice(&state_lo);
    } else {
        let old_lo = out_state[32..64].to_vec();
        out_state[..32].copy_from_slice(&old_lo);
        out_state[32..64].copy_from_slice(&state_lo);
    }
    bits_to_bytes(&out_state)
}

fn parity(value: u64) -> u32 {
    value.count_ones() & 1
}

struct Lfsr {
    poly: u64,
    state: u64,
}

impl Lfsr {
    fn new(poly: u64, seed: u64) -> Self {
        Self {
            poly: poly & MASK48,
            state: seed & MASK48,
        }
    }

    fn bit(&mut self) -> u32 {
        assert!(self.state >> 48 == 0);
        let out = ((self.state >> 47) & 1) as u32;
        let newbit = parity(self.state & self.poly);
        self.state = ((self.state << 1) | u64::from(newbit)) & MASK48;
        out
    }
}

fn crc_append_bit(crc: u32, bit: u32) -> u32 {
    let crc = crc ^ bit;
    (crc >> 1) ^ (0u32.wrapping_sub(crc & 1) & CRC_POLY)
}

fn rk(lfsr: &mut Lfsr) -> u32 {
    let mut crc = 0xffffffffu32;
    for _ in 0..SIZE {
        crc = crc_append_bit(crc, lfsr.bit());
    }
    crc ^ 0xffffffffu32
}

pub fn expand_key(key: &[u8], feedback: u64) -> [u32; 32] {
    assert_eq!(key.len(), 6);
    assert!(feedback >= (1u64 << 47));
    assert!(feedback < (1u64 << 48));

    let mut seed = 0u64;
    for (i, byte) in key.iter().enumerate() {
        seed |= u64::from(*byte) << (8 * i);
    }

    let mut lfsr = Lfsr::new(feedback, seed);
    let mut round_keys = [0u32; 32];
    for i in 0..16 {
        round_keys[2 * i] = rk(&mut lfsr);
        lfsr.bit();
        round_keys[2 * i + 1] = rk(&mut lfsr);
    }
    round_keys
}

#[derive(Clone)]
pub struct Ghost {
    round_keys: [u32; 32],
}

impl Ghost {
    pub fn new(key: &[u8], feedback: u64) -> Self {
        Self {
            round_keys: expand_key(key, feedback),
        }
    }

    pub fn from_round_keys(round_keys: &[u32]) -> Self {
        assert_eq!(round_keys.len(), 32);
        let mut keys = [0u32; 32];
        keys.copy_from_slice(round_keys);
        Self { round_keys: keys }
    }

    fn round_function(&self, hi: u32, lo: u32, round_n: usize, is_enc: bool) -> (u32, u32) {
        let state_lo = lo.wrapping_add(self.round_keys[round_n]);
        let state_lo = substitute_u32(state_lo, &SBOX);
        let state_lo = state_lo.rotate_left(11);
        let state_lo = state_lo ^ hi;

        if (is_enc && round_n == 31) || (!is_enc && round_n == 0) {
            (state_lo, lo)
        } else {
            (lo, state_lo)
        }
    }

    fn encrypt_block(&self, block: &[u8]) -> [u8; 8] {
        let mut hi = u32::from_be_bytes(block[..4].try_into().unwrap());
        let mut lo = u32::from_be_bytes(block[4..8].try_into().unwrap());
        for round in 0..32 {
            (hi, lo) = self.round_function(hi, lo, round, true);
        }

        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&hi.to_be_bytes());
        out[4..].copy_from_slice(&lo.to_be_bytes());
        out
    }

    fn decrypt_block(&self, block: &[u8]) -> [u8; 8] {
        let mut hi = u32::from_be_bytes(block[..4].try_into().unwrap());
        let mut lo = u32::from_be_bytes(block[4..8].try_into().unwrap());
        for round in (0..32).rev() {
            (hi, lo) = self.round_function(hi, lo, round, false);
        }

        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&hi.to_be_bytes());
        out[4..].copy_from_slice(&lo.to_be_bytes());
        out
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        assert!(plaintext.len() % 8 == 0);
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        for block in plaintext.chunks(8) {
            ciphertext.extend_from_slice(&self.encrypt_block(block));
        }
        ciphertext
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        assert!(ciphertext.len() % 8 == 0);
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        for block in ciphertext.chunks(8) {
            plaintext.extend_from_slice(&self.decrypt_block(block));
        }
        plaintext
    }
}
