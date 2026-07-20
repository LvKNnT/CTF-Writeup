#![allow(dead_code)]

pub fn xor_bits(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

pub fn int_to_bits(value: u64, bits_len: usize) -> Vec<u8> {
    let mut binary = format!("{value:b}");
    if binary.len() < bits_len {
        let padding = "0".repeat(bits_len - binary.len());
        binary = padding + &binary;
    }
    binary.bytes().map(|b| b - b'0').collect()
}

pub fn bits_to_int(bits: &[u8]) -> u64 {
    bits.iter()
        .fold(0u64, |acc, bit| (acc << 1) | u64::from(*bit & 1))
}

pub fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for shift in (0..8).rev() {
            bits.push((byte >> shift) & 1);
        }
    }
    bits
}

pub fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
    assert!(bits.len() % 8 == 0);
    bits.chunks(8)
        .map(|chunk| chunk.iter().fold(0u8, |acc, bit| (acc << 1) | (*bit & 1)))
        .collect()
}

pub fn add_mod_2_32(bit32: &[u8], key32: &[u8]) -> Vec<u8> {
    let a = bits_to_int(bit32) as u32;
    let b = bits_to_int(key32) as u32;
    int_to_bits(u64::from(a.wrapping_add(b)), 32)
}

pub fn sub_mod_2_32(bit32: &[u8], key32: &[u8]) -> Vec<u8> {
    let a = bits_to_int(bit32) as u32;
    let b = bits_to_int(key32) as u32;
    int_to_bits(u64::from(a.wrapping_sub(b)), 32)
}

pub fn rol11(bits: &[u8]) -> Vec<u8> {
    if bits.len() <= 11 {
        return bits.to_vec();
    }
    bits[11..]
        .iter()
        .chain(bits[..11].iter())
        .copied()
        .collect()
}

pub fn ror11(bits: &[u8]) -> Vec<u8> {
    if bits.len() <= 11 {
        return bits.to_vec();
    }
    bits[bits.len() - 11..]
        .iter()
        .chain(bits[..bits.len() - 11].iter())
        .copied()
        .collect()
}

pub fn feedback_from_seed(seed: &[u8], feedback_index: usize) -> u64 {
    assert_eq!(seed.len(), 2048 / 8);
    assert!(feedback_index <= 2048 - 47);

    let mut value = 0u64;
    for bit in 0..47 {
        let source_bit = feedback_index + bit;
        let byte_idx = seed.len() - 1 - (source_bit / 8);
        let bit_idx = source_bit % 8;
        let b = (seed[byte_idx] >> bit_idx) & 1;
        value |= u64::from(b) << bit;
    }
    (1u64 << 47) | value
}

pub fn hex_to_bytes_like_python(input: &str) -> Result<Vec<u8>, hex::FromHexError> {
    let filtered: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    hex::decode(filtered)
}
