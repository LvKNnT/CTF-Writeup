use std::env;
use std::fs::File;
use std::io::{self, BufRead, Read, Write};

const BLOCK_BITS: usize = 64;
const NIBBLE_BITS: usize = 4;
const NIBBLES: usize = BLOCK_BITS / NIBBLE_BITS;
const DEFAULT_ROUNDS: i32 = 12;
const BLOCK_BYTES: usize = 8;

const PERM: [usize; 64] = [
    5, 44, 34, 62, 13, 29, 9, 59, 47, 23, 43, 39, 18, 35, 51, 21, 2, 48, 45, 7, 54, 46, 30, 10, 3,
    12, 42, 1, 11, 37, 19, 0, 55, 60, 32, 38, 27, 49, 20, 58, 15, 36, 53, 56, 31, 52, 6, 40, 14,
    28, 26, 24, 63, 61, 16, 33, 41, 4, 17, 25, 22, 8, 50, 57,
];

type SBox = [u8; 16];
type SBoxes = [SBox; NIBBLES];

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn bytes_from_hex(hex: &str) -> Option<Vec<u8>> {
    let bytes = hex.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn bytes_to_hex(data: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for &b in data {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

fn load_u64_le(b: &[u8]) -> u64 {
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&b[..8]);
    u64::from_le_bytes(arr)
}

fn store_u64_le(v: u64, out: &mut [u8]) {
    out[..8].copy_from_slice(&v.to_le_bytes());
}

fn sha256_hex(input: &[u8]) -> String {
    bytes_to_hex(&sha256(input))
}

fn sboxes_from_key(key: &[u8]) -> SBoxes {
    let hashed_key = sha256_hex(key);
    let h = hashed_key.as_bytes();
    let mut base_sboxes = [[0u8; 16]; NIBBLES / 4];

    for idx in 0..(NIBBLES / 4) {
        let mut sbox = [0u8; 16];
        for (i, slot) in sbox.iter_mut().enumerate() {
            *slot = i as u8;
        }

        let mut i = 4 * idx;
        while i < 4 * idx + 16 {
            let a = hex_nibble(h[i]).expect("sha256 hex only contains valid hex") as usize;
            let b = hex_nibble(h[i + 1]).expect("sha256 hex only contains valid hex") as usize;
            sbox.swap(a, b);
            i += 2;
        }
        base_sboxes[idx] = sbox;
    }

    let mut sboxes = [[0u8; 16]; NIBBLES];
    for i in 0..NIBBLES {
        sboxes[i] = base_sboxes[i % (NIBBLES / 4)];
    }
    sboxes
}

fn inverse_sboxes_from_sboxes(sboxes: &SBoxes) -> SBoxes {
    let mut inv = [[0u8; 16]; NIBBLES];
    for i in 0..NIBBLES {
        let mut s = [0u8; 16];
        for x in 0..16 {
            s[sboxes[i][x] as usize] = x as u8;
        }
        inv[i] = s;
    }
    inv
}

fn sbox_layer(state: u64, sboxes: &SBoxes) -> u64 {
    let mut out = 0u64;
    for i in 0..NIBBLES {
        let nibble = ((state >> (i * NIBBLE_BITS)) & 0xF) as usize;
        out |= ((sboxes[i][nibble] & 0xF) as u64) << (i * NIBBLE_BITS);
    }
    out
}

fn inverse_sbox_layer(state: u64, inverse_sboxes: &SBoxes) -> u64 {
    let mut out = 0u64;
    for i in 0..NIBBLES {
        let nibble = ((state >> (i * NIBBLE_BITS)) & 0xF) as usize;
        out |= ((inverse_sboxes[i][nibble] & 0xF) as u64) << (i * NIBBLE_BITS);
    }
    out
}

fn permute_bits(state: u64) -> u64 {
    let mut out = 0u64;
    for (i, &dst) in PERM.iter().enumerate() {
        let bit = (state >> i) & 1;
        out |= bit << dst;
    }
    out
}

fn inverse_permute_bits(state: u64) -> u64 {
    let mut out = 0u64;
    for (i, &src) in PERM.iter().enumerate() {
        let bit = (state >> src) & 1;
        out |= bit << i;
    }
    out
}

fn encrypt_block(block: u64, rounds: i32, sboxes: &SBoxes) -> u64 {
    let mut state = block;
    for _ in 0..(rounds - 1) {
        state = sbox_layer(state, sboxes);
        state = permute_bits(state);
    }
    sbox_layer(state, sboxes)
}

fn decrypt_block(block: u64, rounds: i32, inverse_sboxes: &SBoxes) -> u64 {
    let mut state = inverse_sbox_layer(block, inverse_sboxes);
    for _ in 0..(rounds - 1) {
        state = inverse_permute_bits(state);
        state = inverse_sbox_layer(state, inverse_sboxes);
    }
    state
}

fn encrypt_block_bytes(pt: &[u8], rounds: i32, sboxes: &SBoxes) -> Option<Vec<u8>> {
    if pt.len() % BLOCK_BYTES != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(pt.len());
    for chunk in pt.chunks_exact(BLOCK_BYTES) {
        let value = load_u64_le(chunk);
        let enc = encrypt_block(value, rounds, sboxes);
        let mut block = [0u8; BLOCK_BYTES];
        store_u64_le(enc, &mut block);
        out.extend_from_slice(&block);
    }
    Some(out)
}

fn decrypt_block_bytes(ct: &[u8], rounds: i32, inverse_sboxes: &SBoxes) -> Option<Vec<u8>> {
    if ct.len() % BLOCK_BYTES != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(ct.len());
    for chunk in ct.chunks_exact(BLOCK_BYTES) {
        let value = load_u64_le(chunk);
        let dec = decrypt_block(value, rounds, inverse_sboxes);
        let mut block = [0u8; BLOCK_BYTES];
        store_u64_le(dec, &mut block);
        out.extend_from_slice(&block);
    }
    Some(out)
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    if let Ok(mut urandom) = File::open("/dev/urandom") {
        if urandom.read_exact(&mut out).is_ok() {
            return out;
        }
    }

    let mut x = 1u64;
    for b in &mut out {
        x = x.wrapping_mul(1103515245).wrapping_add(12345);
        *b = ((x >> 16) & 0xff) as u8;
    }
    out
}

fn rounds_from_env() -> i32 {
    match env::var("ROUNDS") {
        Ok(s) if !s.is_empty() => match s.parse::<i64>() {
            Ok(v) if (1..=1000).contains(&v) => v as i32,
            _ => DEFAULT_ROUNDS,
        },
        _ => DEFAULT_ROUNDS,
    }
}

fn print_banner() {
    print!(concat!(
        "\x1b[1;3;95m\n",
        "\n",
        "      ██╗  ██╗ ██████╗███╗   ███╗██╗   ██╗███████╗\n",
        "      ██║  ██║██╔════╝████╗ ████║██║   ██║██╔════╝\n",
        "      ███████║██║     ██╔████╔██║██║   ██║███████╗\n",
        "      ██╔══██║██║     ██║╚██╔╝██║██║   ██║╚════██║\n",
        "      ██║  ██║╚██████╗██║ ╚═╝ ██║╚██████╔╝███████║\n",
        "      ╚═╝  ╚═╝ ╚═════╝╚═╝     ╚═╝ ╚═════╝ ╚══════╝\n",
        "\n",
        "                  ██████╗████████╗███████╗\n",
        "                 ██╔════╝╚══██╔══╝██╔════╝\n",
        "                 ██║        ██║   █████╗\n",
        "                 ██║        ██║   ██╔══╝\n",
        "                 ╚██████╗   ██║   ██║\n",
        "                  ╚═════╝   ╚═╝   ╚═╝\n",
        "\n",
        "                   ▸  HCMUS CTF 2026  ◂\n",
        "\x1b[0m\n",
    ));
}

fn main() {
    print_banner();

    let key = random_bytes(8);
    let rounds = rounds_from_env();
    let env_name = String::from_utf8(vec![0x46, 0x4c, 0x41, 0x47]).expect("valid env name");
    let secret = env::var(env_name).unwrap_or_else(|_| "redacted".to_string());

    let sboxes = sboxes_from_key(&key);
    let inverse_sboxes = inverse_sboxes_from_sboxes(&sboxes);

    println!("Working with {} rounds.", rounds);

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    loop {
        print!("> ");
        io::stdout().flush().unwrap();

        let inp = match lines.next() {
            Some(Ok(line)) => line,
            _ => break,
        };
        if inp.is_empty() {
            break;
        }

        let mode = inp.as_bytes()[0] as char;
        let payload = &inp[1..];
        let data = match bytes_from_hex(payload) {
            Some(v) => v,
            None => break,
        };

        let out = match mode {
            'E' => match encrypt_block_bytes(&data, rounds, &sboxes) {
                Some(v) => v,
                None => break,
            },
            'D' => match decrypt_block_bytes(&data, rounds, &inverse_sboxes) {
                Some(v) => v,
                None => break,
            },
            _ => break,
        };
        println!("{}", bytes_to_hex(&out));
    }

    for _ in 0..100 {
        let challenge = random_bytes(BLOCK_BYTES);
        println!("Challenge: {}", bytes_to_hex(&challenge));
        print!("Response: ");
        io::stdout().flush().unwrap();

        let line = match lines.next() {
            Some(Ok(line)) => line,
            _ => return,
        };
        let response = match bytes_from_hex(&line) {
            Some(v) => v,
            None => return,
        };

        let expected = match encrypt_block_bytes(&challenge, rounds, &sboxes) {
            Some(v) => v,
            None => return,
        };
        if response != expected {
            println!("Wrong response!");
            return;
        }
    }

    println!("Congratulations! Here is the f{}: {}", "lag", secret);
}

fn sha256(input: &[u8]) -> [u8; 32] {
    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let bit_len = (input.len() as u64) * 8;
    let mut msg = input.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut h = H0;
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}
