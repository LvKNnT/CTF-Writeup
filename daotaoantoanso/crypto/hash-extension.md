# Hash Extension Writeup

## Summary

The server hashes `username + ":" + flag` and gives the client that digest (`H1`), then challenges the client to produce `SHA256(pad(message_1) + salt)` without ever revealing the flag. Because the server's own padding function always pads `message_1` out to exactly one 64-byte SHA-256 block, this is a textbook SHA-256 length-extension setup: the digest `H1` alone gives the internal compression-function state needed to resume hashing and append `salt` plus fresh padding, with no knowledge of the flag's content required.

Flag:

```text
HCMUS-CTF{H4sh_L3n9th_4ttatck_2add0ba87a95ef}
```

## Triage

`Server.py` builds `message_1` from an attacker-controlled username and the secret flag, hands over its digest, then demands the digest of a second message built by padding `message_1` and appending a random salt:

```python
self.flag = self.get_flag()
salt = ''.join(random.choices(string.printable, k=8))

self.send(f"Flag length: {len(self.flag)}\n")
self.send(f"Salt: {salt}\n")
username = self.receive("Tell me your name:\n").decode()
if (5 <= len(username) <= 15):
    message_1 = ''.join((username, ":", self.flag)).encode()
    self.send(f"Message 1 hexdigest: {hashlib.sha256(message_1).hexdigest()}\n")

    message_2 = self._pad_message(message_1) + salt.encode()
    user_input = self.receive("Send hexdigest of message 2.\n").decode()
    if (user_input == hashlib.sha256(message_2).hexdigest()):
        ...
        self.send(self.flag + "\n")
```

`_pad_message` is not a generic padding helper - it always emits exactly `64 - len(message)` bytes total (a fixed one-block pad), quoting SHA-256's own RFC 4634 padding scheme in a comment:

```python
def _pad_message(self, message):
    # https://www.rfc-editor.org/rfc/rfc4634#page-6
    return b''.join((message, b'\x80', b'\x00' * (55 - len(message)), struct.pack('>LL', 8*len(message) >> 32, 8*len(message) & 0xffffffff)))
```

This only produces SHA-256's *real* standard padding when `len(message) <= 55` - the server tells the client the flag length directly and lets the client pick its own username length (5-15 chars), so `len(message_1)` is fully known and controllable up front. The server also leaks `H1 = SHA256(message_1)` directly before asking for `SHA256(message_2)`, which is exactly the digest a length-extension attack needs as its starting internal state.

## Solve Path

`message_2 = message_1 || pad(message_1) || salt`, and `pad(message_1)` is SHA-256's own block-padding for `message_1`. That means `message_2` has precisely the shape SHA-256's length-extension weakness targets: `H1` already encodes the internal 8-word state after processing `message_1`'s (padded) one block, so the compression function can be resumed from that state and fed `salt` plus SHA-256's padding for the *new* total length, without ever knowing `message_1`'s actual bytes.

Choosing the minimum allowed username length (5 chars) keeps `len(message_1) = len(username) + 1 + len(flag)` as small as possible, maximizing the chance it stays `<= 55` bytes so the server's fixed one-block padding assumption holds:

```python
username = b"aaaaa"                     # minimum allowed length (5)
orig_len = len(username) + 1 + flag_len  # len("username:flag")
if orig_len > 55:
    print(f"!! message_1 length {orig_len} > 55; the server's own "
          f"padding formula breaks down here, attack won't line up.")
```

The forgery itself reimplements SHA-256 compression by hand, seeding the internal state directly from `H1`'s bytes instead of the usual fixed IV:

```python
def sha256_length_extend(orig_digest_hex, orig_len, extra):
    h = [int(x) for x in struct.unpack(">8L", bytes.fromhex(orig_digest_hex))]

    processed_len = int(orig_len) + len(sha256_pad(orig_len))  # == 64 here
    new_total_len = processed_len + len(extra)
    to_process = extra + sha256_pad(new_total_len)

    for i in range(0, len(to_process), 64):
        h = sha256_compress(h, to_process[i:i + 64])

    return "".join(f"{x:08x}" for x in h)
```

`to_process` is `salt` followed by SHA-256's padding computed for the *combined* processed length (`orig_len` padded up to 64, plus `len(salt)`) - exactly what real SHA-256 would hash as the continuation of `message_1`'s (invisible) already-processed block. Feeding that through the same round function SHA-256 itself uses (`sha256_compress`, a manual reimplementation of the standard compression function with the real round constants `K`) reproduces the digest the server expects for `message_2`, with the flag's content never needed.

## Exploit

[solve.sage](#Solve) connects to the remote service, reads the announced flag length and salt, sends a fixed 5-character username, receives `H1`, computes the forged length-extension digest locally, and sends it back to receive the flag.

Run:

```bash
sage solve.sage
```

Key steps:

- `rrot(x, n)`: 32-bit right-rotate, a SHA-256 primitive.
- `sha256_pad(message_len)`: reproduces SHA-256's standard message padding for a given already-known length.
- `sha256_compress(h, chunk)`: one full 64-round SHA-256 compression-function pass over a 64-byte block, given an 8-word state `h`.
- `sha256_length_extend(orig_digest_hex, orig_len, extra)`: the actual length-extension forgery - seeds `h` from the leaked digest bytes instead of SHA-256's IV, builds the correct continuation bytes (`extra` + fresh padding for the new total length), and re-derives the resulting digest.
- `main()`: drives the network protocol - parses flag length and salt, sends the minimum-length username, reads `H1`, calls `sha256_length_extend`, and sends the forged digest back.

## Solve
```python=
import struct
from pwn import *

context.log_level = "error"

HOST = "vm.daotao.antoanso.org"
PORT = 32786

MASK = int(0xffffffff)

K = tuple(int(x) for x in (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
))


def rrot(x, n):
    n = int(n)
    return ((x >> n) | (x << (32 - n))) & MASK


def sha256_pad(message_len):
    message_len = int(message_len)
    ml_bits = message_len * 8
    pad_len = (56 - (message_len + 1) % 64) % 64
    return b"\x80" + b"\x00" * pad_len + struct.pack(">Q", ml_bits)


def sha256_compress(h, chunk):
    w = [int(x) for x in struct.unpack(">16L", chunk)] + [0] * 48
    for i in range(16, 64):
        s0 = rrot(w[i - 15], 7) ^^ rrot(w[i - 15], 18) ^^ (w[i - 15] >> 3)
        s1 = rrot(w[i - 2], 17) ^^ rrot(w[i - 2], 19) ^^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK

    a, b, c, d, e, f, g, hh = h

    for i in range(64):
        S1 = rrot(e, 6) ^^ rrot(e, 11) ^^ rrot(e, 25)
        ch = (e & f) ^^ ((e ^^ MASK) & g)
        temp1 = (hh + S1 + ch + K[i] + w[i]) & MASK
        S0 = rrot(a, 2) ^^ rrot(a, 13) ^^ rrot(a, 22)
        maj = (a & b) ^^ (a & c) ^^ (b & c)
        temp2 = (S0 + maj) & MASK

        hh, g, f = g, f, e
        e = (d + temp1) & MASK
        d, c, b = c, b, a
        a = (temp1 + temp2) & MASK

    return [
        (h[0] + a) & MASK, (h[1] + b) & MASK, (h[2] + c) & MASK, (h[3] + d) & MASK,
        (h[4] + e) & MASK, (h[5] + f) & MASK, (h[6] + g) & MASK, (h[7] + hh) & MASK,
    ]


def sha256_length_extend(orig_digest_hex, orig_len, extra):
    h = [int(x) for x in struct.unpack(">8L", bytes.fromhex(orig_digest_hex))]

    processed_len = int(orig_len) + len(sha256_pad(orig_len))  # == 64 here
    new_total_len = processed_len + len(extra)
    to_process = extra + sha256_pad(new_total_len)

    for i in range(0, len(to_process), 64):
        h = sha256_compress(h, to_process[i:i + 64])

    return "".join(f"{x:08x}" for x in h)


def main():
    io = remote(HOST, PORT)

    io.recvuntil(b"Flag length: ")
    flag_len = int(io.recvline().strip())
    print("flag length =", flag_len)

    io.recvuntil(b"Salt: ")
    salt = io.recvn(8)
    print("salt =", salt)

    io.recvuntil(b"name:\n")

    username = b"aaaaa"                     # minimum allowed length (5)
    orig_len = len(username) + 1 + flag_len  # len("username:flag")
    if orig_len > 55:
        print(f"!! message_1 length {orig_len} > 55; the server's own "
              f"padding formula breaks down here, attack won't line up.")

    io.sendline(username)

    io.recvuntil(b"Message 1 hexdigest: ")
    h1 = io.recvline().strip().decode()
    print("H1 =", h1)

    forged = sha256_length_extend(h1, orig_len, salt)
    print("forged H2 =", forged)

    io.recvuntil(b"message 2.\n")
    io.sendline(forged.encode())

    print(io.recvall(timeout=5).decode(errors="replace"))


if __name__ == "__main__":
    main()

```

## Verification

```text
flag length = 45
salt = b'JLO</V\\%'
H1 = ab61147aa672be642fd4c4ccb7fb2279031d32e69bb7b91cc4e9acef80c370a3
forged H2 = 92ce8dec62a52594fc7abc8df99020da4eb4d5709f83db3b8514308f89b0911b
Genius! You can know the message 2 hexdigest even if you don't know the flag.
Here is your flag.
HCMUS-CTF{H4sh_L3n9th_4ttatck_2add0ba87a95ef}
```

## Flag

```text
HCMUS-CTF{H4sh_L3n9th_4ttatck_2add0ba87a95ef}
```

## Lessons Learned

- Merkle-Damgard hashes (SHA-256, SHA-1, MD5) leak their entire internal state as the digest - anyone holding `H(secret || known_suffix)` can resume hashing from that state and append attacker-chosen data, without ever knowing `secret`.
- A length-extension forgery only works when the attacker can predict (or force) the exact padding boundary - controlling or knowing every length that feeds into the padding calculation (here: username length choice + announced flag length) is what makes the attack line up.
- A "custom" padding function that happens to always emit standard hash padding for messages under a fixed size is functionally identical to the real hash's own padding, and inherits the same length-extension weakness.
- The fix for this class of bug is a construction that isn't vulnerable to state leakage extension (HMAC, or a hash with a finalization step like SHA-3), not a home-grown padding tweak.
- When a service hands you a raw digest of `secret || known_data` and then asks for the digest of `pad(that) || more_known_data`, treat it as a length-extension prompt before looking for anything more exotic.
