# RecoverMe Writeup

## Summary

Crypto challenge. The 44-byte flag is split into a `PREFIX` and `POSTFIX`, each used as a 22-byte RC4 key to encrypt a fixed known prompt; a "Decrypt" oracle lets the client supply part of that key while the server silently pads the rest with the real secret half, and because the oracle echoes the *full* decryption output rather than just a yes/no match, XOR-differencing two queries at the same input length cancels the fixed ciphertext and isolates a clean RC4-keystream oracle over the unknown secret bytes.

Flag:

```text
HCMUS-CTF{FMS_4TT4ck_15_NoT_u53D_7H15_T1mE!}
```

## Triage

`challenge.py` splits the flag and encrypts a shared known prompt under each half as an RC4 key:

```python
self.n = len(FLAG) // 2
assert self.n == 22
self.PREFIX, self.POSTFIX = FLAG[:self.n], FLAG[self.n:]
self.ct1 = ARC4.new(self.PREFIX, drop = 0).encrypt(prompt)
self.ct2 = ARC4.new(self.POSTFIX, drop = 0).encrypt(prompt)
```

Each of the two rounds exposes a "Decrypt" option that builds the RC4 key from attacker input concatenated with the *real* secret half, then prints the entire decrypted output (not just whether it matches):

```python
def round(self, ct, pt, pre = '', post = ''):
    while True:
        option = self.menu()
        if option == 1:
            inp_key = input('Send my your key in hex (at most 22 bytes): ')
            inp_key = bytes.fromhex(inp_key)
            if len(inp_key) > 22:
                raise LongKey

            key = ''
            if pre:
                key = pre[:len(inp_key)] + inp_key
            elif post:
                key = inp_key + post[len(inp_key):]

            cleartext = ARC4.new(key).decrypt(ct)
            print(cleartext.hex())
```

Round 1 (`post=PREFIX`) builds `key = inp_key + PREFIX[len(inp_key):]` - attacker-controlled bytes up front, auto-filled with the true `PREFIX` suffix. Round 2 (`pre=POSTFIX`) builds `key = POSTFIX[:len(inp_key)] + inp_key` - the true `POSTFIX` prefix up front, attacker-controlled suffix. A "Check flag" option (`option == 2`) only advances the round if the exact half is submitted, so it can't be used as a byte-by-byte oracle - but "Decrypt" always runs and always prints, and it never validates that the attacker actually knows the flag half, only its length.

## Solve Path

A naive approach - try `PREFIX[:i] + candidate_byte` and see if the decrypted output equals `prompt` - needs up to 256 queries per byte (~1700 total across 44 bytes), enough to trip the service's connection time limit. The actual weakness is that the oracle leaks the *full* decryption, not just a match/no-match bit, which enables a differencing attack that needs only ~2 queries per byte.

For a fixed query length `L`, the ciphertext (`ct1` or `ct2`) is a constant, so querying two different attacker inputs `G0`, `G1` at the same `L` and XORing the outputs cancels it out entirely:

```python
def oracle(io, inp_key):
    io.sendline(b"1")
    io.sendline(inp_key.hex().encode())
    io.recvuntil(b"22 bytes): ")
    line = io.recvline().strip()
    return bytes.fromhex(line.decode())
```

```
O(G) = ct XOR KS(key(G))
O(G0) XOR O(G1) = KS(key(G0)) XOR KS(key(G1))
```

The right side depends only on the *keystream* difference between two known-attacker-input keys that share the same unknown secret bytes - a clean oracle with no dependence on the plaintext prompt at all.

### Stage 2 (POSTFIX): front-to-back recovery

Round 2's key is `POSTFIX[:L] + inp_key`, so at each length `L` the newly-added unknown byte is `POSTFIX[L-1]` (everything before it is already known from prior iterations). Brute all 256 candidates for that one byte, predict the keystream difference locally with each candidate, and match against the measured difference:

```python
def recover_postfix(io):
    postfix = b""
    for L in range(1, KEYLEN + 1):
        G0 = b"\x41" * L
        G1 = b"\x42" * L
        O0 = oracle(io, G0)
        O1 = oracle(io, G1)
        n = min(len(O0), len(O1))
        measured = xor(O0[:n], O1[:n])

        matches = []
        for c in range(256):
            cand = postfix + bytes([c])
            pred = xor(rc4_keystream(cand + G0, n), rc4_keystream(cand + G1, n))
            if pred == measured:
                matches.append(c)
        assert len(matches) == 1, f"ambiguous byte at L={L}: {matches}"
        postfix += bytes([matches[0]])
    return postfix
```

22 lengths x 2 queries recovers all of `POSTFIX` with no dependence on the 256^11 brute-force that a direct all-at-once approach (unknown suffix appears all at once at `L=11`, since `key = POSTFIX[:L]+inp_key` only reaches 22 bytes there) would require.

### Stage 1 (PREFIX): back-to-front recovery, plus a free byte

Round 1's key is `inp_key + PREFIX[L:]` - always exactly 22 bytes regardless of `L`, with the *suffix* auto-filled from the secret. Recovering back-to-front means at length `L` the new unknown is `PREFIX[L]`, with the rest of the suffix (`PREFIX[L+1:]`) already known:

```python
def recover_prefix(io):
    known = {}
    for L in range(KEYLEN - 1, 0, -1):
        known_suffix = bytes(known[k] for k in range(L + 1, KEYLEN))
        G0 = b"\x41" * L
        G1 = b"\x42" * L
        O0 = oracle(io, G0)
        O1 = oracle(io, G1)
        n = min(len(O0), len(O1))
        measured = xor(O0[:n], O1[:n])

        matches = []
        for c in range(256):
            suff = bytes([c]) + known_suffix
            pred = xor(rc4_keystream(G0 + suff, n), rc4_keystream(G1 + suff, n))
            if pred == measured:
                matches.append(c)
        assert len(matches) == 1, f"ambiguous PREFIX[{L}]: {matches}"
        known[L] = matches[0]
```

This recovers `PREFIX[1:22]` in ~2 queries per byte, `L = 21` down to `1`. `PREFIX[0]` (the flag-format byte, effectively always known already) costs no extra query at all: with the whole suffix `PREFIX[1:]` known, the `L=1` query's ciphertext relationship can be inverted directly -

```python
    n = len(o0_at_L1)
    ct1 = xor(o0_at_L1, rc4_keystream(g0_at_L1 + prefix_1_, n))
    target_ks = xor(ct1, PROMPT[:n])
    for c in range(256):
        if rc4_keystream(bytes([c]) + prefix_1_, n) == target_ks:
            prefix0 = c
            break
```

- reconstructing `ct1` from a single earlier query, then deriving the required keystream `KS(PREFIX)` from the known `prompt`, and brute-forcing `PREFIX[0]` locally against it with no server round-trip.

This differencing approach is also why a naive "count matching output bytes" probe would show nothing informative: any signal is invisible until the unknown, constant `ct1`/`ct2` term is XORed out between two same-length queries - comparing single outputs to `prompt` directly hides the structure that makes the byte-recovery tractable.

## Exploit

[solve.sage](#Solve) connects to the live service, runs the back-to-front differencing attack to recover `PREFIX` (stage 1), submits it to advance, then runs the front-to-back differencing attack to recover `POSTFIX` (stage 2), submits it, and prints the concatenated flag. Run with:

```
sage solve.sage
```

Key functions/steps:
- `rc4_keystream(key, n)` - local RC4 keystream generator used to predict oracle differences for each candidate byte
- `oracle(io, inp_key)` - sends a "Decrypt" query and returns the raw decrypted hex output
- `recover_prefix(io)` - back-to-front byte recovery of `PREFIX[1:22]` via output-XOR differencing, plus a zero-query recovery of `PREFIX[0]`
- `recover_postfix(io)` - front-to-back byte recovery of `POSTFIX[0:22]` via the same differencing technique
- `submit(io, half)` - sends a "Check flag" query to advance rounds / finish
- `main()` - orchestrates stage 1 -> submit -> stage 2 -> submit -> prints the flag

## Solve

```python=
from pwn import *

# context.log_level = "error"   # we print our own progress; queries are many

HOST = ???
PORT = ???

PROMPT = b"You could decrypt this but the flag is in the key. LoL"
KEYLEN = 22


def rc4_keystream(key, n):
    S = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % klen]) % 256
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for _ in range(n):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) % 256])
    return bytes(out)


def xor(a, b):
    return bytes(x ^^ y for x, y in zip(a, b))


def oracle(io, inp_key):
    # option 1 (Decrypt): send the menu choice + key PROACTIVELY (the server
    # reads its inputs line by line, so we don't need to first wait for the
    # "Your option:" / key prompts -- we only anchor on the key prompt to
    # know where the reply begins). recvuntil("22 bytes): ") skips past any
    # pending banner/menu text automatically.
    io.sendline(b"1")
    io.sendline(inp_key.hex().encode())
    io.recvuntil(b"22 bytes): ")
    line = io.recvline().strip()
    return bytes.fromhex(line.decode())


def submit(io, half):
    # option 2 (Check flag): send choice + flag proactively, no prompt wait.
    io.sendline(b"2")
    io.sendline(half.hex().encode())


def recover_prefix(io):
    # server round 1: key = G + PREFIX[L:]  (G = our L-byte input)
    known = {}                      # index -> PREFIX[index], for indices 1..21
    o0_at_L1 = g0_at_L1 = None
    for L in range(KEYLEN - 1, 0, -1):          # L = 21 down to 1
        known_suffix = bytes(known[k] for k in range(L + 1, KEYLEN))  # PREFIX[L+1:]
        G0 = b"\x41" * L
        G1 = b"\x42" * L
        O0 = oracle(io, G0)
        O1 = oracle(io, G1)
        n = min(len(O0), len(O1))
        measured = xor(O0[:n], O1[:n])

        matches = []
        for c in range(256):
            suff = bytes([c]) + known_suffix                     # PREFIX[L:] candidate
            pred = xor(rc4_keystream(G0 + suff, n), rc4_keystream(G1 + suff, n))
            if pred == measured:
                matches.append(c)
        assert len(matches) == 1, f"ambiguous PREFIX[{L}]: {matches}"
        known[L] = matches[0]
        if L == 1:
            o0_at_L1, g0_at_L1 = O0, G0
        print(f"[stage1] PREFIX[{L}] = {bytes([matches[0]])!r}")

    prefix_1_ = bytes(known[k] for k in range(1, KEYLEN))        # PREFIX[1:22]

    # recover PREFIX[0] locally, no extra query
    n = len(o0_at_L1)
    ct1 = xor(o0_at_L1, rc4_keystream(g0_at_L1 + prefix_1_, n))  # G0 was [0x41]*1
    target_ks = xor(ct1, PROMPT[:n])                            # KS(PREFIX) must equal this
    prefix0 = None
    for c in range(256):
        if rc4_keystream(bytes([c]) + prefix_1_, n) == target_ks:
            prefix0 = c
            break
    assert prefix0 is not None, "PREFIX[0] not found"

    prefix = bytes([prefix0]) + prefix_1_
    print(f"[stage1] full PREFIX = {prefix!r}")
    return prefix


def recover_postfix(io):
    postfix = b""
    for L in range(1, KEYLEN + 1):
        G0 = b"\x41" * L
        G1 = b"\x42" * L
        O0 = oracle(io, G0)
        O1 = oracle(io, G1)
        n = min(len(O0), len(O1))
        measured = xor(O0[:n], O1[:n])

        matches = []
        for c in range(256):
            cand = postfix + bytes([c])          # candidate POSTFIX[:L]
            pred = xor(rc4_keystream(cand + G0, n), rc4_keystream(cand + G1, n))
            if pred == measured:
                matches.append(c)
        assert len(matches) == 1, f"ambiguous byte at L={L}: {matches}"
        postfix += bytes([matches[0]])
        print(f"[stage2] POSTFIX[:{L}] = {postfix}")
    return postfix


def main():
    io = remote(HOST, PORT)

    prefix = recover_prefix(io)
    print("[*] PREFIX =", prefix)

    submit(io, prefix)                            # advance to stage 2
    try:
        io.recvuntil(b"welcome to stage 2", timeout=10)
    except EOFError:
        print("[!] server closed after prefix submit; response:",
              io.recvrepeat(2))
        return
    print("[*] stage 1 cleared")

    postfix = recover_postfix(io)
    print("[*] POSTFIX =", postfix)

    submit(io, postfix)                           # win
    tail = io.recvrepeat(3)
    print("[*] server:", tail.decode(errors="replace"))
    print("FLAG =", (prefix + postfix).decode(errors="replace"))


if __name__ == "__main__":
    main()

```

## Verification

```text
[stage1] PREFIX[21] = b'1'
[stage1] PREFIX[20] = b'_'
[stage1] PREFIX[19] = b'k'
[stage1] PREFIX[18] = b'c'
[stage1] PREFIX[17] = b'4'
[stage1] PREFIX[16] = b'T'
[stage1] PREFIX[15] = b'T'
[stage1] PREFIX[14] = b'4'
[stage1] PREFIX[13] = b'_'
[stage1] PREFIX[12] = b'S'
[stage1] PREFIX[11] = b'M'
[stage1] PREFIX[10] = b'F'
[stage1] PREFIX[9] = b'{'
[stage1] PREFIX[8] = b'F'
[stage1] PREFIX[7] = b'T'
[stage1] PREFIX[6] = b'C'
[stage1] PREFIX[5] = b'-'
[stage1] PREFIX[4] = b'S'
[stage1] PREFIX[3] = b'U'
[stage1] PREFIX[2] = b'M'
[stage1] PREFIX[1] = b'C'
[stage1] full PREFIX = b'HCMUS-CTF{FMS_4TT4ck_1'
[*] PREFIX = b'HCMUS-CTF{FMS_4TT4ck_1'
[*] stage 1 cleared
[stage2] POSTFIX[:1] = b'5'
[stage2] POSTFIX[:2] = b'5_'
[stage2] POSTFIX[:3] = b'5_N'
[stage2] POSTFIX[:4] = b'5_No'
[stage2] POSTFIX[:5] = b'5_NoT'
[stage2] POSTFIX[:6] = b'5_NoT_'
[stage2] POSTFIX[:7] = b'5_NoT_u'
[stage2] POSTFIX[:8] = b'5_NoT_u5'
[stage2] POSTFIX[:9] = b'5_NoT_u53'
[stage2] POSTFIX[:10] = b'5_NoT_u53D'
[stage2] POSTFIX[:11] = b'5_NoT_u53D_'
[stage2] POSTFIX[:12] = b'5_NoT_u53D_7'
[stage2] POSTFIX[:13] = b'5_NoT_u53D_7H'
[stage2] POSTFIX[:14] = b'5_NoT_u53D_7H1'
[stage2] POSTFIX[:15] = b'5_NoT_u53D_7H15'
[stage2] POSTFIX[:16] = b'5_NoT_u53D_7H15_'
[stage2] POSTFIX[:17] = b'5_NoT_u53D_7H15_T'
[stage2] POSTFIX[:18] = b'5_NoT_u53D_7H15_T1'
[stage2] POSTFIX[:19] = b'5_NoT_u53D_7H15_T1m'
[stage2] POSTFIX[:20] = b'5_NoT_u53D_7H15_T1mE'
[stage2] POSTFIX[:21] = b'5_NoT_u53D_7H15_T1mE!'
[stage2] POSTFIX[:22] = b'5_NoT_u53D_7H15_T1mE!}'
[*] POSTFIX = b'5_NoT_u53D_7H15_T1mE!}'
[*] server: 1. Decrypt
2. Check flag
3. Exit
Your option: Your flag to check in hex: Congratulation, you found the flag.

FLAG = HCMUS-CTF{FMS_4TT4ck_15_NoT_u53D_7H15_T1mE!}
```

## Flag

```text
HCMUS-CTF{FMS_4TT4ck_15_NoT_u53D_7H15_T1mE!}
```

## Lessons Learned

- An oracle that echoes a full decryption/output (rather than just accept/reject) leaks far more than intended - XOR two same-shaped queries to cancel any fixed unknown ciphertext term and isolate a clean function of only the attacker-controlled and target-secret inputs.
- When a server auto-completes a partial attacker-supplied key/input with a secret value, recover it incrementally one new byte at a time (whichever end grows the unknown region), turning an exponential brute force into linear queries x 256 candidates.
- Order of recovery matters: work from the position that isolates exactly one new unknown byte per query (front-to-back or back-to-front depending on which side the secret auto-fill lands on), not from a fixed starting point that reveals many unknown bytes simultaneously.
- Look for "free" recoveries: once enough secret material is known, some remaining unknowns can be derived by locally re-deriving an already-queried output instead of spending another round-trip - useful when a service enforces query/time limits.
- A stream cipher key that's reused character-for-character as message content (flag bytes as an RC4 key) means any keystream-recovery primitive against that key directly yields plaintext-equivalent secret bytes.
