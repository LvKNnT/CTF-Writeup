# RSB Writeup

## Summary

The server exposes an RSA menu with encrypt, decrypt, and "get encrypted flag" options, where decryption is done "faster" via CRT. The core vulnerability is a copy-paste bug in the CRT-decrypt implementation: the mod-`q` half of the computation is corrupted, which is exactly the fault-injection precondition of the classic Boneh-DeMillo-Lipton CRT-RSA attack - a single decrypt query on a chosen ciphertext factors the modulus.

Flag:

```text
HCMUS-CTF{fault-attack}
```

## Triage

`rsb.py` sets up a standard RSA keypair and offers a menu (`encrypt`, `decrypt`, `get encrypted flag`), but its CRT-based decrypt has a copy-paste bug in the `m_q` accumulation loop:

```python
def decrypt(c: int) -> int:
    # Compute c^d mod p
    m_p = 1
    a = c
    k = d
    while k > 0:
        if k % 2 == 1:
            m_p = m_p * a % p
        a = a * a % p
        k = k // 2

    # Compute c^d mod q
    m_q = 1
    a = c
    k = d
    while k > 0:
        if k % 2 == 1:
            m_q = m_p * a % q     # <-- BUG: should be m_q * a % q
        a = a * a % q
        k = k // 2

    return crt([m_p, m_q], [p, q])
```

`m_q = m_p * a % q` reuses `m_p` (the mod-`p` accumulator) instead of `m_q` on every squaring step, so the returned CRT-combined value `M` satisfies `M ≡ c^d (mod p)` correctly, but `M mod q` is garbage that doesn't actually depend on a valid computation of `c^d mod q`. The `encrypt` function itself is a correct square-and-multiply mod `N`, and the menu also exposes a "get encrypted flag" option that runs the flag through the (correct) `encrypt`, not the buggy `decrypt`, so the real flag ciphertext is trustworthy once `N` and `d` are recovered.

## Solve Path

Because the buggy `decrypt` only decrypts correctly modulo `p`, feeding it any chosen ciphertext `c` and calling the result `M` gives:

```text
M ≡ c^d ≡ c (mod p)      (since ed ≡ 1 mod phi, correct mod-p leg)
M ≡ <garbage>  (mod q)    (wrong leg, doesn't depend on real c^d mod q)
```

so `M^e - c ≡ 0 (mod p)` but generically `M^e - c ≢ 0 (mod q)`. That means `gcd(M^e - c mod N, N)` yields `p` (or a nontrivial factor) directly - the textbook Boneh-DeMillo-Lipton CRT-RSA fault attack, except here the "fault" is a permanent code bug rather than an induced hardware glitch, so it fires on every query.

The solve script drives the menu, requesting decryption of small chosen ciphertexts until the gcd is nontrivial:

```python
p = None
for c in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
    goto_menu(io)
    io.sendline(b"3")                  # Decrypt
    io.recvuntil(b"Ciphertext:")
    io.sendline(str(c).encode())
    io.recvuntil(b"Plaintext:")
    m = int(io.recvline())

    diff = (pow(m, e, N) - c) % N
    g = gcd(diff, N)
    if 1 < g < N:
        p = g
        print(f"factored N with c={c}: p =", p)
        break
```

Once `p` is recovered, the rest is standard RSA key reconstruction:

```python
q = N // p
phi = (p - 1) * (q - 1)
d = inverse_mod(e, phi)
```

The script then requests the *real* encrypted flag through the correct encrypt path (menu option 1, "Get encrypted flag") rather than ever passing it through the buggy `decrypt`, and finishes the decryption itself with the recovered `d`:

```python
goto_menu(io)
io.sendline(b"1")                      # Get encrypted flag
c_flag = int(io.recvline())

m_flag = power_mod(Integer(c_flag), Integer(d), Integer(N))
flag = int(m_flag).to_bytes((int(m_flag).bit_length() + 7) // 8, "big")
```

## Exploit

The solve script is [solve.sage](#Solve). It connects to the remote, parses `N` from the banner, loops over small chosen plaintexts `c ∈ {2,3,5,7,...}` requesting the buggy decrypt on each, tests `gcd(pow(m,e,N) - c, N)` for a nontrivial factor to recover `p`, derives `q`, `phi`, and `d`, then fetches the correctly-encrypted flag and decrypts it locally.

Run:

```bash
sage solve.sage
```

Key steps:

- `goto_menu`: syncs the I/O stream back to the menu prompt between requests, tolerant of `\r\n` line-ending quirks.
- decrypt-oracle loop over `c ∈ {2,3,5,...,29}`: exploits the CRT fault to leak `p` via `gcd(pow(m,e,N) - c, N)`.
- `q = N // p`, `phi`, `inverse_mod(e, phi)`: standard RSA private-key reconstruction once one factor is known.
- final decrypt of `c_flag` obtained from the *correct* encrypt path, never routed through the buggy decrypt.

## Verification

```bash
[+] Opening connection to vm.daotao.antoanso.org on port 32782: Done
[DEBUG] Received 0x194 bytes:
    b'Public key: 175892894619439237483623969548585379816783903857441536821865000648391559389629720262561073903671301335589415642868018538540661695255739791656365601739182085942203909654727019316141164866681594438728186250967850956242270698307289180438956031789663190960308289740336394169600292783785864607037975177211917126123\r\n'
    b'Choose an option:\r\n'
    b'     1. Get encrypted flag\r\n'
    b'     2. Encrypt\r\n'
    b'     3. Decrypt\r\n'
N = 175892894619439237483623969548585379816783903857441536821865000648391559389629720262561073903671301335589415642868018538540661695255739791656365601739182085942203909654727019316141164866681594438728186250967850956242270698307289180438956031789663190960308289740336394169600292783785864607037975177211917126123
[DEBUG] Sent 0x2 bytes:
    b'3\n'
[DEBUG] Received 0xe bytes:
    b'Ciphertext: \r\n'
[DEBUG] Sent 0x2 bytes:
    b'2\n'
[DEBUG] Received 0x193 bytes:
    b'Plaintext: 136958391786123523108795114947448622468093772333029130605449922015798565249444147940532813264338068132164099875474204633019087630362999414492063400962464679504959859047123985428500259605246582850614711494830195177173568492477962254291025276984019468250727350584386184195293822497134621846433816123626753130536\r\n'
    b'Choose an option:\r\n'
    b'     1. Get encrypted flag\r\n'
    b'     2. Encrypt\r\n'
    b'     3. Decrypt\r\n'
factored N with c=2: p = 13330786134763976488385425598920256837848284907187205010576544306986866630178529566749425277881264627581637913587451502476768143936119595733229260880537637
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x137 bytes:
    b'111157208362982657871053516689356618071489008210392431946734949190917953266771517935894360691674038478650159024524649517583164444588621621453367164583441447707563957285181400128556892163803465556291801438878815712539176795295794443087507865924830680937530458968763508972528327497590821771221010984730795258657\r\n'
c_flag = 111157208362982657871053516689356618071489008210392431946734949190917953266771517935894360691674038478650159024524649517583164444588621621453367164583441447707563957285181400128556892163803465556291801438878815712539176795295794443087507865924830680937530458968763508972528327497590821771221010984730795258657
flag = b'HCMUS-CTF{fault-attack}'
[*] Closed connection to vm.daotao.antoanso.org port 32782
```

## Flag

```text
HCMUS-CTF{fault-attack}
```

## Lessons Learned

- CRT-based RSA decryption (`c^d mod p` and `c^d mod q` combined via CRT) is only as safe as both legs being computed correctly and independently - a bug or fault that corrupts just one leg turns any decrypt query into a factorization oracle.
- The Boneh-DeMillo-Lipton fault attack pattern - `gcd(M^e - c mod N, N)` - applies whenever a decryption is correct modulo one prime factor and wrong modulo the other, whether the cause is an induced hardware fault or, as here, an ordinary software bug.
- A single successful query is enough; retry with a handful of small distinct chosen ciphertexts in case any individual attempt yields a trivial gcd.
- When a service offers both a trustworthy encrypt path and a buggy decrypt path, prefer reconstructing the private key and decrypting client-side over routing sensitive data (like the real flag ciphertext) through the buggy oracle.
- Always test cryptographic "optimizations" (like a CRT speedup) against their reference implementation - silent copy-paste bugs in performance code are a common source of exploitable asymmetric faults.
