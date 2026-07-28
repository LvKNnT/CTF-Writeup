# TheChosenOne Writeup

## Summary

Interactive AES-256-ECB crypto challenge, reached with `nc`. The service (`server.py`) reads a line of attacker-controlled plaintext, appends the fixed 32-byte secret flag *after* it, encrypts the whole thing under AES-ECB with a fixed key, and prints the hex ciphertext. Because ECB encrypts identical 16-byte blocks identically and the attacker controls the prefix length, the flag falls to a textbook byte-at-a-time chosen-plaintext attack.

Flag:

```text
HCMUS-CTF{You_Can_4ttack_A3S!?!}
```

## Triage

`server.py` builds every ciphertext as `AES-256-ECB(user_input + flag, padded)`, with attacker input placed *before* the secret:

```python
flag = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" # TODO
key = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" # TODO

padding_character = "D"

assert (len(flag) == 32) and (len(key) == 32)
cipher = AES.new(key, AES.MODE_ECB)
```

```python
plaintext = user_input + flag
padding_length = padding(plaintext)
plaintext = plaintext.ljust(padding_length, padding_character)

sys.stdout.write('The ciphertext:\n{}\n\n'.format((cipher.encrypt(plaintext)).encode('hex')))
```

The custom padding rounds the total length up to the next multiple of **32** (not AES's 16-byte block) with filler `"D"`, and does nothing if the length is already a multiple of 32:

```python
def padding(plaintext):
    plaintext_length = len(plaintext)
    padding_length = 0
    if plaintext_length % 32 != 0:
        padding_length = (plaintext_length // 32 + 1) * 32
    else:
        padding_length = 0
    return padding_length
```

`key` and `flag` are placeholders in this source copy (`# TODO`), filled in at deployment. The `.encode('hex')` call is Python 2. The vulnerability is simply `AES.MODE_ECB` over `user_input + flag`: ECB processes each 16-byte block independently and deterministically, so identical plaintext blocks yield identical ciphertext blocks. The 32-byte padding granularity is irrelevant - the cipher still works in 16-byte blocks internally, so it only ever adds trailing filler beyond the flag.

## Solve Path

Since `plaintext = user_input + flag`, the attacker controls exactly how many bytes precede the unknown flag. Sizing the prefix so that the next unknown flag byte lands as the **last** byte of a 16-byte block turns recovery into a per-byte dictionary lookup:

1. **Align + record.** For flag byte `i`, send a prefix of `A`s of length `15 - (i mod 16)`. This pushes flag byte `i` to the final position of block `i // 16`. Record that ciphertext block as the target.

   ```python
   pad_len = BLOCK - 1 - (i % BLOCK)
   prefix = b"A" * pad_len
   block_idx = i // BLOCK
   sl = slice(block_idx * BLOCK, (block_idx + 1) * BLOCK)
   target_block = oracle(io, prefix)[sl]
   ```

2. **Brute-force one byte.** For each candidate byte `c`, query the oracle with `prefix + recovered + c`. This crafted input has the same block `i // 16` content as the target, except its last byte is our guess. When the block matches, `c` is the true flag byte.

   ```python
   for c in CHARSET:
       guess = prefix + recovered + bytes([c])
       if oracle(io, guess)[sl] == target_block:
           found = c
           break
   ```

3. **Repeat.** Append each recovered byte and continue for all 32 flag bytes. As `i` crosses 16, `block_idx` advances to the second block; the same alignment math keeps working because the recovered bytes fill the earlier positions.

Two practical details:

- **No random prefix.** The attacker input sits at offset 0 with nothing prepended, so alignment is exact and the standard attack applies directly.
- **Charset / newline.** Guesses are restricted to printable ASCII (`0x20`–`0x7e`). Beyond matching typical flag content, this avoids sending `0x0a`, which the server's `readline()` would treat as end-of-input and truncate the payload.

## Exploit

The standalone solver is [solve.sage](#Solve). It connects to the oracle and runs the byte-at-a-time recovery end to end, printing the flag as it grows. Key pieces:

- `oracle(io, data)` - sends one line of plaintext, reads back the response, and returns the raw ciphertext bytes (`bytes.fromhex` of the hex line). Note it consumes the `The ciphertext:\r\n` marker (CRLF over the socket).
- `main()` - loops over the 32 flag positions, doing the align/record (step 1) then the 256-way block-match brute force (step 2), accumulating `recovered`.
- Constants: `BLOCK = 16`, `FLAG_LEN = 32`, `CHARSET = range(0x20, 0x7f)`.

Set `HOST`/`PORT` at the top and run:

```bash
sage solve.sage
```

## Solve

```python
from pwn import *

# context.log_level = "debug"

HOST = ???
PORT = ???

BLOCK = 16
FLAG_LEN = 32
CHARSET = range(0x20, 0x7f)


def oracle(io, data: bytes) -> bytes:
    io.recvuntil(b"Your input: ")
    io.sendline(data)
    io.recvuntil(b"The ciphertext:\r\n")
    return bytes.fromhex(io.recvline().strip().decode())


def main():
    io = remote(HOST, PORT)

    recovered = b""
    for i in range(FLAG_LEN):
        pad_len = BLOCK - 1 - (i % BLOCK)
        prefix = b"A" * pad_len
        block_idx = i // BLOCK
        sl = slice(block_idx * BLOCK, (block_idx + 1) * BLOCK)

        target_block = oracle(io, prefix)[sl]

        found = None
        for c in CHARSET:
            guess = prefix + recovered + bytes([c])
            if oracle(io, guess)[sl] == target_block:
                found = c
                break

        if found is None:
            log.failure(f"no match at byte {i}; recovered so far: {recovered!r}")
            break

        recovered += bytes([found])
        log.info(f"[{i+1:2}/{FLAG_LEN}] {recovered.decode(errors='replace')}")

    io.close()
    log.success(f"FLAG: {recovered.decode(errors='replace')}")


if __name__ == "__main__":
    main()
```

## Verification

Running `sage solve.sage` against the live service recovers the flag one byte per line and prints the final result (flag redacted here per this repo's convention):

```text
$ sage solve.sage
[+] Opening connection to vm.daotao.antoanso.org on port 32779: Done
[*] [ 1/32] H
[*] [ 2/32] HC
[*] [ 3/32] HCM
...
[*] [32/32] HCMUS-CTF{You_Can_4ttack_A3S!?!}
[+] FLAG: HCMUS-CTF{You_Can_4ttack_A3S!?!}
```

## Flag

```text
HCMUS-CTF{You_Can_4ttack_A3S!?!}
```

## Lessons Learned

- ECB mode maps identical plaintext blocks to identical ciphertext blocks - any oracle that concatenates attacker data with a secret under ECB leaks the secret one byte at a time when the prefix length is controllable.
- Placing the secret *after* attacker-controlled input is the enabling condition: it lets the attacker always align the next unknown byte to a block boundary.
- Non-standard padding granularity (32 bytes here vs AES's native 16) does not defend anything - reason in units of the true 16-byte block and ignore the trailing filler.
- Watch the transport: guesses that include the line terminator (`0x0a`) get truncated by a `readline()` oracle, and responses may use CRLF (`\r\n`) over a socket even when the source writes `\n`.
