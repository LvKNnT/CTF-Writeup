# WOTS Up 2 Writeup

## Summary

This is a second WOTS forgery challenge with adjusted data. The solve again uses known one-time signature material to construct a valid signature for the flag-request message, then decrypts the provided ciphertext.

Flag:

```text
ECSC{0ne_m0r3_t1m3_s1gn4tur3_ff}
```

## Triage

`chal_455b7cde5b008daa22efc2ff172c9f28.py` defines the scheme, `data.json` contains the instance, and `solve.py` reconstructs the target signature and decrypts.

## Solve Path

The exploit is the same one-way-chain reuse issue: if a known signature element is earlier in the chain than the target needs, hash it forward to the required position. The script assembles the target signature and uses the derived key to decrypt.

## Exploit

Run:

```bash
python solve.py
```

## Verification

```text
$ python solve.py
Decrypted flag: ECSC{0ne_m0r3_t1m3_s1gn4tur3_ff}
```

## Flag

```text
ECSC{0ne_m0r3_t1m3_s1gn4tur3_ff}
```

## Lessons Learned

- Hash-based signatures are safe only under strict one-time-use assumptions.
- A second message signature can often be forged if the digest ordering lets known chain elements advance far enough.
