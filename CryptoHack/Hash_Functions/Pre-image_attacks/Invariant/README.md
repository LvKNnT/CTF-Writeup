# Invariant Writeup

## Summary

The custom hash has an invariant subspace that maps certain structured inputs to the all-zero digest. Searching a small two-block subspace finds a preimage for the zero digest, which the server accepts and rewards with the flag.

Flag:

```text
crypto{preimages_of_the_all_zero_output}
```

## Triage

`13393_6eac484069c511cc17a276266c645891.py` returns the flag when `MyHash(data).digest() == b"\x00"*8`. `solve.py` reimplements `MyHash` locally and searches payloads built from bytes `66`, `67`, `76`, and `77`.

## Solve Path

The solver precomputes all valid 8-byte blocks in the invariant subspace:

```python
allowed_bytes = [b"\x66", b"\x67", b"\x76", b"\x77"]
allowed_blocks = [b"".join(t) for t in itertools.product(allowed_bytes, repeat=8)]
```

It tests two-block payloads until the hash is all zero:

```text
66666666666666666666666667676776
```

## Exploit

Run:

```bash
python solve.py
```

The file is configured for `localhost`; set `HOST = 'socket.cryptohack.org'` for the live service.

## Verification

```text
[+] Collision found! Payload: 66666666666666666666666667676776
[+] FLAG: crypto{preimages_of_the_all_zero_output}
```

## Flag

```text
crypto{preimages_of_the_all_zero_output}
```

## Lessons Learned

- Invariant subspaces can turn preimage resistance into a small search problem.
- Reimplementing the primitive locally makes live service interaction minimal and reliable.
