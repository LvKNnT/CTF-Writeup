# CSIDH Key Exchange Writeup

## Summary

The challenge asks for a full CSIDH key exchange computation from the provided parameters. The solve applies the private exponent vector to the other party's public curve, derives the shared Montgomery `A`, and decrypts the AES-CBC ciphertext.

Flag:

```text
crypto{post_quantum_NIKE_isogenies_just_do_it}
```

## Triage

`source_47e3caad5ebcbefb8210c11b8c93efe0.sage` leaves the shared secret as `None`. `solve.sage` implements the CSIDH action and decrypts the included ciphertext.

## Solve Path

The CSIDH action applies each small prime according to the sign and magnitude of its exponent. After finishing the walk from the other party's public curve, the shared secret is the Montgomery `A` coefficient:

```python
shared_secret = montgomery_A(E_shared_A)
```

The script hashes `str(shared_secret)` with SHA-256 and uses AES-CBC to recover the flag.

## Exploit

Run:

```bash
sage solve.sage
```

## Verification

```text
$ sage solve.sage
shared_secret = 3535872301824536828474148022891087211908124858372657462170957663778447515208455309139232037575345742373769128664931019679705493779439643552226146830087512
b'crypto{post_quantum_NIKE_isogenies_just_do_it}'
```

## Flag

```text
crypto{post_quantum_NIKE_isogenies_just_do_it}
```

## Lessons Learned

- CSIDH key exchange is a commutative class-group action on curves.
- The Montgomery `A` coefficient is enough to derive the symmetric key in this challenge.
