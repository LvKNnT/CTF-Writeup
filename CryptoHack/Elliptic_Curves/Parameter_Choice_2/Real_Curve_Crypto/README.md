# Real Curve Crypto Writeup

## Summary

This challenge implements elliptic-curve arithmetic over the real numbers instead of a finite field. Real elliptic curves do not provide a hard finite-group ECDLP; scalar multiplication can be related to elliptic integrals on a lattice. Using high-precision integration and LLL recovers the scalar and decrypts the AES ciphertext.

Flag:

```text
crypto{real_fields_arent_finite}
```

## Triage

The challenge provides a Python source file and an output transcript containing real-valued curve points and an encrypted flag. The source shows that the shared secret is derived from scalar multiplication on a real curve.

The solver starts by computing high-precision elliptic integrals:

```text
[*] Computing exact elliptic integrals...
```

## Solve Path

On a real elliptic curve, points can be mapped to an analytic parameter using elliptic integrals. The relation between `G` and `P = N * G` becomes:

```text
u_P = N * u_G mod omega
```

where `omega` is a period. This is an approximate modular linear relation, so the solver builds a lattice and uses LLL to recover the integer scalar `N`. With `N`, the AES key can be recreated and the ciphertext decrypted.

## Exploit

Use `solve.sage`. It:

- computes the elliptic integral values for `G` and `P`,
- builds a lattice for the approximate modular relation,
- recovers `N` with LLL,
- derives the AES key,
- decrypts the flag.

Run it with:

```bash
sage solve.sage
```

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Elliptic_Curves/Parameter_Choice_2/Real_Curve_Crypto
sage solve.sage
```

Output:

```text
[+] Recovered Scalar (N): 106141468078803597872809305192151622442
[+] Recovered AES Key: 4fda1a69712e64c3f8c19e78d7d3a32a
[!] FLAG: crypto{real_fields_arent_finite}
```

## Flag

```text
crypto{real_fields_arent_finite}
```

## Lessons Learned

- Elliptic-curve cryptography relies on finite-field group structure.
- Real-valued elliptic curves expose analytic structure that breaks scalar secrecy.
- Lattice reduction is useful when a scalar relation is known approximately.
