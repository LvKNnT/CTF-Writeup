# Megalomaniac 3 Writeup

## Summary

The third MEGA-style challenge targets encrypted file confidentiality. After recovering RSA private-key structure, the exploit injects the encrypted node key into the private-key field, uses the login oracle to recover it, and decrypts the stored file.

Flag:

```text
crypto{1ntegr1ty_ch3cks_are_n0T_0nly_th3Re_t0_mak3_crYptogr4phers_H4ppy!}
```

## Triage

The service is `socket.cryptohack.org:13410`. `solve.sage` receives encrypted account material and file metadata, reconstructs the RSA parameters, computes where the `u` component begins, injects the encrypted node key, and decrypts the file.

## Solve Path

The exploit first recovers key structure and computes the safe insertion point:

```python
u_data_start = u_start_offset + 2
injection_offset = math.ceil(u_data_start / 16) * 16
LEN_PADDING = injection_offset - u_data_start
```

It replaces one encrypted private-key block with `NODE_KEY_ENC`, then sends an RSA ciphertext for `u * p`. The server's response reveals enough of the manipulated `u'` value to extract the node key:

```python
u_prime = (bytes_to_long(SID_R) << 128) // p
NODE_KEY = u_prime_bytes[LEN_PADDING : LEN_PADDING + 16]
```

That AES key decrypts the encrypted file.

## Exploit

Run:

```bash
sage solve.sage
```

## Verification

```text
$ sage solve.sage
[+] Extracted Node Key: 6d1a7a8d3f31dd5448d8136f1232d19d
[SUCCESS] FLAG: Congratulations! you successfully compromised the confidentiality of the files from MEGA users! The flag is : crypto{1ntegr1ty_ch3cks_are_n0T_0nly_th3Re_t0_mak3_crYptogr4phers_H4ppy!}
```

## Flag

```text
crypto{1ntegr1ty_ch3cks_are_n0T_0nly_th3Re_t0_mak3_crYptogr4phers_H4ppy!}
```

## Lessons Learned

- Confidentiality without integrity lets attackers rearrange encrypted structured data.
- Parsing encrypted key blobs after decryption is dangerous unless the ciphertext is authenticated.
- File keys must be integrity-protected, not just encrypted.
