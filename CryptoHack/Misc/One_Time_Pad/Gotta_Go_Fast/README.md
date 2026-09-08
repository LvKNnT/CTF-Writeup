# Gotta Go Fast Writeup

## Summary

Gotta Go Fast uses a one-time-pad-like XOR key derived from the current Unix timestamp. The solve asks for the encrypted flag immediately, regenerates the same timestamp-derived key locally, and XORs the ciphertext back to plaintext.

Flag:

```text
crypto{t00_f4st_t00_furi0u5}
```

## Triage

The service exposes a `get_flag` option that returns an encrypted flag. The key is:

```python
current_time = int(time.time())
key = hashlib.sha256(long_to_bytes(current_time)).digest()
```

Because the key is only based on the current second, it is predictable if the request is made and decrypted immediately.

## Solve Path

The solve script connects, requests the flag ciphertext, and computes the same key from local time:

```python
io = pwn.remote("socket.cryptohack.org", 13372)
io.sendline(json.dumps({"option": "get_flag"}).encode())
encrypted_flag = bytes.fromhex(data["encrypted_flag"])
decrypted_flag = decrypt(encrypted_flag)
```

The `decrypt` routine is the same XOR operation as encryption because OTP XOR is symmetric.

## Exploit

The standalone exploit is `Misc/One_Time_Pad/Gotta_Go_Fast/solve.py`.

```bash
python solve.py
```

## Verification

Verified against the live CryptoHack socket service from WSL using the `sage` conda environment:

```text
[*] Encrypted flag obtained.
[*] Decrypting flag...
[+] Decrypted flag: crypto{t00_f4st_t00_furi0u5}
```

## Flag

```text
crypto{t00_f4st_t00_furi0u5}
```

## Lessons Learned

- A timestamp is not a secret key.
- XOR encryption is only as strong as the unpredictability and uniqueness of the keystream.
- Time-based attacks often require making the request and decryption attempt in the same second.
