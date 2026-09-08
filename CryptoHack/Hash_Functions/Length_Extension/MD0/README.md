# MD0 Writeup

## Summary

The MAC is `hash(key || message)` using a custom Merkle-Damgard-like AES compression. Because the state after a signed message can be extended, we sign a harmless 15-byte message and forge a valid signature for a message containing `admin=True`.

Flag:

```text
crypto{l3ngth_3xT3nd3r}
```

## Triage

`13388_25e6ecf23e99d2590782f77b3327f862.py` signs messages unless they contain `admin=True`. `solve.sage` signs `b"a"*15`, computes the next compression block locally, and submits the extended message.

## Solve Path

Ask the server to sign:

```python
msg1 = b"a" * 15
```

Then compute the next hash state for the block containing `admin=Trueaaaaa`:

```python
msg2 = pad(b"admin=Trueaaaaa", 16)
out = bxor(AES.new(msg2, AES.MODE_ECB).encrypt(out), out)
```

The final forged message is:

```python
send = msg1 + b"\x01" + b"admin=Trueaaaaa"
```

## Exploit

Run the checked-in logic against the live host:

```bash
sage solve.sage
```

The file is configured for `localhost`; switch `HOST` to `socket.cryptohack.org` for the live service.

## Verification

```text
{"flag": "crypto{l3ngth_3xT3nd3r}"}
```

## Flag

```text
crypto{l3ngth_3xT3nd3r}
```

## Lessons Learned

- Prefix MACs built from iterative hashes are vulnerable to length extension.
- A padding byte can bridge from a signed benign message into a forbidden admin field.
