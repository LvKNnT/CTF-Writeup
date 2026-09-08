# Authenticated Handshake Writeup

## Summary

This TLS 1.3 task asks for the client Finished verify data. The solve script reconstructs the handshake transcript, derives the Finished key from the client handshake traffic secret, and computes the HMAC over the transcript hash.

Flag:

```text
b51d7b5fb12aa3d692140d8f1f80732610e99411ca0f6d928b0f60570cbc778e672457a729d7cf3b58bc174f00dc5d30
```

## Triage

The folder contains a pcap missing the client Finished record, a TLS keylog file, and `client_finished_7be8188c90a19caa197cdc07982f17cb.py`.

## Solve Path

The script implements TLS 1.3 HKDF label expansion:

```python
finished_key = HKDF_expand_label(
    client_handshake_traffic_secret, b"finished", b"", HASH_LEN, HASH_ALG)
```

It concatenates the handshake transcript through the server Finished message, hashes it, and computes:

```python
client_finished = verify_data(finished_key, transcript, HASH_ALG).hex()
```

## Exploit

Run:

```bash
python client_finished_7be8188c90a19caa197cdc07982f17cb.py
```

## Verification

```text
$ python client_finished_7be8188c90a19caa197cdc07982f17cb.py
b51d7b5fb12aa3d692140d8f1f80732610e99411ca0f6d928b0f60570cbc778e672457a729d7cf3b58bc174f00dc5d30
```

## Flag

```text
b51d7b5fb12aa3d692140d8f1f80732610e99411ca0f6d928b0f60570cbc778e672457a729d7cf3b58bc174f00dc5d30
```

## Lessons Learned

- TLS 1.3 Finished messages authenticate the full handshake transcript.
- The Finished key is derived with the TLS 1.3 `HKDF-Expand-Label` construction.
