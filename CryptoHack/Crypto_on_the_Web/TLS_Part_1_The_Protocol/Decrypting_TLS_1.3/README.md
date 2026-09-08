# Decrypting TLS 1.3 Writeup

## Summary

TLS 1.3 uses ephemeral key exchange, so the server private key is not enough to decrypt a capture. The provided `SSLKEYLOGFILE` secrets allow Wireshark/tshark to decrypt the stream and reveal the flag.

Flag:

```text
crypto{export_SSLKEYLOGFILE}
```

## Triage

The folder contains:

```text
tls3_871583423e02a66acd81eb34ed967489.cryptohack.org.pcapng
keylogfile_c86a7e105b820e0780e903b0d8388fa3.txt
%5c
```

The `%5c` file contains the recovered flag.

## Solve Path

Load the keylog file in Wireshark:

```text
Preferences -> Protocols -> TLS -> (Pre)-Master-Secret log filename
```

Then open the pcap and follow the decrypted TLS stream. The keylog includes client/server traffic secrets such as:

```text
CLIENT_TRAFFIC_SECRET_0 ...
SERVER_TRAFFIC_SECRET_0 ...
```

## Exploit

No standalone solve script is needed; use the pcap and keylog file.

## Verification

The checked-in `%5c` file contains:

```text
Flag: crypto{export_SSLKEYLOGFILE}
```

## Flag

```text
crypto{export_SSLKEYLOGFILE}
```

## Lessons Learned

- TLS 1.3 traffic decryption requires session secrets, not just the server private key.
- Browser `SSLKEYLOGFILE` output is the standard way to decrypt your own TLS captures.
