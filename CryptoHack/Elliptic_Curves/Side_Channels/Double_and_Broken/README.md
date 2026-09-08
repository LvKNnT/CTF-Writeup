# Double and Broken Writeup

## Summary

This side-channel challenge provides collected traces from scalar multiplication. Averaging the traces reveals a threshold pattern that corresponds to the scalar bits. Decoding those bits gives the flag.

Flag:

```text
crypto{Sid3_ch4nn3ls_c4n_br34k_s3cur3_curv3s}
```

## Triage

The folder contains `source_snippet_0b89127bb905d47db49281e0449d6bd6.py`, `collected_data.txt`, `clean_data`, and `solve.py`. The source snippet indicates that the secret is encoded through the scalar multiplication behavior, and the collected traces give repeated measurements.

## Solve Path

The solver loads the traces, averages them, and thresholds the result to recover a binary string. The bit order is reversed before converting back to bytes.

The noisy intermediate output includes the averaged trace and candidate bit string, then the final decoded bytes:

```text
b'crypto{Sid3_ch4nn3ls_c4n_br34k_s3cur3_curv3s}'
```

## Exploit

Use `solve.py`. It:

- loads the collected side-channel data,
- averages repeated traces to reduce noise,
- thresholds the averaged signal into bits,
- converts the recovered bit string into the flag bytes.

Run it with:

```bash
python solve.py
```

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Elliptic_Curves/Side_Channels/Double_and_Broken
python solve.py
```

Output:

```text
b'crypto{Sid3_ch4nn3ls_c4n_br34k_s3cur3_curv3s}'
```

## Flag

```text
crypto{Sid3_ch4nn3ls_c4n_br34k_s3cur3_curv3s}
```

## Lessons Learned

- Repeated noisy traces can become useful after averaging.
- Branch-dependent scalar multiplication can leak key bits.
- Constant-time scalar multiplication patterns are necessary for side-channel resistance.
