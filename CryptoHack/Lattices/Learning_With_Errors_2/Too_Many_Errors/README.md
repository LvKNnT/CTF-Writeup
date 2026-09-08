# Too Many Errors Writeup

## Summary

This live LWE challenge runs at `socket.cryptohack.org:13390`. The service exposes enough related encryptions for a differential attack: by collecting samples and identifying the repeated base vector length, the solver recovers the flag directly.

Flag:

```text
crypto{f4ult_4ttack5_0n_lw3}
```

## Triage

The folder contains the server source `13390_7ed55387d10ab932e673c9df3cc8bbfc.py` and `solve.sage`. The solver has the live endpoint hard-coded and connects with pwntools.

## Solve Path

The attack repeatedly queries the encryption oracle and compares the returned noisy samples. Too many errors should make decryption unreliable, but the implementation leaks enough structure across related samples to identify the base vector length:

```text
[+] Identified base vector length: 28
```

With that structure recovered, the script reconstructs the flag.

## Exploit

Use `solve.sage`. It:

- connects to `socket.cryptohack.org:13390`,
- collects encryption samples,
- performs the differential recovery,
- prints the flag.

Run:

```bash
sage solve.sage
```

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Lattices/Learning_With_Errors_2/Too_Many_Errors
sage solve.sage
```

Output:

```text
[*] Collecting samples (Differential Attack)...
[+] Identified base vector length: 28
[+] Flag: crypto{f4ult_4ttack5_0n_lw3}
```

## Flag

```text
crypto{f4ult_4ttack5_0n_lw3}
```

## Lessons Learned

- Repeated oracle queries can expose structure that one noisy sample hides.
- Implementation faults can defeat the intended hardness of LWE.
- Differential attacks are useful when samples are related rather than independent.
