# CSCV 2026 Crypto Writeups

- [Baby Circuit](baby_circuit/) - Sage solver and TEST service bundle.
- [Chimera Student](chimera_student/) - Sage solver, C++ helper, and attestation output.
- [Residuegate](residuegate/) - local service configuration, cached data, pinned Qwen model metadata, and Python solver.
- [Typhone](typhone/) - Sage decryptor and ciphertext output.

The repository's `.gitignore` excludes Residuegate's model weights (`qwen3vl2b/model.safetensors`, approximately 4.26 GB) and local server binary (`local-server/residuegate-hard`, approximately 555 MB). They remain available in the local workspace but are not included in a fresh clone. The Docker build requires the server binary, and local embedding generation requires the model weights.

## Baby Circuit

### Summary

Baby Circuit is a hardware-proof challenge with a supplied offline TEST service. The hosted service encrypts the real flag. Two carefully chosen proofs expose enough circuit residuals to recover the AES key from the public session data.

Flag:

~~~text
CSCV2026{th1s_v1b1ng_c1rcu1t_h4v3_4_l0t_of_w34kn3ss3s_cea549071eb50a4c}
~~~

### Triage

The public bundle contains the service source, the verifier/circuit implementation, and a Linux x86-64 CPython 3.11 extension. `get_hardware_specs` publishes the field, Poseidon parameters, manufacturing shear, register coefficients, IV, and ciphertext. The session permits only two proof queries.

### Solve Path

The shear used by the circuit makes the lane-0 coefficient vanish through the first 24 rounds. This cancels the partial-round fifth-power terms from the row-60 residual, leaving an affine expression in the initial state. An E-only proof at 95 MHz therefore gives a direct equation for `w`:

~~~text
row60 = constant + c_w*w + c_1*nonce1 + c_2*nonce2  (mod p)
~~~

The second proof uses the A+E+F selector at 112 MHz. A zeros the first lane before the partial rounds, and F zeros the round-24 outputs. Interpolating the proof remainder at the public selector points then isolates `load^5`; the recovered load is checked against the intact Poseidon hash.

The published load coefficients also constrain two 54-bit registers with a quadratic equation modulo `p`:

~~~text
r1^2 + A*r1*r2 + B*r2^2 + C*r1 + D*r2 + E - load = 0  (mod p)
~~~

The solver builds shifted polynomials, reduces their lattice with LLL, and uses exact resultants/CRT to find the bounded integer roots. It derives the key as `SHA256(w || r1 || r2)` and checks AES-CBC padding.

### Exploit

From WSL, start the bundled TEST service in one terminal:

~~~bash
python hsm_main.py
~~~

Then run the solver in another:

~~~bash
sage baby_circuit_solver.py 127.0.0.1 1337
~~~

`derive_affine_leak` and `recover_w_from_e_only` extract `w`; `recover_load_from_aef` recovers and verifies the load; `recover_register_pair` performs the bounded LLL recovery; and `decrypt_candidates` validates the derived AES key.

### Verification

The command above completed against the local service with `query_budget_used: 2` and:

~~~text
decrypted_flag: FLAG{test_oracle_local__real_flag_is_online}
~~~

The original writeup also records a separate bundled-fixture check that printed the same TEST flag. These local results do not verify the hosted flag listed below.

<!-- TODO: Add the captured hosted-service result supporting the Baby Circuit flag. -->

Files: [solver](baby_circuit/baby_circuit_solver.py), [local decryptor](baby_circuit/decrypt.sage), and [public service bundle](baby_circuit/public/).

### Flag

~~~text
CSCV2026{th1s_v1b1ng_c1rcu1t_h4v3_4_l0t_of_w34kn3ss3s_cea549071eb50a4c}
~~~

### Lessons Learned

- A verifier that publishes selected proof remainders can leak internal circuit state even when the witness is opaque.
- Fault selectors are useful when they remove all but one unknown term from an interpolation equation.
- Small bounded roots modulo a large prime are a natural LLL target.

## Chimera Student

### Summary

Chimera Student hides an RSA modulus behind 200 attestations of the form `3^(token XOR challenge) mod N`. For a fixed token, the exponent is an affine function of the 128 challenge bits, so integer relations among the samples eliminate the secret token and reveal `N`.

Flag:

~~~text
CSCV2026{ch1m3r4_h1dd3n_m0dulus_th3n_b1453d_k3yg3n_2026}
~~~

### Triage

The source states that `N=p*q` is 768 bits, each factor is 384 bits, and `p mod M = 17^a mod M` for a public `M`. The output includes 200 challenge/attestation pairs and an RSA ciphertext.

### Solve Path

For every sample, write the exponent as a constant plus a signed contribution from each challenge bit. Construct an integer matrix whose rows are the constant row and the 128 challenge-bit rows. Any vector in its integer kernel annihilates the corresponding exponent sum:

~~~text
sum_i r_i * (token XOR challenge_i) = 0
~~~

Consequently, the product of attestations raised to those relation coefficients is `1 mod N`; subtracting the two integer products gives a multiple of `N`. The solver obtains the full integer kernel with Smith normal form, reduces its basis with LLL, and takes GCDs of these differences. It removes accidental factors shared with the attestations and checks that the result has the expected 768-bit size.

To factor `N`, enumerate the subgroup residue `r = 17^a mod M` and its matching `s = N/r mod M`. Write `p=r+M*k` and `q=s+M*l`; expanding `p*q=N` yields a two-dimensional modular linear equation for bounded `k,l`. The GMP helper solves this lattice equation and validates the full product and primality before the RSA decryption.

### Exploit

~~~bash
sage solve.sage
~~~

`recover_modulus` constructs and reduces the annihilating relations. `recover_factors` compiles `factor_chimera.cpp`, whose bounded residue search factors the modulus. The final stage decrypts and re-encrypts the supplied RSA ciphertext as a consistency check.

Files: [solver](chimera_student/solve.sage), [GMP helper](chimera_student/factor_chimera.cpp), and [challenge output](chimera_student/output_chimera.txt).

### Verification

The solver completed against the bundled output and printed:

~~~text
plaintext: CSCV2026{ch1m3r4_h1dd3n_m0dulus_th3n_b1453d_k3yg3n_2026}
~~~

### Flag

~~~text
CSCV2026{ch1m3r4_h1dd3n_m0dulus_th3n_b1453d_k3yg3n_2026}
~~~

### Lessons Learned

- XOR with public bit vectors becomes linear after representing each challenge bit separately.
- An integer relation among exponents turns modular powers into GCD-visible multiples of the hidden modulus.
- A public residue constraint can make factoring practical even when both RSA primes are large.

## Residuegate

### Summary

Residuegate is an image-classification challenge with a weak encrypted linear head and a six-image commitment. The solver recovers the head, evaluates all 16 allowed variants for each of six image slots, finds the committed tuple, and submits those images.

Flag (local TEST service):

~~~text
CTF{local_test_only}
~~~

### Triage

The local bundle contains the server, one badge image, its cached Qwen embeddings, and a Docker Compose file. The service exposes an exact modular public key with `q=167772161`, a 16-query encrypted evaluation budget, six image slots, and a commitment over a space of `16^6` tuples. The client solver needs the pinned Qwen model in `qwen3vl2b/`; its metadata is included, while the weights are excluded from Git.

### Solve Path

The public key provides `b` and `-a` for an exact linear relation. Gaussian elimination recovers the secret vector:

~~~text
(-neg_a) * s = b  (mod q)
~~~

The solver encrypts the zero vector and twelve unit vectors. Their decrypted logits reveal the linear head's bias and columns. It checks that an additional random input equals the recovered affine function before proceeding.

Each of the six slots has 16 allowed variants. `apply_variant` changes the signs of ±8 pixel offsets over four quadrants and three color channels. The local Qwen vision model produces the quantized 12-dimensional embedding for every candidate. The recovered head turns each embedding into logits. `find_tuple` hashes each slot/variant/logit block in the documented order and searches at most `16^6` combinations for the published commitment.

After finding the tuple, the solver uploads the six corresponding PNGs and the session ID. The local server accepts them and returns its test flag.

### Exploit

Install the listed packages in Conda base:

~~~powershell
pip install -r requirements.txt
~~~

Start the local service, then run:

~~~powershell
python sol.py
~~~

The solver defaults to `http://127.0.0.1:5000` and reads the `qwen3vl2b` directory beside itself. `RESIDUEGATE_ENDPOINT` specifies the service URL, while `RESIDUEGATE_MODEL_DIR` specifies the model directory. The model files are pinned to [Qwen3-VL-2B-Instruct revision 89644892e4d85e24eaac8bacfd4f463576704203](https://huggingface.co/Qwen/Qwen3-VL-2B-Instruct/tree/89644892e4d85e24eaac8bacfd4f463576704203); Transformers is configured for local-only loading.

For Docker-based service startup:

~~~powershell
docker compose up -d
~~~

Files: [solver](residuegate/sol.py), [dependencies](residuegate/requirements.txt), and [local compose bundle](residuegate/docker-compose.yml).

### Verification

The bundled native server started in WSL and reported `ResidueGate ready: 5000`. The solver recovered the encrypted head, embedded all 96 candidates in 282 seconds on CPU, found tuple `(12, 7, 15, 10, 12, 13)`, and received an accepted response from `http://127.0.0.1:5000`:

~~~text
96 embeddings in 282s
tuple (12, 7, 15, 10, 12, 13)
{"flag":"CTF{local_test_only}","status":"accepted"}
~~~

### Flag

~~~text
CTF{local_test_only}
~~~

This is the flag configured by the local Docker Compose file. The hosted challenge flag is not recorded here.

### Lessons Learned

- If a public key relation is exact over a small field, test whether linear algebra recovers its secret.
- Chosen encrypted basis vectors reveal an affine function with very few oracle calls.
- A commitment over a moderate product space can be searched directly when each candidate's full hash input is reconstructible.

## Typhone (TYPHON)

### Summary

Typhone is an offline cryptographic chain with multiple stages. Each recovered key decrypts the next layer. The chain combines weak RSA parameters, reused AES-GCM nonces, an LFSR, smooth-order discrete logarithms, SHA-256 length extension, deterministic shuffling, and lattice attacks.

Flag:

~~~text
CSCV2026{typh0n_LCG_h4st4d_w13n3r_LFSR_PH_SHA_C2log_RAT_ECDSA_BD_Coppersm1th}
~~~

### Triage

`output_typhon.txt` contains the encrypted chain. `challenge_typhon.py` documents how each layer is generated, while `decrypt_typhon.sage` reproduces the attacks and reads the output file beside itself.

### Solve Path

#### Stage 1: LCG and broadcast RSA

The observed LCG outputs determine the next state. Its hash gives the AES-GCM key for the first layer. That plaintext contains three RSA ciphertexts of the same 15-byte message with exponent 3; CRT combines them, and an exact integer cube root recovers the message and the next key.

#### Stage 2: Wiener, nonce reuse, and LFSR

The next JSON layer encrypts a weak RSA key. Wiener's continued-fraction attack recovers its small private exponent. Decrypting the RSA-wrapped AES key reveals two GCM ciphertexts that reused a nonce. Known plaintext from the first ciphertext exposes the LFSR output prefix; advancing that recovered LFSR yields the key for the next layer.

#### Stage 3: Smooth-order DH and SHA-256 extension

The DH group has smooth order, so Pohlig–Hellman recovers its private exponent and the next AES key. The following layer gives `SHA256(secret || message)` and the secret length. A SHA-256 length-extension forgery appends the required authorization suffix and derives the next key without learning the secret.

#### Stage 4: Recover the C2 and RAT keys

The C2 log uses a deterministic shuffle seeded with `42`. Reversing that shuffle restores the 16 beacon bytes used as a key. The decrypted RAT configuration stores the following key as module intervals in a fixed module-name order; the solver ignores the random module ordering and unrelated entries.

#### Stage 5: ECDSA, weak RSA, and partial-prime RSA

Forty secp256k1 signatures use nonces below `2^128`, yielding a small-error Hidden Number Problem. LLL recovers the signing key and decrypts the next layer. Boneh–Durfee then recovers a private exponent for the weak RSA instance. The final RSA modulus leaks the top 128 bits of one factor; Coppersmith searches bounded windows for its unknown suffix.

The solver hashes all recovered key components in the specified order and uses the resulting AES-GCM key to decrypt the final flag.

### Exploit

~~~bash
sage decrypt_typhon.sage
~~~

The script's helpers implement the broadcast cube root, Wiener attack, LFSR recovery, Pohlig–Hellman step, SHA-256 compression/length extension, ECDSA lattice, Boneh–Durfee, and windowed Coppersmith search.

Files: [decryptor](typhone/decrypt_typhon.sage), [generator/source](typhone/challenge_typhon.py), and [ciphertext output](typhone/output_typhon.txt).

### Verification

The command completed all stages, including the ECDSA and Boneh–Durfee lattices, and printed:

~~~text
CSCV2026{typh0n_LCG_h4st4d_w13n3r_LFSR_PH_SHA_C2log_RAT_ECDSA_BD_Coppersm1th}
~~~

### Flag

~~~text
CSCV2026{typh0n_LCG_h4st4d_w13n3r_LFSR_PH_SHA_C2log_RAT_ECDSA_BD_Coppersm1th}
~~~

### Lessons Learned

- Reused GCM nonces reveal the XOR of plaintexts, which can expose a stream-cipher prefix.
- Weak RSA exponents, small broadcast exponents, biased ECDSA nonces, and partially known factors each have distinct lattice or number-theoretic attacks.
- In a key chain, validate each recovered layer before using it to decrypt the next.
