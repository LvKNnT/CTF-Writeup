#!/usr/bin/env sage
"""Decrypt the supplied CSCV2026 TYPHON instance.

Run from WSL with:
    conda run -n sage sage decrypt_typhon.sage

The script reads output_typhon.txt beside itself.  PyCryptodome must be
available in the Sage environment for AES-GCM.
"""

import hashlib
import json
import random
import re
import struct
from pathlib import Path
from operator import xor

from Crypto.Cipher import AES


def gcm_decrypt(key, box):
    cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(box["N"]))
    return cipher.decrypt_and_verify(bytes.fromhex(box["C"]), bytes.fromhex(box["T"]))


def i2b(x, size=None):
    x = int(x)
    if size is None:
        size = max(1, (x.bit_length() + 7) // 8)
    return x.to_bytes(size, "big")


def crt_pairwise(residues, moduli):
    value, modulus = ZZ(0), ZZ(1)
    for residue, next_modulus in zip(residues, moduli):
        residue, next_modulus = ZZ(residue), ZZ(next_modulus)
        step = ((residue - value) * inverse_mod(modulus, next_modulus)) % next_modulus
        value += modulus * step
        modulus *= next_modulus
    return value % modulus


def integer_cube_root(n):
    n = ZZ(n)
    lo, hi = ZZ(0), ZZ(1) << ((n.nbits() + 2) // 3 + 1)
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if mid**3 <= n:
            lo = mid
        else:
            hi = mid
    return lo


def recover_lcg_next(modulus, observed):
    x1, x2, x3, x4, x5 = map(ZZ, observed)
    denominator = (x2 - x1) % modulus
    if gcd(denominator, modulus) != 1:
        raise ValueError("LCG difference is not invertible modulo M")
    a = ((x3 - x2) * inverse_mod(denominator, modulus)) % modulus
    c = (x3 - a * x2) % modulus
    if (a * x3 + c) % modulus != x4 or (a * x4 + c) % modulus != x5:
        raise ValueError("LCG recurrence check failed")
    return (a * x5 + c) % modulus


def wiener_attack(n, e):
    for convergent in continued_fraction(ZZ(e) / ZZ(n)).convergents():
        k, d = ZZ(convergent.numerator()), ZZ(convergent.denominator())
        if k == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        disc = (n - phi + 1) ** 2 - 4 * n
        if disc < 0 or not ZZ(disc).is_square():
            continue
        root = ZZ(disc).sqrt()
        if (n - phi + 1 + root) % 2 == 0:
            p = (n - phi + 1 + root) // 2
            q = (n - phi + 1 - root) // 2
            if p * q == n:
                return d
    raise ValueError("Wiener attack did not recover the private exponent")


def lfsr_step(state):
    out = state & 1
    feedback = xor_many(state >> 31, state >> 29, state >> 25, state >> 23) & 1
    return out, (state >> 1) | (feedback << 31)


def lfsr_bits(state, count):
    bits = []
    for _ in range(count):
        bit, state = lfsr_step(state)
        bits.append(bit)
    return bits, state


def bits_to_bytes(bits):
    return bytes(sum(bits[i + j] << (7 - j) for j in range(8)) for i in range(0, len(bits), 8))


def recover_lfsr_state(known):
    observed = [((byte >> (7 - bit)) & 1) for byte in known for bit in range(8)]
    basis_columns = []
    for state_bit in range(32):
        out, _ = lfsr_bits(1 << state_bit, len(observed))
        basis_columns.append(out)
    matrix = Matrix(GF(2), len(observed), 32,
                    lambda row, col: basis_columns[col][row])
    solution = matrix.solve_right(vector(GF(2), observed))
    state = sum(ZZ(solution[i]) << i for i in range(32))
    check, _ = lfsr_bits(state, len(observed))
    if bits_to_bytes(check) != known:
        raise ValueError("LFSR state recovery check failed")
    return state


SHA_K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
]
SHA_IV = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
          0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff


def xor_many(*values):
    result = 0
    for value in values:
        result = xor(result, value)
    return result


def sha256_compress(state, block):
    words = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        x, y = words[i - 15], words[i - 2]
        s0 = xor_many(rotr(x, 7), rotr(x, 18), x >> 3)
        s1 = xor_many(rotr(y, 17), rotr(y, 19), y >> 10)
        words.append((words[i - 16] + s0 + words[i - 7] + s1) & 0xffffffff)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        s1 = xor_many(rotr(e, 6), rotr(e, 11), rotr(e, 25))
        ch = xor(e & f, xor(e, 0xffffffff) & g)
        t1 = (h + s1 + ch + SHA_K[i] + words[i]) & 0xffffffff
        s0 = xor_many(rotr(a, 2), rotr(a, 13), rotr(a, 22))
        maj = xor_many(a & b, a & c, b & c)
        t2 = (s0 + maj) & 0xffffffff
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & 0xffffffff, c, b, a, (t1 + t2) & 0xffffffff
    return [(state[i] + value) & 0xffffffff for i, value in enumerate([a,b,c,d,e,f,g,h])]


def sha_padding(length):
    return b"\x80" + b"\x00" * ((55 - length) % 64) + struct.pack(">Q", length * 8)


def sha256_length_extension(digest_hex, secret_len, original_message, extension):
    initial_length = secret_len + len(original_message)
    processed_length = initial_length + len(sha_padding(initial_length))
    state = [int(digest_hex[i:i+8], 16) for i in range(0, 64, 8)]
    data = extension + sha_padding(processed_length + len(extension))
    for offset in range(0, len(data), 64):
        state = sha256_compress(state, data[offset:offset + 64])
    return b"".join(struct.pack(">I", word) for word in state)


def recover_ecdsa_key(signatures, order, nonce_bound):
    """CVP attack for ECDSA signatures whose nonces are smaller than 2^128."""
    count = len(signatures)
    a_values, b_values = [], []
    for r, s, z in signatures:
        inv_s = inverse_mod(ZZ(s), order)
        a_values.append((ZZ(r) * inv_s) % order)
        b_values.append((ZZ(z) * inv_s) % order)

    # A lattice vector has coordinates (n*(x*a_i + q_i*n), x*B).
    # For x=d, translating by -n*b_i leaves n*k_i in each signature slot.
    rows = []
    for i in range(count):
        row = [ZZ(0)] * (count + 1)
        row[i] = order**2
        rows.append(row)
    rows.append([order * a for a in a_values] + [nonce_bound])
    basis = Matrix(ZZ, rows).LLL()
    target = vector(ZZ, [-order * b for b in b_values] + [ZZ(0)])

    # Exact Babai nearest plane in the reduced row basis.
    orthogonal = []
    for row in basis.rows():
        v = vector(QQ, row)
        for previous in orthogonal:
            v -= (v.dot_product(previous) / previous.dot_product(previous)) * previous
        orthogonal.append(v)
    residual = vector(QQ, target)
    for i in range(basis.nrows() - 1, -1, -1):
        q = residual.dot_product(orthogonal[i]) / orthogonal[i].dot_product(orthogonal[i])
        residual -= ZZ(round(q)) * vector(QQ, basis.row(i))
    residual = vector(ZZ, [ZZ(x) for x in residual])
    candidate = ((target[-1] - residual[-1]) // nonce_bound) % order

    for private in (candidate, (-candidate) % order):
        nonces = [((a * private + b) % order) for a, b in zip(a_values, b_values)]
        if all(k < nonce_bound and (ZZ(s) * k - ZZ(z) - private * ZZ(r)) % order == 0
               for (r, s, z), k in zip(signatures, nonces)):
            return private
    raise ValueError("ECDSA small-nonce lattice failed verification")


def remove_unhelpful_vectors(lattice, monomials, bound, current, minimum=7):
    if current < 0 or lattice.nrows() <= minimum:
        return lattice
    for i in range(min(current, lattice.nrows() - 1), -1, -1):
        if lattice[i, i] < bound:
            continue
        affected = [j for j in range(i + 1, lattice.nrows()) if lattice[j, i] != 0]
        if not affected:
            lattice = lattice.delete_rows([i]).delete_columns([i])
            monomials.pop(i)
            return remove_unhelpful_vectors(lattice, monomials, bound, i - 1, minimum)
        if len(affected) == 1:
            j = affected[0]
            deeper = all(lattice[k, j] == 0 for k in range(j + 1, lattice.nrows()))
            if deeper and abs(bound - lattice[j, j]) < abs(bound - lattice[i, i]):
                lattice = lattice.delete_rows([j, i]).delete_columns([j, i])
                monomials.pop(j)
                monomials.pop(i)
                return remove_unhelpful_vectors(lattice, monomials, bound, i - 1, minimum)
    return lattice


def boneh_durfee(n, e, delta=0.275, m=5):
    """Herrmann-May Boneh-Durfee lattice for d < n^delta."""
    t = int(floor((1 - 2 * delta) * m))
    X = 2 * ZZ(floor(RR(n) ** delta))
    Y = ZZ(floor(RR(n) ** 0.5))

    P = PolynomialRing(ZZ, names=("x", "y"))
    px, py = P.gens()
    A = (n + 1) // 2
    polynomial = 1 + px * (A + py)

    PR = PolynomialRing(ZZ, names=("u", "x", "y"))
    u, x, y = PR.gens()
    quotient = PR.quotient(x * y + 1 - u)
    pol_z = quotient(PR(polynomial)).lift()
    U = X * Y + 1

    shifts = []
    for k in range(m + 1):
        for i in range(m - k + 1):
            shifts.append(x**i * ZZ(e)**(m-k) * pol_z**k)
    shifts.sort()
    monomials = []
    for shift in shifts:
        for monomial in shift.monomials():
            if monomial not in monomials:
                monomials.append(monomial)
    monomials.sort()

    for j in range(1, t + 1):
        for k in range(int(floor(m / t) * j), m + 1):
            shifts.append(quotient(y**j * pol_z**k * ZZ(e)**(m-k)).lift())
    for j in range(1, t + 1):
        for k in range(int(floor(m / t) * j), m + 1):
            monomials.append(u**k * y**j)

    dimension = len(monomials)
    lattice = Matrix(ZZ, dimension)
    for i in range(dimension):
        lattice[i, 0] = shifts[i](0, 0, 0)
        for j in range(1, i + 1):
            if monomials[j] in shifts[i].monomials():
                lattice[i, j] = (shifts[i].monomial_coefficient(monomials[j]) *
                                 monomials[j](U, X, Y))
    lattice = remove_unhelpful_vectors(lattice, monomials, ZZ(e)**m, dimension - 1)
    dimension = lattice.nrows()
    lattice = lattice.LLL()

    R2 = PolynomialRing(QQ, names=("w", "z"))
    w, z = R2.gens()
    p1 = p2 = R2.zero()
    for j in range(dimension):
        factor = monomials[j](w*z + 1, w, z) / monomials[j](U, X, Y)
        p1 += factor * lattice[0, j]
        p2 += factor * lattice[1, j]
    resultant = p1.resultant(p2)
    Rq = PolynomialRing(ZZ, names=("q",))
    q = Rq.gen()
    resultant = Rq(resultant(q, q))
    y_roots = resultant.roots(ring=ZZ)
    if not y_roots:
        raise ValueError("Boneh-Durfee resultant has no integer roots")
    for y0, _ in y_roots:
        x_poly = Rq(p1(q, y0))
        for x0, _ in x_poly.roots(ring=ZZ):
            numerator = 1 + ZZ(x0) * (A + ZZ(y0))
            if numerator % ZZ(e):
                continue
            candidate_d = numerator // ZZ(e)
            if candidate_d > 0:
                phi_candidate = 2 * (A + ZZ(y0))
                if ZZ(e) * candidate_d - 1 != ZZ(x0) * (A + ZZ(y0)):
                    continue
                disc = (n - phi_candidate + 1) ** 2 - 4*n
                if disc >= 0 and ZZ(disc).is_square():
                    root = ZZ(disc).sqrt()
                    p = (n - phi_candidate + 1 + root) // 2
                    qv = (n - phi_candidate + 1 - root) // 2
                    if p*qv == n:
                        return candidate_d
    raise ValueError("Boneh-Durfee did not yield a valid RSA exponent")


def main():
    here = Path(__file__).resolve().parent
    data = json.loads((here / "output_typhon.txt").read_text(encoding="utf-8"))

    # α: recover the next LCG output and the AES key.
    alpha = data["α"]
    x6 = recover_lcg_next(ZZ(alpha["M"]), alpha["out"])
    k0 = hashlib.sha256(i2b(x6, 16)).digest()[:16]
    alpha_plain = gcm_decrypt(k0, alpha["Φ"])
    rsa_parts = [int.from_bytes(alpha_plain[i:i+16], "big") for i in range(0, 96, 16)]
    hn, hc = rsa_parts[:3], rsa_parts[3:]
    message_cube = crt_pairwise(hc, hn)
    message = integer_cube_root(message_cube)
    if message**3 != message_cube or any(pow(message, 3, n) != c for n, c in zip(hn, hc)):
        raise ValueError("Broadcast RSA reconstruction failed")
    s1 = i2b(message, 15)
    kw = hashlib.sha256(s1).digest()[:16]
    print("[+] alpha: LCG and broadcast RSA recovered", flush=True)

    # γ: Wiener RSA exposes the AES key protecting the reused-nonce GCM pair.
    gamma = json.loads(gcm_decrypt(kw, data["γ"]["Φ"]))
    nw, ew, wc = ZZ(gamma["nw"]), ZZ(gamma["ew"]), ZZ(gamma["wc"])
    dw = wiener_attack(nw, ew)
    gk_int = power_mod(wc, dw, nw)
    gk = i2b(gk_int, 16)
    print("[+] gamma: Wiener RSA recovered", flush=True)
    c1, c2 = bytes.fromhex(gamma["c1"]), bytes.fromhex(gamma["c2"])
    p1 = bytes.fromhex(gamma["p1"])
    p2_prefix = bytes(xor(xor(a, b), c) for a, b, c in zip(c1[:len(p1)], c2[:len(p1)], p1))
    lf = p2_prefix[:8]

    # δ: the smooth-order DH logarithm gives the key encrypting the LFSR payload.
    delta = json.loads(gcm_decrypt(b"\x00" * 16, data["δ"]["Φ"])) if False else None
    # δ is encrypted under kL, recovered from the GCM nonce-reuse leakage above.
    lfsr_state = recover_lfsr_state(lf)
    all_lfsr, _ = lfsr_bits(lfsr_state, (8 + 16) * 8)
    lfsr_stream = bits_to_bytes(all_lfsr)
    if lfsr_stream[:8] != lf:
        raise ValueError("LFSR prefix mismatch")
    kL = lfsr_stream[8:24]
    print("[+] reused GCM nonce and LFSR recovered kL", flush=True)

    delta_plain = json.loads(gcm_decrypt(kL, data["δ"]["Φ"]))
    dh_p, dh_g, dh_h = ZZ(delta_plain["ph_p"]), ZZ(delta_plain["ph_g"]), ZZ(delta_plain["ph_h"])
    px = discrete_log(Mod(dh_h, dh_p), Mod(dh_g, dh_p), ord=dh_p-1)
    kP = i2b(px, 16)
    ke = hashlib.sha256(kP).digest()[:16]
    print("[+] delta: smooth-order discrete log recovered", flush=True)

    # ζ: exploit the SHA-256 length extension bug to obtain kS.
    zeta = json.loads(gcm_decrypt(ke, data["ζ"]["Φ"]))
    sha_msg = bytes.fromhex(zeta["sha_msg"])
    extension = b"::uid=root::op=exec"
    kS = sha256_length_extension(zeta["sha_mac"], int(zeta["secret_len"]), sha_msg, extension)[:16]
    ke2 = hashlib.sha256(kS).digest()[:16]
    print("[+] zeta: SHA-256 length extension recovered kS", flush=True)

    # η: recover key_cc from the deterministic shuffle of the beacon log.
    cc_plain = gcm_decrypt(ke2, data["η"]["Φ"]).decode("utf-8")
    beacon_values = [int(x) for x in re.findall(r"BEACON #(\d+)", cc_plain)]
    if len(beacon_values) != 16:
        raise ValueError("Expected 16 beacon values in recovered log")
    shuffled_origins = list(range(24))
    random.Random(int(42)).shuffle(shuffled_origins)
    key_cc_buf = [None] * 16
    observed_index = 0
    for original_index in shuffled_origins:
        if original_index < 16:
            key_cc_buf[original_index] = beacon_values[observed_index]
            observed_index += 1
    key_cc = bytes(key_cc_buf)
    kcc = hashlib.sha256(key_cc).digest()[:16]
    print("[+] eta: deterministic beacon shuffle recovered key_cc", flush=True)

    # θ: the module intervals preserve key_rat in a named order.
    rat = json.loads(gcm_decrypt(kcc, data["θ"]["Φ"]))
    module_names = ["keylogger","screencap","filegrab","shellexec","clipboard","browser_stealer",
                    "credential_dump","network_scan","lateral_move","persistence","exfil","c2_rotate",
                    "av_evasion","process_inject","memory_scan","log_wipe"]
    modules_by_name = {module["name"]: module for module in rat["modules"]}
    key_rat = bytes(modules_by_name[name]["interval"] for name in module_names)
    krat = hashlib.sha256(key_rat).digest()[:16]
    print("[+] theta: module intervals recovered key_rat", flush=True)

    # ι and the biased ECDSA nonces reveal the secp256k1 signing key.
    sig_bundle = json.loads(gcm_decrypt(krat, data["ι"]["Φ"]))
    tx_bytes = gcm_decrypt(kS, {"N": sig_bundle["tx_nonce"], "C": sig_bundle["tx_ct"], "T": sig_bundle["tx_tag"]})
    signatures = []
    for offset in range(0, len(tx_bytes), 96):
        block = tx_bytes[offset:offset+96]
        signatures.append(tuple(ZZ(int.from_bytes(block[i:i+32], "big")) for i in (0,32,64)))
    secp_order = ZZ("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
    print("[+] iota: running small-nonce ECDSA lattice", flush=True)
    de = recover_ecdsa_key(signatures, secp_order, ZZ(1) << 128)
    kec = hashlib.sha256(i2b(de, 32)).digest()[:16]
    print("[+] iota: ECDSA key recovered", flush=True)

    # κ: Boneh-Durfee recovers the weak RSA plaintext that derives key_bd.
    bd_data = json.loads(gcm_decrypt(kec, data["κ"]["Φ"]))
    n_bd, e_bd, c_bd = ZZ(bd_data["n"]), ZZ(bd_data["e"]), ZZ(bd_data["c"])
    print("[+] kappa: running Boneh-Durfee lattice", flush=True)
    d_bd = boneh_durfee(n_bd, e_bd, delta=0.27, m=8)
    bd_msg = i2b(power_mod(c_bd, d_bd, n_bd), 16)
    key_bd = hashlib.sha256(bd_msg).digest()[:16]
    print("[+] kappa: weak RSA recovered", flush=True)

    # λ: the factor is 256 bits, but its unknown suffix is only 128 bits.
    # Split that suffix range into smaller intervals to keep each
    # Coppersmith lattice substantially smaller.
    ld = json.loads(gcm_decrypt(key_bd, data["λ"]["Φ"]))
    n_cop, p_top = ZZ(ld["n"]), ZZ(ld["p_top"])
    unknown_bits = int(ld["p_bits"]) - int(ld["known_bits"])
    p_base = p_top << unknown_bits
    R = PolynomialRing(Zmod(n_cop), names=("x",), implementation="NTL")
    x = R.gen()
    # p_base is a proven lower bound for p, so beta uses the actual factor
    # size lower bound instead of conservatively assuming a 255-bit prime.
    beta = RR(p_base).log() / RR(n_cop).log()
    epsilon = RR("0.01")
    # A little safety margin keeps X strictly inside the Coppersmith bound.
    window_bits = int(floor((beta**2 - epsilon) * n_cop.nbits() - RR("0.25")))
    if window_bits <= 0:
        raise ValueError("Coppersmith interval bound is not positive")
    window = ZZ(1) << window_bits
    window_count = (ZZ(1) << unknown_bits) // window
    print(f"[+] lambda: searching {window_count} windows of {window_bits} bits", flush=True)
    p_cop = None
    for index, offset in enumerate(range(0, 1 << unknown_bits, int(window))):
        if index % 8 == 0:
            print(f"[+] lambda: window {index + 1}/{window_count}", flush=True)
        f = x + (p_base + offset)
        roots = f.small_roots(X=window, beta=beta, epsilon=epsilon)
        for root in roots:
            low = ZZ(offset) + ZZ(root)
            if 0 <= low < (ZZ(1) << unknown_bits):
                candidate = p_base + low
                if n_cop % candidate == 0:
                    p_cop = candidate
                    break
        if p_cop is not None:
            break
    if p_cop is None:
        raise ValueError("Coppersmith windows did not recover the partially known prime")
    key_cop = hashlib.sha256(i2b(p_cop, int(ld["p_bits"]) // 8)).digest()[:16]
    print("[+] lambda: partially known prime recovered", flush=True)

    master = hashlib.sha256(kL + kP + kS + key_cc + key_rat + key_bd + key_cop).digest()
    flag = gcm_decrypt(master, data["Ω"])
    print(flag.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()
