#!/usr/bin/env sage
"""Recover the Baby Circuit AES key from the hosted two-proof oracle.

Usage:
    sage solve.sage HOST PORT
    sage solve.sage --host HOST --port PORT

With no target, decrypt the bundled TEST fixture using its local-only shortcut.
"""

import argparse
import hashlib
import json
import socket
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PUBLIC = HERE / "public"
sys.path.insert(0, str(PUBLIC))

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from sage.all import GF, PolynomialRing, QQ, ZZ, matrix, next_prime


def decrypt_local_test_session():
    """The direct key API exists only in the bundled TEST extension."""
    if not (PUBLIC / "hw_model.cpython-311-x86_64-linux-gnu.so").exists():
        raise SystemExit("The local hw_model extension is missing.")
    import hw_model
    import hsm_main

    session = hsm_main.Session()
    try:
        session.ensure()
        key = hw_model.session_key(session.h)
        ciphertext = bytes.fromhex(session.enc)
        return unpad(
            AES.new(key, AES.MODE_CBC, session.iv).decrypt(ciphertext),
            AES.block_size,
        )
    finally:
        session.close()


def extract_remainder(proof, selectors, p, n=64):
    """Return the numerator remainder at zeta and its challenge point."""
    evaluations = proof["evaluations"]
    zeta = int(proof["zeta"], 16)
    zh = (pow(zeta, n, p) - 1) % p
    if zh == 0:
        raise ValueError("Fiat-Shamir challenge unexpectedly landed on the domain")

    eval_poly = lambda poly: selectors_poly_eval(poly, zeta, p)
    a = int(evaluations["eval_a"], 16)
    b = int(evaluations["eval_b"], 16)
    c = int(evaluations["eval_c"], 16)
    z = int(evaluations["eval_z"], 16)
    zw = int(evaluations["eval_z_omega"], 16)
    t = int(evaluations["eval_t"], 16)

    gate = (
        eval_poly(selectors.q_M) * a * b
        + eval_poly(selectors.q_L) * a
        + eval_poly(selectors.q_R) * b
        + eval_poly(selectors.q_O) * c
        + eval_poly(selectors.q_C)
        + eval_poly(selectors.q_acc) * (zw - z - a)
    ) % p
    remainder_at_zeta = (gate - t * zh) % p

    return remainder_at_zeta, zeta


def lagrange_at_zeta(selectors, zeta, row, p, n=64):
    zh = (pow(zeta, n, p) - 1) % p
    root = pow(selectors.omega, row, p)
    return root * zh * pow((n * (zeta - root)) % p, -1, p) % p


def extract_row60_residual(proof, selectors, p, n=64, row=60):
    """Extract the sole unsatisfied E-only row from the quotient remainder."""
    remainder_at_zeta, zeta = extract_remainder(proof, selectors, p, n)
    return remainder_at_zeta * pow(lagrange_at_zeta(selectors, zeta, row, p, n), -1, p) % p


def selectors_poly_eval(poly, point, p):
    from plonk_engine import poly_eval

    return poly_eval(poly, point, p)


def derive_affine_leak(mds, rc, alpha1, alpha2, alpha3, p):
    """Write the row-60 residual as an affine function of the initial state.

    The manufacturing shear makes l*M^k's lane-0 coefficient zero for all
    1 <= k <= 24. Thus every x^5 partial-round term cancels from l*s[24].
    """
    leak = [0, alpha1 % p, (alpha1 * alpha3) % p, alpha2 % p]
    powers = [leak]
    for _ in range(24):
        prev = powers[-1]
        powers.append([
            sum(prev[i] * mds[i][j] for i in range(4)) % p
            for j in range(4)
        ])
    if any(powers[k][0] for k in range(1, 25)):
        raise ValueError("published shear does not cancel all partial-round S-box terms")

    linear = powers[24]
    constant = sum(
        sum(powers[23 - r][i] * rc[r][i] for i in range(4))
        for r in range(24)
    ) % p
    return linear, constant


def recover_w_from_e_only(observation, linear, constant, p):
    """The E-only residual is independent of load and linear in w."""
    n1, n2 = (int(v, 16) for v in observation["nonce"])
    residual = int(observation["row60_residual"], 16)
    if linear[0] != 0:
        raise ValueError("expected the shear leak to cancel the load lane")
    if linear[1] == 0:
        raise ValueError("row-60 leak does not depend on w for this session")
    return (residual - constant - linear[2] * n1 - linear[3] * n2) * pow(linear[1], -1, p) % p


def recover_load_from_aef(proof, selectors, p, mds, rc, alpha1, alpha2,
                          alpha3, w, nonce1, nonce2):
    """Isolate load^5 from the A+E+F proof's row-remainder scalar.

    The A fault zeros the first round's lane-0 S-box output. That cuts load
    out of the state entering the remaining partial rounds. F then zeros the
    four round-24 S-box outputs and the final shear output. Their fault-row
    residuals can therefore be predicted from public parameters, w and nonces;
    row 3 is left as the one unknown residual load^5.
    """
    # Recreate rounds 0..23 with the first S-box output forced to zero.
    s = [0, int(w), int(nonce1), int(nonce2)]
    for r in range(24):
        y = ([0] + s[1:]) if r == 0 else [pow(s[0], 5, p)] + s[1:]
        s = [
            (sum(mds[i][j] * y[j] for j in range(4)) + rc[r][i]) % p
            for i in range(4)
        ]

    # Faulted rows 22, 35, 49, 57 correspond to the four lane S-box products;
    # row 60 is the final published shear. The A fault cuts load from s[24].
    row_residuals = {
        22: pow(s[0], 5, p),
        35: pow(s[1], 5, p),
        49: pow(s[2], 5, p),
        57: pow(s[3], 5, p),
        60: (alpha1 * (s[1] + alpha3 * s[2]) + alpha2 * s[3]) % p,
    }
    remainder, zeta = extract_remainder(proof, selectors, p)
    known = sum(
        lagrange_at_zeta(selectors, zeta, row, p) * value
        for row, value in row_residuals.items()
    ) % p
    row3_lagrange = lagrange_at_zeta(selectors, zeta, 3, p)
    if row3_lagrange == 0:
        raise ValueError("row-3 Lagrange coefficient unexpectedly vanished")
    load5 = (remainder - known) * pow(row3_lagrange, -1, p) % p

    exponent = pow(5, -1, p - 1)
    load_value = pow(load5, exponent, p)
    if pow(load_value, 5, p) != load5:
        raise ValueError("could not take the fifth root of the recovered load")
    return load_value


def sparse_mul(a, b):
    out = {}
    for (ax, ay), av in a.items():
        for (bx, by), bv in b.items():
            key = (ax + bx, ay + by)
            out[key] = out.get(key, 0) + av * bv
    return {k: v for k, v in out.items() if v}


def recover_register_pair(load_value, coeffs, p, bits=54, min_m=5, max_m=7,
                          diagnostic=False):
    """Find the 54-bit roots of the published modular quadratic via LLL.

    For f(r1,r2)=0 mod p, use shifts p^(m-k) r1^i r2^j f^k with a
    triangular monomial basis. A sufficiently short reduced polynomial must
    vanish over ZZ at the bounded secret root. Modular resultants and CRT
    isolate the common integer roots.
    """
    A, B, C, D, E = (int(coeffs[k], 16) if isinstance(coeffs[k], str)
                     else int(coeffs[k]) for k in ("A", "B", "C", "D", "E"))
    X = 1 << bits
    Y = 1 << bits
    f = {
        (2, 0): 1,
        (1, 1): A,
        (0, 2): B,
        (1, 0): C,
        (0, 1): D,
        (0, 0): (E - int(load_value)) % p,
    }

    # Sage polynomial ring used only to solve the exact short relations.
    R = PolynomialRing(QQ, names=("r1", "r2"), order="lex")
    r1, r2 = R.gens()

    for m in range(min_m, max_m + 1):
        print("[+] building register lattice (m=%d)" % m, file=sys.stderr)
        monoms = sorted(
            ((a, b) for a in range(2 * m + 1)
             for b in range(2 * m + 1 - a)),
            key=lambda ab: (ab[0] + ab[1], ab[0]),
        )
        dim = len(monoms)
        col = {ab: i for i, ab in enumerate(monoms)}
        f_powers = [{(0, 0): 1}]
        for _ in range(m):
            f_powers.append(sparse_mul(f_powers[-1], f))

        shifts = []
        for a, b in monoms:
            k = a // 2
            i = a - 2 * k
            multiplier = p ** (m - k)
            row = [ZZ(0)] * dim
            for (fx, fy), value in f_powers[k].items():
                aa, bb = fx + i, fy + b
                if aa + bb > 2 * m:
                    continue
                row[col[(aa, bb)]] += ZZ(multiplier * value) * X**aa * Y**bb
            shifts.append(row)

        basis = matrix(ZZ, shifts)
        reduced = basis.LLL(delta=0.99, algorithm="NTL:LLL", fp="rr")
        short_polys = []
        seen = set()
        threshold = p ** (2 * m)
        for row in reduced.rows():
            norm2 = sum(c * c for c in row)
            if norm2 * dim >= threshold:
                continue
            terms = []
            signature = []
            for ab, idx in col.items():
                scale = X**ab[0] * Y**ab[1]
                value = row[idx] // scale
                if value:
                    terms.append((value, ab[0], ab[1]))
                    signature.append((int(value), ab[0], ab[1]))
            sig = tuple(signature)
            if sig in seen or not terms:
                continue
            seen.add(sig)
            poly = sum(QQ(value) * r1**a * r2**b for value, a, b in terms)
            short_polys.append(poly)

        print("[+] %d exact-root relations from LLL" % len(short_polys), file=sys.stderr)
        if diagnostic:
            return short_polys
        if len(short_polys) < 2:
            continue

        # Intersect resultants over three ~28-bit primes. Sage's Singular
        # resultant backend supports prime fields below 2^29; CRT lifts the
        # roots past the 54-bit register bounds without factoring a huge
        # integer resultant over ZZ.
        primes = []
        q = int(next_prime(1 << 28))
        for _ in range(3):
            primes.append(q)
            q = int(next_prime(q + 1000))

        def bounded_crt(old_values, old_modulus, new_residues, modulus, bound):
            combined_modulus = old_modulus * modulus
            inv = pow(old_modulus, -1, modulus)
            out = set()
            for old in old_values:
                for residue in new_residues:
                    value = (old + old_modulus * (((residue - old) * inv) % modulus)) % combined_modulus
                    if 0 <= value < bound:
                        out.add(value)
            return combined_modulus, sorted(out)

        x_candidates = [0]
        x_modulus = 1
        for q in primes:
            Fq = GF(q)
            Rq = PolynomialRing(Fq, names=("x", "y"), order="lex")
            xq, yq = Rq.gens()
            modular = []
            for poly in short_polys[:8]:
                value = Rq.zero()
                for (a, b), coefficient in poly.dict().items():
                    value += Fq(int(coefficient) % q) * xq**a * yq**b
                modular.append(value)

            Rx = PolynomialRing(Fq, "X")
            common = None
            for i in range(1, len(modular)):
                resultant = modular[0].resultant(modular[i], yq)
                if resultant == 0:
                    continue
                coeffs = [resultant.monomial_coefficient(xq**d)
                          for d in range(resultant.degree(xq) + 1)]
                resultant_x = Rx(coeffs)
                common = resultant_x if common is None else common.gcd(resultant_x)
            if common is None or common.degree() <= 0:
                x_candidates = []
                break
            residues = [int(root) for root, _ in common.roots()]
            x_modulus, x_candidates = bounded_crt(
                x_candidates, x_modulus, residues, q, X
            )
            if not x_candidates:
                break

        verified = []
        for x in x_candidates:
            y_candidates = [0]
            y_modulus = 1
            for q in primes:
                Fq = GF(q)
                Ry = PolynomialRing(Fq, "Y")
                Yq = Ry.gen()
                common_y = None
                for poly in short_polys[:12]:
                    value = Ry.zero()
                    for (a, b), coefficient in poly.dict().items():
                        value += Fq(int(coefficient) % q) * Fq(x % q)**a * Yq**b
                    common_y = value if common_y is None else common_y.gcd(value)
                if common_y is None or common_y.degree() <= 0:
                    y_candidates = []
                    break
                residues = [int(root) for root, _ in common_y.roots()]
                y_modulus, y_candidates = bounded_crt(
                    y_candidates, y_modulus, residues, q, Y
                )
                if not y_candidates:
                    break
            for y in y_candidates:
                value = (x*x + A*x*y + B*y*y + C*x + D*y + E - load_value) % p
                if value == 0:
                    verified.append((x, y))
        if verified:
            return sorted(set(verified))

    raise RuntimeError(
        "could not isolate the 54-bit load-register roots; increase max_m or inspect the oracle data"
    )


def decrypt_candidates(w, pairs, iv_hex, ciphertext_hex):
    iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    results = []
    for r1, r2 in pairs:
        key = hashlib.sha256(
            int(w).to_bytes(32, "big")
            + int(r1).to_bytes(32, "big")
            + int(r2).to_bytes(32, "big")
        ).digest()
        raw = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
        try:
            plaintext = unpad(raw, AES.block_size)
        except ValueError:
            continue
        results.append({"r1": r1, "r2": r2, "key": key.hex(), "plaintext": plaintext})
    return results


def remote_solve(host, port, timeout=300):
    """Use one E-only and one A+E+F proof, then recover/decrypt."""
    import plonk_engine as pe

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        reader = sock.makefile("rb")
        writer = sock.makefile("wb")

        banner = json.loads(reader.readline().decode())
        writer.write(b'{"action":"get_hardware_specs"}\n')
        writer.flush()
        specs = json.loads(reader.readline().decode())
        if specs.get("status") != "success":
            raise RuntimeError("get_hardware_specs failed: " + repr(specs))

        params = specs["session_parameters"]
        p = int(params["field_prime"], 16)
        mds = [[int(x, 16) for x in row] for row in specs["poseidon_mds"]]
        rc = [[int(x, 16) for x in row] for row in specs["round_constants"]]
        alpha1 = int(params["shear_alpha1"], 16)
        alpha2 = int(params["shear_alpha2"], 16)
        alpha3 = int(params["shear_alpha3"], 16)
        selectors = pe.CircuitSelectors(mds, rc[0], alpha1, alpha2, alpha3, p)
        linear, constant = derive_affine_leak(mds, rc, alpha1, alpha2, alpha3, p)

        # Reuse the same chosen state. E-only reveals w; A+E+F isolates
        # load^5 after stage A cuts load out of the later Poseidon rounds.
        nonce1, nonce2 = 0x1234, 0x5678
        observations = []
        aef_proof = None
        for freq in (95, 112):
            req = {
                "action": "prove",
                "public_nonce": hex(nonce1),
                "public_nonce2": hex(nonce2),
                "core_voltage_mv": int(1200),
                "clock_freq_mhz": int(freq),
            }
            writer.write((json.dumps(req) + "\n").encode())
            writer.flush()
            result = json.loads(reader.readline().decode())
            if result.get("status") != "success":
                raise RuntimeError("prove failed: " + repr(result))
            proof = result["proof"]
            if freq == 95:
                observations.append({
                    "nonce": [hex(nonce1), hex(nonce2)],
                    "public_hash": proof["public_hash"],
                    "row60_residual": hex(extract_row60_residual(proof, selectors, p)),
                })
            else:
                aef_proof = proof

    w = recover_w_from_e_only(observations[0], linear, constant, p)
    load_value = recover_load_from_aef(
        aef_proof, selectors, p, mds, rc, alpha1, alpha2, alpha3,
        w, nonce1, nonce2,
    )
    import plonk_engine as pe
    if pe.poseidon_hash([load_value, w, nonce1, nonce2], rc, mds, p) != int(observations[0]["public_hash"], 16):
        raise ValueError("recovered load/w fail the intact E-only Poseidon hash check")
    pairs = recover_register_pair(load_value, params["load_coeffs"], p)
    decrypted = decrypt_candidates(w, pairs, specs["iv"], specs["encrypted_flag"])
    if not decrypted:
        raise RuntimeError("register candidates did not decrypt with valid PKCS#7 padding")

    return {
        "banner": banner,
        "recovered_load": hex(load_value),
        "recovered_w": hex(w),
        "register_candidates": [
            {"r1": hex(item["r1"]), "r2": hex(item["r2"]), "aes_key": item["key"]}
            for item in decrypted
        ],
        "decrypted_flag": decrypted[0]["plaintext"].decode("utf-8", errors="replace"),
        "query_budget_used": int(2),
    }


def main():
    parser = argparse.ArgumentParser(description="Recover the Baby Circuit remote AES key")
    parser.add_argument("target_host", nargs="?")
    parser.add_argument("target_port", nargs="?", type=int)
    parser.add_argument("--host", dest="host_opt")
    parser.add_argument("--port", dest="port_opt", type=int)
    parser.add_argument("--timeout", type=float, default=300)
    args = parser.parse_args()

    host = args.host_opt or args.target_host
    port = args.port_opt or args.target_port
    if host is None and port is None:
        print(decrypt_local_test_session().decode("utf-8"))
        return
    if host is None or port is None:
        parser.error("provide both HOST and PORT")

    try:
        result = remote_solve(host, port, args.timeout)
    except (OSError, ValueError, RuntimeError, KeyError, json.JSONDecodeError) as exc:
        raise SystemExit("remote solve failed: %s" % exc)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
