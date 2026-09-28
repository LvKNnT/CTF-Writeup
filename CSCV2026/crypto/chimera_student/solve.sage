#!/usr/bin/env sage
"""Offline CHIMERA solver. Run: sage solve.sage [output_chimera.txt]

Requires SageMath, g++, GMP headers, and factor_chimera.cpp beside this file.
The helper is compiled in a temporary directory.

Relations annihilating the constant row and all challenge-bit rows also
annihilate token XOR challenge. Their attestation product differences
are multiples of N. Remove accidental factors shared with attestations,
which are units modulo N. A saturated integer kernel bounds the powers.

For r = 17^a mod M and s = N/r mod M, write p=r+M*k and q=s+M*l.
Then s*k+r*l = (N-r*s)/M mod M. The compiled helper solves this exact
2D lattice equation in the bounded box and checks the full product.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

M = ZZ(31721752939659896617792337171084495768312741523809821454149295955199893657462682088273)
G = 17
PBITS = 384
SAMPLE_BITS = 128


def remove_nonunits(candidate, values):
    """Remove factors shared with values known to be coprime to N."""
    for value in values:
        while True:
            shared = gcd(candidate, value)
            if shared == 1:
                break
            candidate //= shared
    return candidate


def recover_modulus(samples):
    count = len(samples)
    constraints = [[ZZ(1)] * count]
    constraints += [[(c >> j) & 1 for c, _ in samples]
                    for j in range(SAMPLE_BITS)]
    A = matrix(ZZ, constraints)
    # Clearing denominators of a rational kernel can miss the full integer
    # kernel and previously produced impractically large exponents.
    smith, U, V = A.smith_form(transformation=True)
    if U*A*V != smith:
        raise RuntimeError("invalid Smith-form transformation")
    rank = sum(smith[i, i] != 0 for i in range(min(A.dimensions())))
    if rank != SAMPLE_BITS + 1:
        raise RuntimeError("unexpected rank in the challenge-bit matrix")
    reduced = V[:, rank:].transpose().LLL()
    if reduced*A.transpose() != zero_matrix(ZZ, reduced.nrows(), A.nrows()):
        raise RuntimeError("invalid integer-kernel relations")
    values = [y for _, y in samples]
    common = ZZ(0)
    for idx, row in enumerate(reduced.rows(), 1):
        # Only the first nonzero difference needs full integer powers.
        if not common and sum(abs(x) for x in row) > 100000:
            continue
        positive = ZZ(1)
        negative = ZZ(1)
        for coeff, y in zip(row, values):
            if coeff == 0:
                continue
            term = power_mod(y, abs(coeff), common) if common else y**abs(coeff)
            if coeff > 0:
                positive *= term
                if common:
                    positive %= common
            else:
                negative *= term
                if common:
                    negative %= common
        common = gcd(common, abs(positive-negative))
        if not common:
            continue
        print("modulus gcd relation", idx, "->", common.nbits(), "bits", flush=True)
        # Avoid saturating the enormous first difference unnecessarily.
        if common.nbits() <= 8192:
            common = remove_nonunits(common, values)
            print("after removing nonunits:", common.nbits(), "bits", flush=True)
        if common.nbits() < 2*PBITS:
            raise RuntimeError("relation gcd is smaller than the expected modulus")
        if common.nbits() == 2*PBITS:
            if any(y >= common for y in values):
                raise RuntimeError("candidate modulus is smaller than an attestation")
            return common
    raise RuntimeError("relations did not isolate the expected 768-bit modulus")


def recover_factors(N):
    compiler = shutil.which("g++")
    if compiler is None:
        raise RuntimeError("g++ is required; on Ubuntu install g++ and libgmp-dev")
    source = Path(__file__).resolve().with_name("factor_chimera.cpp")
    if not source.is_file():
        raise RuntimeError("place factor_chimera.cpp beside solve.sage")
    order = ZZ(Mod(G, M).multiplicative_order())
    print("residue subgroup order:", order, flush=True)
    with tempfile.TemporaryDirectory(prefix="chimera-") as directory:
        executable = str(Path(directory) / "factor-chimera")
        subprocess.run([compiler, "-O3", "-std=c++17", str(source),
                        "-lgmpxx", "-lgmp", "-o", executable], check=True)
        result = subprocess.run([executable], input="%s %s %s\n" % (N, M, order),
                                text=True, stdout=subprocess.PIPE, check=True)
    factors = result.stdout.split()
    if len(factors) != 2:
        raise RuntimeError("unexpected output from the factor search")
    p, q = map(ZZ, factors)
    if p*q != N or p.nbits() != PBITS or q.nbits() != PBITS:
        raise RuntimeError("factor search returned invalid factors")
    if not p.is_prime() or not q.is_prime():
        raise RuntimeError("recovered factors are not prime")
    return p, q


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path,
                        default=Path(__file__).resolve().with_name("output_chimera.txt"))
    parser.add_argument("--modulus-only", "--gcd-only", action="store_true",
                        help="stop after recovering the exact modulus")
    args = parser.parse_args()
    with args.input.open() as f:
        data = json.load(f)
    if ZZ(data["base_c"]) != 3:
        raise ValueError("this solver expects attestation base 3")
    samples = [(ZZ(c), ZZ(y)) for c, y in data["attestations"]]
    if len(samples) <= SAMPLE_BITS + 1:
        raise ValueError("not enough attestation samples")
    if any(c < 0 or c >= 2**SAMPLE_BITS or y <= 0 for c, y in samples):
        raise ValueError("invalid challenge or attestation value")
    N = recover_modulus(samples)
    print("recovered N:", N, flush=True)
    if args.modulus_only:
        return
    p, q = recover_factors(N)
    e, ciphertext = ZZ(data["e"]), ZZ(data["flag_ct"])
    if not 0 <= ciphertext < N:
        raise ValueError("ciphertext is outside the recovered modulus")
    d = inverse_mod(e, (p-1)*(q-1))
    message = power_mod(ciphertext, d, N)
    if power_mod(message, e, N) != ciphertext:
        raise RuntimeError("RSA re-encryption check failed")
    plaintext = int(message).to_bytes(max(1, (message.nbits()+7)//8), "big")
    print("p:", p)
    print("q:", q)
    print("plaintext bytes:", repr(plaintext))
    try:
        print("plaintext:", plaintext.decode("utf-8"))
    except UnicodeDecodeError:
        print("plaintext hex:", plaintext.hex())


if __name__ == "__main__":
    main()
