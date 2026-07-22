import hashlib

from Crypto.Cipher import AES

FLAG = b"HCMUS-CTF{??}"


def generate_challenge():
    p = random_prime(2**400 - 1, lbound=2**399, proof=False)
    q = random_prime(2**400 - 1, lbound=2**399, proof=False)
    N = p * q

    k = 1
    A = p**k 
    B = q**k

    P = random_prime(2**812)
    Fp = GF(P, proof=False)

    A_Fp = Fp(A)
    B_Fp = Fp(B)

    E = EllipticCurve(Fp, [0, B_Fp - A_Fp, 0, -A_Fp * B_Fp, 0])
    iso = E.isogeny(E(0, 0))
    j_iso = iso.codomain().j_invariant()

    key = hashlib.sha256(str(p + q).encode()).digest()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(FLAG)

    print(f"N = {N}")
    print(f"P = {P}")
    print(f"j_iso = {j_iso}")
    print(f"ciphertext = bytes.fromhex('{ciphertext.hex()}')")
    print(f"tag = bytes.fromhex('{tag.hex()}')")
    print(f"nonce = bytes.fromhex('{cipher.nonce.hex()}')")


generate_challenge()
