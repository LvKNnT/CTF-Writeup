# Exact port of cipher.rs (the period-2 / general GOST-style cipher).
SBOX = [
 [0xC,0x4,0x6,0x2,0xA,0x5,0xB,0x9,0xE,0x8,0xD,0x7,0x0,0x3,0xF,0x1],
 [0x6,0x8,0x2,0x3,0x9,0xA,0x5,0xC,0x1,0xE,0x4,0x7,0xB,0xD,0x0,0xF],
 [0xB,0x3,0x5,0x8,0x2,0xF,0xA,0xD,0xE,0x1,0x7,0x4,0xC,0x9,0x6,0x0],
 [0xC,0x8,0x2,0x1,0xD,0x4,0xF,0x6,0x7,0x0,0xA,0x5,0x3,0xE,0x9,0xB],
 [0x7,0xF,0x5,0xA,0x8,0x1,0x6,0xD,0x0,0x9,0x3,0xE,0xB,0x4,0x2,0xC],
 [0x5,0xD,0xF,0x6,0x9,0x2,0xC,0xA,0xB,0x7,0x8,0x1,0x4,0x3,0xE,0x0],
 [0x8,0xE,0x2,0x5,0x6,0x9,0x1,0xC,0xF,0x4,0xB,0x0,0xD,0xA,0x3,0x7],
 [0x1,0x7,0xE,0xD,0x0,0x5,0x8,0x3,0x4,0xF,0xA,0x6,0x9,0xC,0xB,0x2],
]
# inverse sbox (per nibble)
ISBOX = [[0]*16 for _ in range(8)]
for t in range(8):
    for x in range(16):
        ISBOX[t][SBOX[t][x]] = x

MASK32 = 0xFFFFFFFF

def substitute_u32(value, table):
    out = 0
    for i in range(8):
        shift = 28 - 4*i
        nibble = (value >> shift) & 0xF
        out |= table[7 - i][nibble] << shift
    return out & MASK32

def rotl32(x, r):
    return ((x << r) | (x >> (32 - r))) & MASK32

def sub_u32(value):
    return substitute_u32(value, SBOX)

def f_round(lo, rk):
    # state_lo = ROL11(S(lo + rk)) ; returned XORed with hi by caller
    s = (lo + rk) & MASK32
    s = substitute_u32(s, SBOX)
    s = rotl32(s, 11)
    return s

class Ghost:
    def __init__(self, round_keys):
        assert len(round_keys) == 32
        self.rk = list(round_keys)

    def round_function(self, hi, lo, round_n, is_enc):
        s = (lo + self.rk[round_n]) & MASK32
        s = substitute_u32(s, SBOX)
        s = rotl32(s, 11)
        s ^= hi
        if (is_enc and round_n == 31) or ((not is_enc) and round_n == 0):
            return (s, lo)
        else:
            return (lo, s)

    def encrypt_block(self, block8):
        hi = int.from_bytes(block8[:4], 'big')
        lo = int.from_bytes(block8[4:], 'big')
        for r in range(32):
            hi, lo = self.round_function(hi, lo, r, True)
        return hi.to_bytes(4,'big') + lo.to_bytes(4,'big')

    def decrypt_block(self, block8):
        hi = int.from_bytes(block8[:4], 'big')
        lo = int.from_bytes(block8[4:], 'big')
        for r in reversed(range(32)):
            hi, lo = self.round_function(hi, lo, r, False)
        return hi.to_bytes(4,'big') + lo.to_bytes(4,'big')

    def encrypt(self, pt):
        return b''.join(self.encrypt_block(pt[i:i+8]) for i in range(0,len(pt),8))
    def decrypt(self, ct):
        return b''.join(self.decrypt_block(ct[i:i+8]) for i in range(0,len(ct),8))

def period2(k0, k1):
    return Ghost([k0 if r%2==0 else k1 for r in range(32)])

if __name__ == "__main__":
    import os, random
    # sanity: encrypt/decrypt inverse
    k0 = random.getrandbits(32); k1 = random.getrandbits(32)
    g = period2(k0,k1)
    pt = os.urandom(8)
    ct = g.encrypt_block(pt)
    assert g.decrypt_block(ct) == pt, "inverse failed"
    print("cipher self-inverse OK; k0=%08x k1=%08x" % (k0,k1))
