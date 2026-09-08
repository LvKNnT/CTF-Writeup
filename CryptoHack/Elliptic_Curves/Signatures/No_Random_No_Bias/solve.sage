
from Crypto.Util.number import *
from hashlib import sha1

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
K = GF(p)
a = K(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
b = K(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
E = EllipticCurve(K, (a, b))
G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
E.set_order(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 * 0x1)


P = E(48780765048182146279105449292746800142985733726316629478905429239240156048277, 74172919609718191102228451394074168154654001177799772446328904575002795731796)


T = E(16807196250009982482930925323199249441776811719221084165690521045921016398804, 72892323560996016030675756815328265928288098939353836408589138718802282948311)


sig1 = {'msg': 'I have hidden the secret flag as a point of an elliptic curve using my private key.', 'r': '0x91f66ac7557233b41b3044ab9daf0ad891a8ffcaf99820c3cd8a44fc709ed3ae', 's': '0x1dd0a378454692eb4ad68c86732404af3e73c6bf23a8ecc5449500fcab05208d'}
sig2 = {'msg': 'The discrete logarithm problem is very hard to solve, so it will remain a secret forever.', 'r': '0xe8875e56b79956d446d24f06604b7705905edac466d5469f815547dea7a3171c', 's': '0x582ecf967e0e3acf5e3853dbe65a84ba59c3ec8a43951bcff08c64cb614023f8'}
sig3 = {'msg': 'Good luck!', 'r': '0x566ce1db407edae4f32a20defc381f7efb63f712493c3106cf8e85f464351ca6', 's': '0x9e4304a36d2c83ef94e19a60fb98f659fa874bfb999712ceb58382e2ccda26ba'}

r1 = int(sig1["r"], 16)
s1_inv = inverse(int(sig1["s"], 16), E.order())
r2 = int(sig2["r"], 16)
s2_inv = inverse(int(sig2["s"], 16), E.order())
r3 = int(sig3["r"], 16)
s3_inv = inverse(int(sig3["s"], 16), E.order())

msg1 = bytes_to_long(sha1(sig1["msg"].encode()).digest())
msg2 = bytes_to_long(sha1(sig2["msg"].encode()).digest())
msg3 = bytes_to_long(sha1(sig3["msg"].encode()).digest())


def hnp(a,t,B,p) : 
    
    assert len(a) == len(t)
    x = len(a)
    
    M = Matrix(QQ,x,x)
    for i in range(x) :
        M[i,i] = p
    M = M.stack(vector(a)).stack(vector(t))
    M = M.augment(vector([0]*x + [B/p] + [0])).augment(vector([0]*(x+1) + [B]))
    
    M = M.LLL()
    return M 

a = [r1*s1_inv, r2*s2_inv, r3*s3_inv]
t = [msg1*s1_inv, msg2*s2_inv, msg3*s3_inv] 
p = E.order()
B = 2^160
M = hnp(a,t,B,p)
print(M)
r1_inv = inverse(r1, E.order())
s1 = int(sig1["s"], 16)
 
for row in M:
    potential_nonce_1 = row[0]
    potential_priv_key = r1_inv * ((potential_nonce_1 * s1) - msg1) % E.order()

    if G * potential_priv_key == P:
        print('Found')
        pr = potential_priv_key
        break

# --- 4. RECOVER FLAG ---
# d = (s1 * k1 - z1) * r1^-1 mod n
d = int(pr)
n = E.order()
print(f"[+] Private Key d: {d}")

Hidden_x = 16807196250009982482930925323199249441776811719221084165690521045921016398804
Hidden_y = 72892323560996016030675756815328265928288098939353836408589138718802282948311

try:
    T = E(Hidden_x, Hidden_y)
    d_inv = inverse(d, n)
    Q = d_inv * T
    print("sybau")

    flag_x = int(Q.xy()[0])
    print(f"[+] Flag: {long_to_bytes(flag_x)}")
except Exception as e:
    print(f"[-] Point error: {e}")