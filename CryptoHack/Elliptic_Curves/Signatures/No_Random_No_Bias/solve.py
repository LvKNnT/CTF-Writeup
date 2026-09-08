from hashlib import sha1
from Crypto.Util.number import bytes_to_long, long_to_bytes
from ecdsa import ellipticcurve
from ecdsa.ecdsa import curve_256, generator_256, Public_key, Private_key
from random import randint
from sympy import mod_inverse
from sympy.ntheory.modular import crt

G = generator_256
q = G.order()

s1 = {'msg': 'I have hidden the secret flag as a point of an elliptic curve using my private key.', 'r': '0x91f66ac7557233b41b3044ab9daf0ad891a8ffcaf99820c3cd8a44fc709ed3ae', 's': '0x1dd0a378454692eb4ad68c86732404af3e73c6bf23a8ecc5449500fcab05208d'}
s2 = {'msg': 'The discrete logarithm problem is very hard to solve, so it will remain a secret forever.', 'r': '0xe8875e56b79956d446d24f06604b7705905edac466d5469f815547dea7a3171c', 's': '0x582ecf967e0e3acf5e3853dbe65a84ba59c3ec8a43951bcff08c64cb614023f8'}
s3 = {'msg': 'Good luck!', 'r': '0x566ce1db407edae4f32a20defc381f7efb63f712493c3106cf8e85f464351ca6', 's': '0x9e4304a36d2c83ef94e19a60fb98f659fa874bfb999712ceb58382e2ccda26ba'}

r1 = int(s1['r'], 16)
s1_s = int(s1['s'], 16)
h1 = bytes_to_long(sha1(s1['msg'].encode()).digest())
r2 = int(s2['r'], 16)
s2_s = int(s2['s'], 16)
h2 = bytes_to_long(sha1(s2['msg'].encode()).digest())
r3 = int(s3['r'], 16)
s3_s = int(s3['s'], 16)
h3 = bytes_to_long(sha1(s3['msg'].encode()).digest())

d_mod1 = (h1 - h2) * (s1_s - s2_s - 1) * mod_inverse(r1 - r2, q) % q
d_mod2 = (h2 - h3) * (s2_s - s3_s - 1) * mod_inverse(r2 - r3, q) % q
d_mod3 = (h3 - h1) * (s3_s - s1_s - 1) * mod_inverse(r3 - r1, q) % q
d, _ = crt([q, q, q], [d_mod1, d_mod2, d_mod3]) 
print("Private key:", d)

pubkey = Public_key(G, d*G)
print('\nPublic key:', (int(pubkey.point.x()), int(pubkey.point.y())), '\n')
assert pubkey.point.x() == 48780765048182146279105449292746800142985733726316629478905429239240156048277
assert pubkey.point.y() == 74172919609718191102228451394074168154654001177799772446328904575002795731796

Hidden_x = 16807196250009982482930925323199249441776811719221084165690521045921016398804
Hidden_y = 72892323560996016030675756815328265928288098939353836408589138718802282948311
Q = ellipticcurve.Point(curve_256, Hidden_x, Hidden_y)
flag_point = d*Q
print("Flag point:", (int(flag_point.x()), int(flag_point.y())))
flag_x = int(flag_point.x())
flag_bytes = long_to_bytes(flag_x)
print("Flag:", flag_bytes)
