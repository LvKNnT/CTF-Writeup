# CryptoHack - Isogeny Challenges - Andre Encoding
#
# Andre encodes each flag byte b (1..255) as the *degree* of a secret
# isogeny: the kernel generator is built with cofactor (p+1)/(2^64*b),
# giving a kernel point of exact order 2^64*b. Only phi(P), phi(Q) are
# leaked (no explicit codomain curve) - but two points on a short
# Weierstrass curve pin down its coefficients directly, since
# y^2 = x^3 + A*x + B is linear in (A, B).
#
# Weil-pairing functoriality: for an isogeny phi and P, Q of order N,
#   e_N(phi(P), phi(Q)) = e_N(P, Q)^deg(phi).
# N = p+1 = 37 * 2^64 * lcm(1..255) has every prime factor <= 255, so
# this is a fully smooth discrete log - Pohlig-Hellman recovers
# deg(phi) = 2^64*b exactly (and hence b) instantly, for every entry.

import json
from sage.groups.generic import discrete_log

proof.all(False)

p = 37 * 2**64 * lcm(range(1, 256)) - 1
F = GF((p, 2), name="i", modulus=[1, 0, 1])
i = F.gen()
E = EllipticCurve(F, [0, 1])
N = p + 1
E.set_order(N**2)

P = E(2754452008418475544762931777380298061286322242088097042789979017337032668335152047250270118628626846112409632316814344852346179989*i + 300888031019145372993855450123312195268855753102882163072967372426589237335996165853668912727448513477444811191182550244111536735,
      4048396253042221946332182039831591283289177370092736377609511682595711744157657185583897171948127827836521892887941707373829426385*i + 5574313210012278375687658199880462698154719575075630281638825753946911987283962578905520742770486366773314976292767579688991668535)
Q = E(1914292834750542008365772941838940247194316211832948370075234167086803005671626788818592170824160266813720050022811399854833864570*i + 675917976944321956275103708696442108160242821688340828072457829850507425923003867371226253254729899087222613984510532839645132037,
      1353413969699500553835259943514301405386193613479830974260135363453012387178560466458631824224103775101292443946360403995987929735*i + 2642848780435012471695812611372313188888541702956899224702856112971832879700145426992696527731460150858414996112482220450878252755)

zeta = P.weil_pairing(Q, N)

# N = p+1 is smooth by construction: every prime factor is <= 255 (the
# two extra factors just bump the exponents of 2 and 37), so Sage's
# internal factor() call inside discrete_log() is effectively instant.


def parse_point(d):
    x = F(d["x"][0]) + F(d["x"][1]) * i
    y = F(d["y"][0]) + F(d["y"][1]) * i
    return x, y


def codomain_from_points(pt1, pt2):
    x1, y1 = pt1
    x2, y2 = pt2
    A = ((y1**2 - x1**3) - (y2**2 - x2**3)) / (x1 - x2)
    B = (y1**2 - x1**3) - A * x1
    return EllipticCurve(F, [A, B])


with open("output_6e30f9b5a6cd1356d485b369927bb106.txt") as f:
    ct = json.load(f)

flag_bytes = []
for entry in ct:
    Px, Py = parse_point(entry["P"])
    Qx, Qy = parse_point(entry["Q"])
    E_prime = codomain_from_points((Px, Py), (Qx, Qy))
    E_prime.set_order(N**2)
    P_prime = E_prime(Px, Py)
    Q_prime = E_prime(Qx, Qy)

    zeta_prime = P_prime.weil_pairing(Q_prime, N)
    k = discrete_log(zeta_prime, zeta, ord=N, operation="*")

    assert k % 2**64 == 0
    flag_bytes.append(k // 2**64)

flag = bytes(flag_bytes)
print(flag)
