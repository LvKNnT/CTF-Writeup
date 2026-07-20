#!/usr/bin/env sage
# (1) factor the main modulus q to see the RNS prime pattern
# (2) try to obtain q_aux from OpenFHE directly (if the python package is importable)
import json
data = json.load(open("data.json"))
q  = Integer(data["q"])
q0 = Integer(data["q0"])

print("==== main modulus factorization ====")
F = list(factor(q))
print("q factors:", F)
primes = [p for p, _ in F]
print("q0 given :", q0, " is prime:", q0.is_prime())
for p in primes:
    print("  prime", p, " nbits", p.nbits(), " mod64=", p % 64, " mod16=", p % 16)
print("product check:", prod(primes) == q)

print("\n==== try OpenFHE for q_aux (ring dim 8) ====")
try:
    from openfhe import CCParamsBFVRNS, GenCryptoContext, PKE, KEYSWITCH, LEVELEDSHE, HEStd_NotSet
    def build(ringdim):
        p = CCParamsBFVRNS()
        p.SetPlaintextModulus(65537)
        p.SetRingDim(ringdim)
        p.SetBatchSize(ringdim)
        p.SetSecurityLevel(HEStd_NotSet)
        p.SetMultiplicativeDepth(3)
        cc = GenCryptoContext(p)
        cc.Enable(PKE); cc.Enable(KEYSWITCH); cc.Enable(LEVELEDSHE)
        return cc
    for rd in (32, 8):
        cc = build(rd)
        # try several accessors that openfhe-python may expose
        modv = None
        for attr in ("GetModulus",):
            if hasattr(cc, attr):
                try:
                    modv = getattr(cc, attr)()
                except Exception as ex:
                    print("  ", attr, "failed:", ex)
        print("ringdim", rd, "GetModulus ->", modv)
        print("  dir(cc) sample:", [a for a in dir(cc) if "odul" in a or "aram" in a.lower()])
except Exception as ex:
    print("openfhe import/use failed:", repr(ex))
    print("=> we'll reconstruct q_aux another way; that's fine.")
