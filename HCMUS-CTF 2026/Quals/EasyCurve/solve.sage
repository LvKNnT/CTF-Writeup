import hashlib
from Crypto.Cipher import AES

# Constants from output.txt
N = 2963165758250530878529883887579711437094064583945416055057163518787823793211522394720197072824707181434005194258484916736169182165947818454671493665435229813204218454322556006236596559086527793019066910609307711494187745179115361806670884871
P = 19513429963028943302877290751686852744024434094808337233097306550581712538079493637750812575487988877374804431737143112210692125971464957436957225949105667495060886687957981082918850339397699758625054925569241512441049373006285827359978453788601
j_iso = 691367025832336926039908637347030693212694748752413512283072061022794879984425544818894329913455616537101994223378133614569191085132158984069204073381660613069608033123234599092754502354281087391559470066974991587919176054051906096129156044379
ciphertext = bytes.fromhex('1771381726feb53a5db4f17a24ecbe0cbc5898d4695aaa008c75a260983ccfec939e5335fe0738500092aaa87d7adc37')
tag = bytes.fromhex('0709135537a34a8dbe8f88af039fa714')
nonce = bytes.fromhex('fd72910e5ad44b7715eacbc1c0229fcb')

# 1. Setup the field and polynomial ring
Fp = GF(P)
R.<S> = PolynomialRing(Fp)

# 2. Define the derived cubic polynomial
f = 16*S^3 + N*(j_iso - 768)*S^2 + 12288*N^2*S - 65536*N^3

# 3. Find the roots to get S = (p+q)^2
roots = f.roots()

p_plus_q = None
for root, multiplicity in roots:
    S_val = Integer(root)
    if S_val.is_perfect_power():
        p_plus_q = S_val.isqrt()
        break

if p_plus_q is None:
    print("Could not find a valid p+q.")
else:
    print(f"Recovered p+q = {p_plus_q}")

    # 4. Reconstruct the AES key and decrypt
    key = hashlib.sha256(str(p_plus_q).encode()).digest()
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    try:
        flag = cipher.decrypt_and_verify(ciphertext, tag)
        print("Flag:", flag.decode())
    except Exception as e:
        print("Decryption failed:", e)