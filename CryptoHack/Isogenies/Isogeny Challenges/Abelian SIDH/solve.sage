from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad

proof.all(False)

# --- Parameters (copied from source) ---
q = 66755491218549620204451278063200785887258235588279474221852899550437797658031
l_a = 2
l_b = 3
e_a = 216
e_b = 137
p = (l_a^e_a)*(l_b^e_b)*q - 1

assert is_pseudoprime(p)
assert is_pseudoprime(q)

F2.<i> = GF(p^2, name="i", modulus=x^2 + 1)
E = EllipticCurve(F2, [1, 0])

assert E.order() == ((l_a^e_a)*(l_b^e_b)*q)^2

# --- Public parameters from output.txt ---
Gx = 284525705055227305209171433354262326583483353932890396374082376039620293167347284486476175866841636870352172611140798770638607860891148421274491414781769460579269366987499711492224975722383693724998945327430*i + 1505732117301446306244456647291108872440150309218670346804336845746049737306166624890419953190750991745319605357809802251161115415632644954176702934116791663302337496487008464465331505899884564177127436954255
Gy = 625472529935654036223921391438157288453365901129930947294363367235040059593079687415091508012127435124029308811603045594581554202553372496400288438224966890629676977438466598167329973052918856464699791832852*i + 47601474380995597168525750969588840445021207583064647146015202571081375996653285276671081590297360068195022075982179758981719629604575131347969613756306189238588058541679309930305808586991507704997154990697

G = E(Gx, Gy)

# --- The break ---
# gen_pubkey returns (phi, phi_hat), phi_hat(phi(G)).
# For ANY isogeny phi of degree l^e, the dual satisfies:
#     phi_hat . phi == [l^e]   (multiplication-by-degree endomorphism of E)
# So G_A = phi_hat_A(phi_A(G)) = l_a^e_a * G  and  G_B = l_b^e_b * G,
# completely independent of the randomly chosen secret kernel R = P + k*Q.
#
# Therefore the "shared secret" is publicly computable, with no secret
# isogeny walk required at all:
#     ss = phi_hat_A(phi_A(G_B)) = l_a^e_a * l_b^e_b * G

shared_secret = (l_a^e_a * l_b^e_b) * G

# --- Decrypt the flag exactly as encrypt_flag() does ---
key = SHA256.new(data=str(shared_secret).encode()).digest()[:128]

iv = bytes.fromhex("f81ce520adb3e49a834f711f8dbf5903")
ct = bytes.fromhex("2309ddcea639f3acf2503470ad44a33144afed4b8a76c06cca4eb0d01e2aa4a4bb76035f778b179421d59b5449786a994455b3a4638f4d58759be1a515dc950a")

cipher = AES.new(key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(ct), 16)

print(flag)
