from sage.all import *
from pwn import *
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256
from collections import namedtuple
from itertools import product

# --- CONFIGURATION ---
HOST = "socket.cryptohack.org"
PORT = 13419

# --- CONSTANTS (NIST P-256) ---
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b_original = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
G_x = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
G_y = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

# Define the standard curve for verification later
E_real = EllipticCurve(GF(p), [a, b_original])
G_real = E_real(G_x, G_y)

Point = namedtuple("Point", "x y")

# --- PRE-COMPUTED INVALID CURVES ---
# These are the (b, point_coords, order) tuples found in your analysis
invalid_points = [
    (1, (42175002054995005456032054847634109837867303662168681301823775328618621167257, 6288996052773274040412201979379734305561094315771238104660729610235490947637), 30203), 
    (6, (6916521694035682658992053075537445565363624352836952220952602038623371916311, 115744457910252132470609452006147133035446993203577266408387470384916086810576), 102001), 
    (8, (77177801688308590375281554339899397417008060715610710567469335543154535886705, 56482272201767764731237538221641643594417345014338560713897142910862902169184), 81173), 
    (9, (47034223721829461168018756183871790769531391997619306789768234976326643247188, 36690069098527171645302352091156608424561426366188813858864489931430425383110), 72337), 
    (9, (75867611241594963079296923992435306339863773743108034424194673499749692866234, 113386585066735986822606642693176073228481019212119301188621728278163800568548), 119591), 
    (11, (19586860274784579655299587649139369412746127963221097383745638856655651898653, 23506756512908370884843826409707591477075649717818438083240617620152533296415), 19423), 
    (12, (10284201017848954876928008678653247877572280857921112946804946132993725175179, 40420569947068244273309851366163691484564738277857776362688595870303603587354), 52183), 
    (21, (58893411339232717342928636766596153449829176933471364985984689019374288055282, 88967594578819727566524853729748425661839637170999623086359876721048301159595), 33493), 
    (44, (110493461217465614468627623232377433409210065126508400219960363592442096726843, 55122348430005210628102102776322553271812402494266245356568909691203567141037), 40169), 
    (45, (35938554177401964069979911595078887825898257087923837623686733269582908209128, 11524366179381991622832862533357684466096661348359806791553910444715556523854), 48271), 
    (56, (56761570687336245374057625531084333464888137771292682611740289890578963534878, 33450370200870181145296473112712061026862769454952910310746596602882805839690), 67679), 
    (66, (43810882600301584935214199838313271322146173207288006422267895018035800361127, 44405842419998416758345573858274384725705150184374927168935702777557358552841), 49597), 
    (73, (69815731950837116865486749513863186648302933375407100095031596454884845743692, 94459750075954258816372844475402716662904459615185301469096341198063906889743), 126421), 
    (76, (26235900583225356520135066868962606396134152478202309378665848781557925143560, 55657970105128320732848413162137654823706304262160141309209853597072001074910), 85531), 
    (91, (21180251250242349014208338047366392797219577182480583290292421353404602997473, 37851261500832061839129503770403284127655480750967230036644455606426287614036), 21379), 
    (92, (45376149881473028048370059872608836315356847508569955273199669704191342458484, 3875078093375110800492042110536859108223885838603671789480427323474807245366), 111217), 
    (93, (104404686430647022268382044928462370201938211524330387976602658007918887654500, 102264535239061459146382273757898757218836699584086892982149187675342121406119), 39119)
]

def decrypt_aes(key, iv, ct):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        return cipher.decrypt(ct)
    except:
        return b""

def main():
    io = remote(HOST, PORT)

    # --- STEP 1: INITIAL HANDSHAKE & DATA GATHERING ---
    io.recvuntil(b"agreement :\n")
    
    # Parse Client Public Key (Ephemeral) - WE NEED THIS FOR FINAL DECRYPTION
    line = io.recvline().strip().split(b" : ")[1]
    # Format: Point(x=..., y=...)
    # Using python eval is a bit dirty but works for this specific namedtuple output
    client_pub_raw = eval(line, {"Point": Point}) 
    Q_client_ephemeral = E_real(client_pub_raw.x, client_pub_raw.y)

    # Parse Server Public Key (Static) - WE NEED THIS TO VERIFY 's'
    line = io.recvline().strip().split(b" : ")[1]
    server_pub_raw = eval(line, {"Point": Point})
    P_server = E_real(server_pub_raw.x, server_pub_raw.y)

    # Parse Encrypted Flag
    enc_flag_hex = io.recvline().strip().split(b" : ")[1].decode()
    iv_flag = bytes.fromhex(enc_flag_hex[:32])
    ct_flag = bytes.fromhex(enc_flag_hex[32:])

    print(f"[+] Target P_server: {P_server}")
    print(f"[+] Client Ephemeral: {Q_client_ephemeral}")
    print(f"[+] Encrypted Flag: {enc_flag_hex}")

    # --- STEP 2: INVALID CURVE ATTACK ---
    remainders = []
    moduli = []

    print("\n[+] Starting Invalid Curve Attack...")
    
    for idx, (b_val, (Qx, Qy), order_Q) in enumerate(invalid_points):
        # Create the weak curve locally to handle point math
        E_weak = EllipticCurve(GF(p), [a, b_val])
        Q = E_weak(Qx, Qy)

        # Send invalid point to server
        req = {
            "option": "start_key_exchange",
            "ciphersuite": "ECDHE_P256_WITH_AES_128",
            "Qx": hex(Qx)[2:],
            "Qy": hex(Qy)[2:]
        }
        io.sendline(json.dumps(req).encode())
        io.recvline() # Consume response

        # Get test message encrypted with shared secret
        req = {"option": "get_test_message"}
        io.sendline(json.dumps(req).encode())
        resp = json.loads(io.recvline())
        
        test_ct_hex = resp["msg"]
        iv_test = bytes.fromhex(test_ct_hex[:32])
        ct_test = bytes.fromhex(test_ct_hex[32:])

        # Brute force the small order locally
        # We look for k such that AES_decrypt(k*Q) works
        # Optimization: We don't need to decrypt fully, just generate the points
        
        found_d = None
        
        # Generator for points in the subgroup. 
        # Since order is small (~16-17 bits), we can iterate fast.
        curr_P = Q # This is 1*Q
        for d in range(1, order_Q + 1):
            # Check if this d is the secret
            # Key derivation: sha256(str(x))[:16]
            shared_x = curr_P[0]
            key = sha256(str(shared_x).encode()).digest()[:16]
            
            # Try decrypting just the first block to see if it makes sense
            # Or just check known plaintext "SERVER_TEST_MESSAGE"
            pt = decrypt_aes(key, iv_test, ct_test)
            if b"SERVER_TEST_MESSAGE" in pt:
                found_d = d
                break
            
            # Next point
            curr_P += Q
        
        if found_d:
            print(f"    [{idx+1}/{len(invalid_points)}] Found remainder: {found_d} (mod {order_Q})")
            remainders.append(found_d)
            moduli.append(order_Q)
        else:
            print(f"    [{idx+1}/{len(invalid_points)}] Failed to find remainder for order {order_Q}")
            exit(1)

    # --- STEP 3: CRT RECOVERY WITH SIGN BRUTE-FORCE ---
    print("\n[+] Solving for 's' using CRT and sign flipping...")
    
    # We found d such that s == ±d (mod n). 
    # Because x-coordinate is symmetric for ±y, we don't know the sign.
    # We try all 2^k combinations.
    
    found_s = None
    
    # Pre-calculate CRT coefficients to speed up inside loop? 
    # Sage's CRT is fast enough for 17 moduli.
    
    for signs in product([1, -1], repeat=len(moduli)):
        current_rems = [(signs[i] * remainders[i]) % moduli[i] for i in range(len(moduli))]
        
        try:
            candidate_s = CRT(current_rems, moduli)
        except ValueError:
            continue # Moduli conflict (shouldn't happen here)

        # Check if valid private key
        if candidate_s.bit_length() > 256: 
            continue
            
        # Verify against the REAL server public key
        # s * G_real == P_server
        if candidate_s * G_real == P_server:
            found_s = candidate_s
            print(f"[+] FOUND SECRET KEY s: {found_s}")
            break
            
    if not found_s:
        print("[-] Failed to recover s. Check inputs.")
        exit(1)

    # --- STEP 4: DECRYPT THE FLAG ---
    print("\n[+] Decrypting Flag...")
    
    # Calculate shared secret for the initial captured session
    # S = s * Q_client_ephemeral
    shared_point = found_s * Q_client_ephemeral
    
    # Derive key
    shared_key = sha256(str(shared_point[0]).encode()).digest()[:16]
    
    # Decrypt
    cipher = AES.new(shared_key, AES.MODE_CBC, iv_flag)
    try:
        plaintext = unpad(cipher.decrypt(ct_flag), 16)
        print(f"\n[SUCCESS] FLAG: {plaintext.decode()}")
    except Exception as e:
        print(f"[-] Decryption error: {e}")
        print(f"Raw decrypted: {cipher.decrypt(ct_flag)}")

if __name__ == "__main__":
    main()