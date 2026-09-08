from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import json
from sage.all import *

# --- Cấu hình ---
HOST = 'localhost'
PORT = 13419

# Các tham số của đường cong thật (P-256) để tính toán bước cuối
p_real = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a_real = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b_real = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

# Danh sách tuple (b, point, order) bạn đã tìm được
# Lưu ý: point là tuple (x, y)
# (b, point, order)
tup = [(1, (42175002054995005456032054847634109837867303662168681301823775328618621167257, 6288996052773274040412201979379734305561094315771238104660729610235490947637, 1), 30203), (6, (6916521694035682658992053075537445565363624352836952220952602038623371916311, 115744457910252132470609452006147133035446993203577266408387470384916086810576, 1), 102001), (8, (77177801688308590375281554339899397417008060715610710567469335543154535886705, 56482272201767764731237538221641643594417345014338560713897142910862902169184, 1), 81173), (9, (47034223721829461168018756183871790769531391997619306789768234976326643247188, 36690069098527171645302352091156608424561426366188813858864489931430425383110, 1), 72337), (9, (75867611241594963079296923992435306339863773743108034424194673499749692866234, 113386585066735986822606642693176073228481019212119301188621728278163800568548, 1), 119591), (11, (19586860274784579655299587649139369412746127963221097383745638856655651898653, 23506756512908370884843826409707591477075649717818438083240617620152533296415, 1), 19423), (12, (10284201017848954876928008678653247877572280857921112946804946132993725175179, 40420569947068244273309851366163691484564738277857776362688595870303603587354, 1), 52183), (21, (58893411339232717342928636766596153449829176933471364985984689019374288055282, 88967594578819727566524853729748425661839637170999623086359876721048301159595, 1), 33493), (44, (110493461217465614468627623232377433409210065126508400219960363592442096726843, 55122348430005210628102102776322553271812402494266245356568909691203567141037, 1), 40169), (45, (35938554177401964069979911595078887825898257087923837623686733269582908209128, 11524366179381991622832862533357684466096661348359806791553910444715556523854, 1), 48271), (56, (56761570687336245374057625531084333464888137771292682611740289890578963534878, 33450370200870181145296473112712061026862769454952910310746596602882805839690, 1), 67679), (66, (43810882600301584935214199838313271322146173207288006422267895018035800361127, 44405842419998416758345573858274384725705150184374927168935702777557358552841, 1), 49597), (73, (69815731950837116865486749513863186648302933375407100095031596454884845743692, 94459750075954258816372844475402716662904459615185301469096341198063906889743, 1), 126421), (76, (26235900583225356520135066868962606396134152478202309378665848781557925143560, 55657970105128320732848413162137654823706304262160141309209853597072001074910, 1), 85531), (91, (21180251250242349014208338047366392797219577182480583290292421353404602997473, 37851261500832061839129503770403284127655480750967230036644455606426287614036, 1), 21379), (92, (45376149881473028048370059872608836315356847508569955273199669704191342458484, 3875078093375110800492042110536859108223885838603671789480427323474807245366, 1), 111217), (93, (104404686430647022268382044928462370201938211524330387976602658007918887654500, 102264535239061459146382273757898757218836699584086892982149187675342121406119, 1), 39119)]

def solve():
    io = remote(HOST, PORT)
    
    # 1. Nhận thông tin ban đầu (để lấy Public Key của Client và Encrypted Flag)
    io.recvuntil(b"client->server : ")
    client_pub_str = io.recvline().strip().decode()
    # Parse Point Client
    client_pub_str = client_pub_str.replace("Point(x=", "").replace(" y=", "").replace(")", "")
    cp_x, cp_y = map(int, client_pub_str.split(","))
    
    io.recvuntil(b"server->client : ") # Skip
    io.recvline() 
    io.recvuntil(b"server->client : ")
    encrypted_flag_hex = io.recvline().strip().decode()
    print(f"[*] Encrypted Flag: {encrypted_flag_hex}")
    
    residues = []
    moduli = []
    
    print(f"[*] Starting Attack with {len(tup)} invalid curves...")

    for i, (b_val, point_coords, order_val) in enumerate(tup):
        # Tạo đường cong invalid (chỉ để tính toán brute force cục bộ)
        E_invalid = EllipticCurve(GF(p_real), [a_real, b_val])
        P_invalid = E_invalid(point_coords)
        
        # Gửi Public Key độc hại (nằm trên đường cong invalid)
        payload = {
            "option": "start_key_exchange",
            "Qx": hex(int(point_coords[0])),
            "Qy": hex(int(point_coords[1])),
            "ciphersuite": "ECDHE_P256_WITH_AES_128"
        }
        
        io.sendline(json.dumps(payload).encode())
        
        # Đọc phản hồi "Key exchange proceeded successfully"
        try:
            resp_line = io.recvline().decode()
            resp = json.loads(resp_line)
        except:
            print(f"[-] Error reading response at curve index {i}")
            continue

        if "msg" in resp and "successfully" in resp["msg"]:
            # Yêu cầu tin nhắn test để kiểm tra tính đúng đắn của shared secret
            io.sendline(json.dumps({"option": "get_test_message"}).encode())
            test_resp = json.loads(io.recvline().decode())
            enc_test = bytes.fromhex(test_resp["msg"])
            
            # Brute force DLP trong nhóm nhỏ (order ~ 16 bit => rất nhanh)
            found = False
            
            # Tính toán trước IV và Ciphertext của test message
            test_iv = enc_test[:16]
            test_ct = enc_test[16:]
            
            # Duyệt k từ 1 đến order_val
            for k in range(1, order_val + 1):
                # Giả sử shared secret là k * P_invalid
                # Lưu ý: Server dùng double_and_add, nên kết quả vẫn đúng trên đường cong invalid
                S_guess = k * P_invalid
                
                # Derive Key theo logic của server: sha256(str(S.x))
                # Phải ép kiểu int() để tránh lỗi format của Sage Element
                key_guess = hashlib.sha256(str(int(S_guess[0])).encode()).digest()[:16]
                
                cipher = AES.new(key_guess, AES.MODE_CBC, test_iv)
                try:
                    pt = unpad(cipher.decrypt(test_ct), 16)
                    if pt == b"SERVER_TEST_MESSAGE":
                        print(f"    [+] Curve b={b_val}: Found secret residue s = {k} mod {order_val}")
                        residues.append(k)
                        moduli.append(order_val)
                        found = True
                        break
                except:
                    continue
            
            if not found:
                print(f"    [-] Curve b={b_val}: Failed to solve DLP.")
        else:
             print(f"[-] Exchange failed for curve b={b_val}")

    # 2. Reconstruct Secret s bằng CRT
    print("[*] Reconstructing secret s using CRT...")
    try:
        secret_s = crt(residues, moduli)
        print(f"[*] Recovered Secret s: {secret_s}")
    except Exception as e:
        print(f"[-] CRT Failed: {e}")
        return

    # 3. Decrypt Flag
    print("[*] Decrypting Flag...")
    # Tạo đường cong thật để tính shared secret thật
    E_real = EllipticCurve(GF(p_real), [a_real, b_real])
    Client_P = E_real(cp_x, cp_y)
    
    # Tính shared secret thật: S = s * Client_Pub
    real_shared_point = int(secret_s) * Client_P
    final_key = hashlib.sha256(str(int(real_shared_point[0])).encode()).digest()[:16]
    
    enc_flag_bytes = bytes.fromhex(encrypted_flag_hex)
    iv = enc_flag_bytes[:16]
    ct = enc_flag_bytes[16:]
    
    cipher = AES.new(final_key, AES.MODE_CBC, iv)
    try:
        flag = unpad(cipher.decrypt(ct), 16)
        print(f"\n[SUCCESS] FLAG: {flag.decode()}")
    except Exception as e:
        print(f"\n[FAIL] Decryption failed: {e}")
        print("Note: Check if 's' exceeds the product of moduli or if p is larger than product.")

    io.close()

if __name__ == "__main__":
    solve()