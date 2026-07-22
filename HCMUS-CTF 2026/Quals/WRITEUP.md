# HCMUS-CTF 2026

> Mình được gánh. Cảm ơn anh Vũ Quốc Lâm rất nhiều orz.

```
This is not my work. This is only replicate work from the WU he submited :sob:
```

# Crypto101

> Nhập môn Crypto ở xứ sở HCMUS T.T

## Chall

Bài offline, không có server, chỉ có [challenge.sage](Crypto101/public/challenge.sage) và [output.txt](Crypto101/public/output.txt).

Server dựng curve `E: y^2 = x^3 + a*x + b` trên vành `Z/p^4Z` với `p` là prime 256-bit bí mật, chọn điểm gốc bí mật `P` và 24 điểm bí mật `Q = [Q_0..Q_23]` (mỗi `Q_j = random_scalar * P`). Sau đó sinh 120 vector byte ngẫu nhiên `c_i` (24 byte, giá trị 0-255) và publish:

```python
R_i = sum(c_i[j] * Q_j for j in range(24))    # 120 điểm, publish (x,y) mod p^4
Px % p                                         # x của P, nhưng chỉ mod p (không phải mod p^4!)
ct = AES_ECB(flag, key=md5(str(sum(Q))))
```

`p, a, b, P, Q_j, c_i` đều bí mật hết. Cái mình có là 120 điểm trên cùng 1 curve `mod p^4`, mỗi điểm là tổ hợp tuyến tính hệ số byte của chỉ 24 điểm ẩn. Tỉ lệ "120 samples cho 24 ẩn" + vành không phải trường (là `Z/p^4Z` chứ không phải `GF(p)`) là dấu hiệu rõ ràng của bài lattice/p-adic chứ không phải discrete log thường.

## Solve

### Lấy `p` bằng GCD

Với mọi điểm `R` trên curve: `R.y^2 - R.x^3 - a*R.x - b ≡ 0 (mod p^4)`. Lấy hiệu giữa các cặp quan hệ này để triệt tiêu `a, b` chưa biết, phần còn lại chỉ đảm bảo `≡ 0 (mod p)` (chứ không cần mod `p^4`) vì discriminant curve coprime với `p`:

```python
v_i = R_i.y**2 - R_i.x**3
t = (v_0-v_1)*(x_0-x_i) - (v_0-v_i)*(x_0-x_1)
g = gcd(g, t)   # tích luỹ dần thành bội của p
```

Sau đó chia hết các cofactor nhỏ, lấy căn bậc 4 nguyên là ra `p` 256-bit.

### Lấy `(a, b) mod p^4`

Biết `p` rồi thì biết luôn `mod = p^4`. Hai điểm bất kỳ cho hệ tuyến tính 2 ẩn `a, b`, giải trực tiếp bằng nghịch đảo modular.

### Formal group log kiểu p-adic (đây mới là chốt bài)

Reduce `E` xuống mod `p` được 1 curve "ordinary" thường trên `GF(p)` với order `N`. Điều thú vị: với **bất kỳ** điểm `R` nào trên `E` (mod `p^4`), điểm `N*R` sẽ reduce về identity mod `p` — tức là nó rơi vào **formal group**, kernel của phép reduction. Formal group này đẳng cấu (qua 1 log map p-adic khá kinh điển) với nhóm **cộng** `Z/p^3Z`. Nghĩa là: nhân điểm trên curve ⟺ nhân log trong `Z/p^3Z`.

```python
P2 = P1 * (N - 1)
# ... (công thức chord qua P1, P2 để tính log)
z = (t // p) % (p**3)   # log dạng p-adic của R, sống trong Z/p^3Z
```

Vì log map là đẳng cấu nhóm nên:

```
z_list[j] = log(R_j) = sum_k c_j[k] * log(Q_k)   (mod p^3)
```

— y hệt hệ 24 ẩn ban đầu, nhưng giờ là **đại số tuyến tính thật sự** trên `Z/p^3Z` thay vì cộng điểm trên curve.

### LLL tìm nullspace, MILP dựng lại ma trận byte

`z_list` có 120 số, mỗi số là tổ hợp tuyến tính nguyên (hệ số 0-255) của 24 ẩn `log(Q_k)`. Nhét vào lattice với hằng số scale lớn rồi LLL, các vector ngắn còn lại (`row[120]==0`) chính là các quan hệ null giữa các sample — 24 chiều nullspace của ma trận hệ số 120x24:

```python
K = 2**1000
L[i,i] = 1; L[i,120] = K * z_list[i]
L[120,120] = K * p**3
B_basis = matrix(ZZ, [r[:120] for r in L.LLL() if ...]).right_kernel_matrix()
```

`B_basis` chỉ span đúng row space của ma trận byte thật `C`, chưa ra được chính `C`. Mỗi cột thật của `C` là 1 tổ hợp **nguyên** cụ thể của các hàng `B_basis`, với mọi entry trong `[0,255]`. Dùng MILP với objective ngẫu nhiên, lặp lại nhiều lần để duyệt ra từng cột (24/24 cột):

```python
p_milp.add_constraint(0 <= expr <= 255)
p_milp.set_objective(sum(random.randint(-100,100)*x[j] for j in active))
```

### Ghép lại thành `sum(Q)`

Có 24 cột của `C` rồi thì tìm tổ hợp hữu tỉ `x_sol` sao cho `C_T . x_sol = [1]*24` — đúng là tổ hợp sample nào mà tổng hệ số trên mỗi `Q_k` bằng 1:

```python
x_sol = matrix(QQ, columns_of_C).solve_right(vector(QQ,[1]*24))
```

Scale `x_sol` ra mẫu số chung `D`, cộng điểm thật (point addition, không phải log nữa — log chỉ để tìm hệ số) trên các `R_j` tương ứng ra `D * sum(Q)`, nhân nghịch đảo `D^-1 mod (N*p^3)` là ra đúng `sum(Q)` → key AES → decrypt flag.

## Script

[solve.sage](Crypto101/public/solve.sage): chạy thẳng, đọc `output.txt` có sẵn, không cần mạng.

```bash
sage solve.sage
```

Chạy xong in luôn:

```text
[+] Recovered 256-bit prime p: 3783604169789799981646554902454398796131601172800...
[*] Recovered 24/24 columns of C.
[+] FLAG: HCMUS-CTF{tH3_L4tT1cE_w4$_r3dUc3D_bY_LLL_th3n_BKZ_b3t4_40_...CrYpT0$}
```

# EasyCurve

> `Easy` and `Curve` can be in the same sentence in the big 2026 now T.T

## Chall

Bài offline, [source.sage](EasyCurve/source.sage) cho sẵn full source + output in ra. 2 số nguyên tố bí mật 400-bit `p, q` được nhét vào curve `E: y^2 = x^3 + (q-p)x^2 - pq*x` trên field public 812-bit. Server isogeny hoá `E` qua điểm xoắn bậc 2 hữu tỉ `(0,0)` (degree 2), publish **j-invariant của curve ảnh (codomain)**, cộng với `N = p*q` và ciphertext AES-GCM key = `sha256(str(p+q))`.

```python
E = EllipticCurve(Fp, [0, q-p, 0, -p*q, 0])
iso = E.isogeny(E(0, 0))
j_iso = iso.codomain().j_invariant()
```

`p, q` bí mật, nhưng key AES chỉ phụ thuộc `p+q` — không cần tách riêng `p, q` làm gì, chỉ cần ra được tổng.

## Solve

`(0,0)` luôn là điểm xoắn bậc 2 hữu tỉ của mọi curve dạng `y^2=x^3+ax^2+bx` (với `a=q-p, b=-pq`). Isogeny qua nó (Vélu bậc 2) cho curve ảnh với hệ số:

```
a' = -2a
b' = a^2 - 4b = (q-p)^2 + 4pq = (p+q)^2
```

Đặt `s = p+q`. Cả `a', b'` (và mọi hàm chẵn theo `a'`, trong đó có j-invariant) đều chỉ phụ thuộc `s` và `N=pq` — dấu của `q-p` bị triệt tiêu hết. Thay công thức j-invariant vào, quy đồng mẫu số ra được 1 **cubic theo `S = s^2`**:

```python
Fp = GF(P); R.<S> = PolynomialRing(Fp)
f = 16*S^3 + N*(j_iso - 768)*S^2 + 12288*N^2*S - 65536*N^3
```

Giải nghiệm cubic trên `GF(P)`, nghiệm nào là số chính phương (vì `s=p+q` là số nguyên ~400-bit thật, không chỉ là residue trong field) thì đúng là `S = s^2`:

```python
for root, _ in f.roots():
    S_val = Integer(root)
    if S_val.is_perfect_power():   # chính phương
        p_plus_q = S_val.isqrt()
```

Có `p+q` rồi thì `key = sha256(str(p+q))`, decrypt AES-GCM thẳng ra flag, không cần factor `N` hay tách `p, q` riêng.

## Script

[solve.sage](EasyCurve/solve.sage): hardcode sẵn `N, P, j_iso, ciphertext, tag, nonce` từ output, dựng cubic, tìm nghiệm chính phương, decrypt.

```bash
sage solve.sage
```

```text
Recovered p+q = 2884456...
Flag: HCMUS-CTF{v3lus_f0rmul4_m4k3s_1s0g3n13s_1nst4nt}
```

# Funny Helicopter Morphology - 1

> :helicopter:

## Chall

Service OpenFHE/BFV (`server_new.cpp`) mỗi connection sinh 1 đa thức bí mật `T` (8 hệ số, uniform `[2^59,2^60)`, sorted), XOR-mask flag bằng byte little-endian của `T`. Gửi `EVALSUM` **trước** `PARAMS` mở khoá hint trực tiếp: 2 sample RLWE-kiểu `S_i = B_i*T + K_i` (`B_i` ternary, `K_i` Gaussian nhỏ, ring negacyclic dim 8). Vì cả 2 sample chung 1 `T`, nhân chéo triệt tiêu nó (`B0*S1-B1*S0 = B0*K1-B1*K0`) biến bài toán thành recovery lattice bé cho `(K0,K1)`, từ đó ra `T`.

## Solve

### Về chung 1 tower

`B_i` in ra là giá trị CRT-interpolate đầy đủ (nên "-1" ternary sẽ hiện ra thành `aux_modulus - 1`), cần center rồi mod về đúng 1 tower prime `Q = 1152921504606846577` để khớp với `S_i` (server chỉ in `S_i` đã mod sẵn theo tower này):

```python
B0 = [center(v, AUX_FULL_MODULUS) % Q for v in b0_arr]
```

### Triệt tiêu `T`

`B1` khả nghịch mod `Q` (verify được bằng Gauss elimination chạy suôn sẻ), nên:

```
C   := B0 * B1^-1        (mod Q)
RHS := S0 - C*S1          (mod Q, tính được hết)
RHS === K0 - C*K1          (mod Q)   <- cả 2 vế đều BÉ!
```

`C, RHS` biết hết, `K0, K1` bé (Gaussian sigma=2) — bài toán small-error/CVP kinh điển, y hệt trick "cancellation relation" bên bài 2, chỉ áp lên tầng error thay vì tầng ternary sample.

### CVP bằng LLL + Babai

Dựng lattice 16 chiều từ `q*I_8` và ma trận convolution của `C`, LLL rồi Babai nearest-plane nhắm target `(-RHS, 0)` ra 1 candidate `(K0, K1)`.

**Đây là chỗ mình gặp vấn đề khi build lại từ đầu.** Validate offline (`local_verify_lattice.py`, dùng instance giả lập biết trước đáp án thật) cho thấy lattice sau khi reduce có **8 vector độc lập norm cực nhỏ** (~sqrt(12)) gần như không liên quan gì tới target — do `B0, B1` đều ternary/sparse nên `C = B0*B1^-1` "không generic" như 1 ma trận random mod Q bình thường. Cụ thể:

```text
[*] 8 short basis vectors quanh điểm Babai.
[*] 4765 candidate qua được filter K0[0],K0[1].
[*] 4765 candidate CŨNG có T sorted + đúng range (đây chính là điểm yếu).
[+] Đáp án thật NẰM TRONG các candidate đã lọc: True
```

`(K0,K1)` thật **có** trong pool candidate (tổ hợp điểm Babai với tổ hợp nguyên nhỏ của 8 vector kernel ngắn) — nhưng chỉ filter "sorted + đúng range" thôi thì không đủ chọn duy nhất 1 trong hàng nghìn candidate giống nhau. Cái này khớp gần như y hệt writeup gốc: `CHALLENGE` leak miễn phí 2 hệ số đầu của combined error (`K0[0], K0[1]` chính xác), và writeup gốc còn nói thẳng là phải "intersect nhiều live transcript" mới ra được flag ổn định — tức bản thân solve gốc cũng noisy y vậy, không phải determin 1 phát.

### Ra `T` và decrypt

Với mỗi candidate `(K0,K1)` sống sót:

```python
T = B1^-1 * (S1 - K1)     # mod Q; T < Q gần như chắc chắn nên không cần unwrap gì thêm
key_bytes = little_endian(signed(T))
flag_body = enc_bytes XOR key_bytes (lặp)
```

lọc candidate xuống còn những cái decode ra toàn ASCII in được (filter cực mạnh — candidate sai thì byte gần như random, xác suất 32+ byte liên tiếp in được là gần bằng 0) là ra đúng flag.

## Script

[solve.sage](Funny%20Helicopter%20Morphology%20-%201/solve.sage): connect live, gửi `EVALSUM` rồi `PARAMS` rồi `CHALLENGE 1 0`, dựng `C, RHS`, LLL+Babai ra base `(K0,K1)`, duyệt tổ hợp nhỏ quanh nó, lọc theo leak `K0[0]/K0[1]` + "decode ra ASCII in được", in hết candidate còn sống.

```bash
sage solve.sage
```

[local_verify_lattice.py](Funny%20Helicopter%20Morphology%20-%201/local_verify_lattice.py): check offline (pure Python, không cần Sage) với instance giả lập biết đáp án thật — dùng để confirm phần đại số/lattice độc lập với server live, và cũng là script tái hiện lại phát hiện "ambiguity" ở trên.

```bash
python local_verify_lattice.py
```

## Verification

Vì recovery vốn noisy, cách verify thực tế là: chạy `solve.sage` live, check trong list candidate có chuỗi bắt đầu `HCMUS-CTF{` không. Đối chiếu 2-3 connection khác nhau, giữ phần prefix lặp lại (chỉ khác đoạn hex padding cuối, giống hệt bài 2):

```text
l4tt1ce-or-d1d-y48-brute?-How-Long-To-m4CH-1t-t4k3?<hex suffix khác nhau mỗi lần>
```

Cắt bỏ hex suffix theo đúng hướng dẫn của chall là ra flag được chấp nhận.

# Funny Helicopter Morphology - 2

> :helicopter: :helicopter:

## Chall

Xài lại đúng service OpenFHE/BFV của bài 1 (`server_new.cpp`, share chung), nhưng khai thác qua **1 thứ tự lệnh khác**. Mỗi connection server sinh 1 đa thức bí mật `T` (16 hệ số, thật ra là 8 hệ số aux ~60-bit random, sorted), dùng byte little-endian của `T` XOR-mask **2 flag riêng biệt**. Server đọc lệnh theo kiểu:

```cpp
if (action == "PARAMS") {
    // trả "Encrypted flag: " + (used_hint ? flag_1 : flag_2)
    used_params = true;
}
else if (action == "EVALSUM") {
    if (used_params) continue;   // gọi PARAMS trước là EVALSUM bị lờ luôn!
    used_hint = true;
    // in thẳng B0, S0, B1, S1
}
else if (action == "CHALLENGE") {
    // C0 = C1*S + e*r + m, in ra rồi đóng connection
}
```

Gọi `PARAMS` **trước** `EVALSUM` là khoá luôn đường hint (bài 1 dùng), `PARAMS` trả về `encrypted_flag_2`. Thứ duy nhất còn xài được là oracle `CHALLENGE`: vài sample noisy kiểu RLWE `C0 = C1*S + e*r + m` với `S` cố định (theo connection) và `r` là 1 scalar random chung.

## Solve

### Ra `S` chính xác bằng least squares

`C1` là đa thức ternary public (khả nghịch mod `r` gần như chắc chắn), nên **1 sample** đã cho `S mod r`:

```python
S_mod_r = matrix(Zmod(R), M_C1_0).solve_right(vector(Zmod(R), C0_0))
```

Viết `S = S_mod_r + r*X` với `X` nguyên chưa biết, mỗi sample cho 16 phương trình tuyến tính theo `X` (trừ mod-r đi thì `e_i` nhỏ còn lại thôi):

```python
V_i = (C0_i - M_i * S_mod_r_lifted) / R      # ~= M_i*X + e_i nhỏ
```

Với 10 sample (160 phương trình, 16 ẩn) — dư thừa nhiều — giải least squares trung bình hoá nhiễu Gaussian ra, round là ra `X` chính xác, tức là ra `S` nguyên chính xác:

```python
X_exact = round(least_squares(M_stack, V_stack))
S_exact = S_mod_r_lifted + R * X_exact
```

### Lattice ACDP ra `B0, B1`

`S` tách thành `S0 = B0*T+K0`, `S1 = B1*T+K1` (8 hệ số mỗi cái). `B0, B1` ternary (bé), `K0, K1` Gaussian (bé), nên `B0*S1 - B1*S0 = B0*K1 - B1*K0` cũng **bé** — bài toán ACDP kinh điển. Dựng lattice rồi LLL, `(B0,B1)` xuất hiện thẳng làm vector ngắn nhất:

```python
L[i,i]=1; L[i,16+j]=M_S1_row[i,j]
L[8+i,8+i]=1; L[8+i,16+j]=-M_S0_row[i,j]
B0, B1 = L.LLL()[0][:8], L.LLL()[0][8:16]
```

### Giải ra `T`

Biết `B0` rồi thì `S0=B0*T+K0` chỉ còn nhiễu `K0` bé xíu — giải hệ tuyến tính (rational) rồi round ra `T` luôn:

```python
T = [round(x) for x in M_B0_col.solve_right(vector(QQ, S0))]
assert T == sorted(T)   # server luôn sort T -- check cho chắc
```

### Decrypt flag

```python
key_bytes = b"".join(struct.pack("<q", c) for c in T)
flag = bytes(b ^ key_bytes[i % 64] for i, b in enumerate(enc_bytes))
```

## Script

[solve.sage](Funny%20Helicopter%20Morphology%20-%202/solve.sage): chạy live, tự connect và xử lý hết.

```bash
sage solve.sage
```

Kết quả 1 run có thể lệch 1 chút do rounding/sign biên (hiếm), nên chạy lại vài connection rồi so prefix — chỉ khác đoạn padding random cuối, còn lại giống hệt nhau:

```text
l4ttice?-w1th-what-ortho-l4tt1c3-or-idea-1ng4n134-an4th3r-dm!bb9
l4ttice?-w1th-what-ortho-l4tt1c3-or-idea-1ng4n134-an4th3r-dm!9f8
l4ttice?-w1th-what-ortho-l4tt1c3-or-idea-1ng4n134-an4th3r-dm!5ea
```

# Rust In Peace

> Sage In Sadge :sob:

## Chall

Service Rust (`chall.rs`) là 1 SPN 12 vòng trên block 64-bit: mỗi vòng áp S-box theo nibble (chỉ **4 S-box khác nhau** thật sự, lặp lại theo `i % 4` trên 16 vị trí nibble) rồi permute bit cố định public. 4 S-box được sinh bí mật từ key random mỗi connection. Service cho oracle `E`/`D` tự do, sau đó tới 100 vòng "encrypt hộ tao, không được hỏi oracle nữa" mới in flag.

```rust
fn encrypt_block(block, rounds, sboxes) {
    for _ in 0..(rounds-1) { state = S(state); state = P(state); }
    S(state)
}
```

## Solve

### Oracle chính là 1 luỹ thừa của round function

Gọi `S` là lớp S-box, `P` là permute public. `encrypt_block` áp `S,P,S,P,...,S` — 12 lần `S`, 11 lần `P`. Đặt `F := P∘S` (1 "vòng key" đầy đủ):

```
E(x) = S(F^11(x))     # oracle trả về cái này
```

Áp `P` (public, biết trước) lên output oracle:

```
G(x) := P(E(x)) = F(F^11(x)) = F^12(x)
```

`G` tính được chỉ từ 1 lần gọi oracle + 1 lần `P` local. Và vì `G` là luỹ thừa của `F` nên `F` và `G` **commute**: `G(F(z)) = F(G(z))` với mọi `z` (mở rộng ra, `G` commute với `F^j` bất kỳ).

### Không gian candidate bé cho `F` tại 1 state chọn sẵn

Chọn state `x_a` mà **mọi** nibble đều = `a` (0-15). Vì `sbox_layer` tra `sboxes[i%4]` theo từng nibble, `S(x_a)` (và `F(x_a)=P(S(x_a))`) chỉ phụ thuộc **4** ẩn: `(S0(a),S1(a),S2(a),S3(a))`, mỗi cái 0..15 — `16^4=65536` candidate, không phải `16!^4`.

### Lọc candidate bằng quan hệ commute

Với `y = F(x_a)` thật, `G^k(y) = F(G^k(x_a))` mọi `k`. `G^k(x_a)` đo được **chính xác** (không đoán — `x_a` tự chọn, hỏi oracle lặp lại được). Với 1 candidate `y`, check `G^k(y)` có "consistent" với `F(G^k(x_a))` không mà không cần biết `F` đầy đủ: undo `P` trên `G^k(y)` ra candidate output của `S` tại input biết trước `G^k(x_a)`, rồi check tính chất bắt buộc của `S`: input nibble giống nhau (cùng loại S-box) thì output giống nhau, input khác nhau thì output khác nhau (S-box là song ánh):

```python
def consistent(input_nibbles, output_nibbles):
    for t in range(4):
        seen = {}
        for i in range(t, 16, 4):
            iv, ov = input_nibbles[i], output_nibbles[i]
            if iv in seen:
                if seen[iv] != ov: return False
            elif ov in seen.values():
                return False
            else:
                seen[iv] = ov
    return True
```

Candidate sai bị loại gần như ngay lập tức — guess sai cho output nibble gần như random, xác suất thoả structure "same-in-same-out, distinct-in-distinct-out" trên 16 vị trí là cực thấp.

### Batch 1 lần, dùng lại cho cả 16 giá trị `a`

`16^4` candidate và ảnh `G^k` của chúng **không phụ thuộc `a`** — chỉ chain thật `G^k(x_a)` mới phụ thuộc. Nên batch toàn bộ (`G^1(y)..G^k(y)` cho cả 65536 candidate) tính **1 lần**, dùng lại cho cả 16 giá trị `a`, pipeline query `E` qua connection cho nhanh. Implementation này dừng mở rộng round cho `a` nào đã còn 1 candidate — validate offline (`local_verify_commute.py`) thấy thường resolve hết 16 giá trị trong 4 round:

```text
round 1: resolved so far = 0/16
round 2: resolved so far = 3/16
round 3: resolved so far = 11/16
round 4: resolved so far = 16/16
recovered == true: True
```

### Đóng oracle, trả lời 100 challenge

Check vài query oracle tươi so với local encryption cho chắc, rồi gửi dòng rỗng đóng phase interactive, trả lời 100 block `Challenge:` hoàn toàn local bằng S-box đã recover.

## Script

[solve.sage](Rust%20In%20Peace/rust-in-peace/solve.sage): connect, recover 4 S-box bằng commute attack (pipeline theo chunk), sanity check với oracle live, rồi trả lời 100 challenge local.

```bash
sage solve.sage --host chall.blackpinker.com --port 20280 --powers 8 --chunk-blocks 8192
```

[local_verify_commute.py](Rust%20In%20Peace/rust-in-peace/local_verify_commute.py): check offline không cần mạng — dựng cipher giả trong process với S-box random biết trước, chạy đúng thuật toán `recover_sboxes`, confirm khớp và test thêm 200 block random.

```bash
python local_verify_commute.py
```

## Verification

Offline (không mạng):

```text
round 4: resolved so far = 16/16
recovered == true: True
total oracle queries used: 262208
fresh random blocks match: True
```

Live:

```text
[+] All 16 type-values resolved.
[+] Local encryption matches the oracle.
Congratulations! Here is the flag: HCMUS-CTF{TH3_0rAcl3_5P0K3_1N_R0Und5_ANd_th3_thR35H0LD_an5w3R3D_1N_P3rMuTaT10N2}
```