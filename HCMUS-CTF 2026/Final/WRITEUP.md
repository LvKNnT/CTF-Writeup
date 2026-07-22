# FINAL HCMUS-CTF 2026

Đầu tiên thì rất vui vì cuối cùng năm nay cũng đã được thực sự tham gia Chung kết HCMUS-CTF. Năm ngoái team mình vẫn qualify bảng dưới nhma 1 thành viên quan trọng trong team lại bận nên ko có cơ hội tham gia vòng Chung kết :sob:. Năm nay tham gia thì team mình mạnh hơn nên tâm lí cũng thoải mái hơn chút. 

Mình chuyên crypto nên chắc blog này tập trung chủ yếu vào 3 bài crypto mình giải được trong thời gian thi thôi

# lock

> Bài này chắc warmup thôi 🐧

## Chall

[chall.py](lock/chall.py)

Server sinh `p, q` 128-bit, `N = p·q`, và `g` 256-bit rồi in `g`. Mình gửi `y`, `logT` (bắt buộc `≥ 50`), `pi`, server tính `T = 2^logT` rồi verify theo kiểu **Wesolowski VDF proof**:

```python
l = hash_to_prime(g, y, T)      # số nguyên tố hash từ (g, y, T)
r = pow(2, T, l)
lhs = pow(pi, l, N) * pow(g, r, N) % N
if lhs == y: # in flag
```

Ý đồ bài là: `pi` chỉ tính được nhanh nếu bạn *thực sự* chạy `T` phép bình phương liên tiếp (VDF — Verifiable Delay Function), tức phải tốn thời gian tỉ lệ `T`.

## Solve

`N` chỉ 256-bit (`p, q` mỗi cái 128-bit) nên factor được gần như tức thì bằng Sage → biết luôn `φ(N) = (p-1)(q-1)`. Có `φ(N)` thì việc "chứng minh đã chờ đủ `T` bước" trở thành vô nghĩa — có thể **forge** `pi` trực tiếp mà không cần lũy thừa lặp lại nào:

- Chọn `y = 2` (số nhỏ, `is_inside` chấp nhận), `logT = 50` (giá trị nhỏ nhất được phép).
- Tính `l = hash_to_prime(g, y, T)`, `r = 2^T mod l` (rẻ vì `l` chỉ ~256-bit).
- Vì biết `φ(N)`, lấy `d = l⁻¹ mod φ(N)` rồi `pi = (y · g^{-r})^d mod N` — đúng bằng nghiệm của phương trình verify `pi^l · g^r ≡ y (mod N)` mà không cần chạy VDF thật.

Bruteforce thử factor `N` trước để chắc kịp thời gian giới hạn của server, thấy kịp nên chỉ cần chọn `y`, `logT` nhỏ nhất có thể là xong.

Nếu các bạn cần thì có thể tham khảo [paper](https://eprint.iacr.org/2018/623.pdf) (Wesolowski, "Efficient Verifiable Delay Functions").

## Script

- [solve.sage](lock/solve.sage): factor `N` bằng Sage, tính `l, r`, forge `pi` theo công thức trên rồi gửi lên server để nhận flag.
```bash
sage solve.sage
```

# F1 Hybrid

> Redbull gives u wings (literally Max can fly in 2026)

## Chall

Server viết bằng Rust, source đầy đủ nằm trong [f1-hybrid-dist/src](F1%20Hybrid/f1-hybrid-dist/src) (đóng gói sẵn trong [f1-hybrid-dist.zip](F1%20Hybrid/f1-hybrid-dist.zip)):

- [main.rs](F1%20Hybrid/f1-hybrid-dist/src/main.rs) — logic kết nối: in seed 2048-bit, đọc `feedback_index`, sinh key 6 byte random, build cipher, rồi mở oracle loop.
- [cipher.rs](F1%20Hybrid/f1-hybrid-dist/src/cipher.rs) — cipher `Ghost`: Feistel 32 vòng kiểu GOST trên block 64-bit, key schedule LFSR 48-bit + CRC32.
- [utils.rs](F1%20Hybrid/f1-hybrid-dist/src/utils.rs) — tiện ích phụ (S-box, CRC, LFSR...).

Mỗi lần connect, oracle cho phép:

1. Encrypt hex tuỳ ý (ECB, bao nhiêu block cũng được).
2. Decrypt hex tuỳ ý (ECB).
3. Server tự encrypt 1 plaintext 8 byte random, đưa mình `ct`, mình phải đoán đúng `pt` — **không được hỏi oracle sau khi thấy `ct`** — để lấy flag.

## Solve

Vì không được hỏi oracle sau khi thấy `ct` của round 3, muốn thắng buộc phải tự decrypt offline được, tức là phải khôi phục lại cipher (key schedule) mà không cần biết key 48-bit gốc.

1. Key schedule tuy nhìn rối (LFSR 48-bit + CRC32 mỗi round key) nhưng thực chất là **hàm affine tuyến tính trên GF(2)** theo key gốc. Brute force ngây thơ `2^48` là bẫy vì mỗi lần thử key phải chạy lại LFSR ~380 triệu bước.
2. Model chính xác state-transition matrix `T` của LFSR (`model.py`) cho thấy các round key lệch nhau theo luỹ thừa `T^N`, với `N = 2·SIZE + 1 = 23738715 = 3²·5·7·11·13·17·31` — một số rất **mịn (smooth)**. Nếu tìm được `feedback` sao cho order của `T` chia hết `N` (tức `T^N = I`) thì 32 round key sẽ suy biến chỉ còn **2 giá trị luân phiên** `k0, k1, k0, k1, ...`.
3. Server cho mình tự chọn `feedback_index` để build feedback poly từ 2048-bit seed nó in ra sẵn — chỉ cần duyệt hết các index (`period_check.py`, test nhanh bằng `x^N mod c(x)`) tìm cái nào cho `T^N = I`. Ước lượng (`count_divisors.py`) mỗi lần connect có ~1/3 cơ hội tồn tại ít nhất 1 index tốt, nên chỉ cần reconnect tới khi trúng.
4. Khi đã suy biến 2-key, để ý **vòng cuối không swap** hai nửa block → suy ra được `decrypt = encrypt với k0, k1 hoán đổi vai trò cho nhau`, dẫn tới đẳng thức conjugate `E = ρ_k0 ∘ D ∘ ρ_k0` (kiểm chứng trên bản thu nhỏ ở `toy_slide.py`, `toy_attack.py`).
5. Từ đẳng thức đó, cố định một nửa block = 0 rồi dò theo "cột": `E((L,0)).hi == D((0, L⊕K)).lo` với `K = f(0,k0)`. Thử ~`2^19` giá trị `L`, cặp đúng sẽ có ~64 vote trong khi cặp nhiễu chỉ ~1 vote → lấy mode ra `K`, suy ngược `k0 = S⁻¹(ROR11(K))`. Làm tương tự (đổi vai trò encrypt/decrypt) để ra nốt `k1`.
6. Có `k0, k1` → dựng lại cipher offline, verify bằng 1 lần gọi oracle encrypt, rồi decrypt `ct` của round thử thách (option `3`) hoàn toàn offline, gửi lại `pt` đúng → nhận flag.

## Script

Thứ tự bên dưới cũng là thứ tự mình đi từ việc chứng minh ý tưởng trên bản mô phỏng nhỏ tới lúc viết solver thật.

- [model.py](F1%20Hybrid/model.py): dựng model affine chính xác trên GF(2) của key schedule, dùng để chứng minh nó full-rank 48 và rút ra công thức round key theo luỹ thừa `T^N`.
```bash
python model.py
```

- [count_divisors.py](F1%20Hybrid/count_divisors.py): đếm số ước bậc 48 của `x^N − 1` trên GF(2) để ước lượng xác suất gặp được feedback "tốt" (`T^N = I`) mỗi lần connect.
```bash
python count_divisors.py
```

- [sbox_props.py](F1%20Hybrid/sbox_props.py): tính DDP/LAT của S-box, xác nhận S-box là tối ưu (không có đường vi sai/tuyến tính nào khai thác được qua 32 vòng).
```bash
python sbox_props.py
```

- [f1cipher.py](F1%20Hybrid/f1cipher.py): port lại chính xác `cipher.rs` sang Python để tính toán/mô phỏng offline, được các script khác import dùng chung.

- [period_check.py](F1%20Hybrid/period_check.py): hàm `is_period2(feedback)` — check nhanh `T^N ≡ I` bằng `x^N mod c(x)` thay vì nhân ma trận, cross-check lại với cách nhân trực tiếp cho chắc.
```bash
python period_check.py
```

- [toy_slide.py](F1%20Hybrid/toy_slide.py): verify cấu trúc slide `E = swap ∘ F¹⁶` trên bản clone thu nhỏ của cipher trước khi tin vào nó.
```bash
python toy_slide.py
```

- [toy_attack.py](F1%20Hybrid/toy_attack.py): verify đẳng thức conjugate `E = ρ_k0 ∘ D ∘ ρ_k0` và kỹ thuật column-collision recovery trên bản nhỏ, trước khi áp dụng lên cipher thật.
```bash
python toy_attack.py
```

- [f1_solve.py](F1%20Hybrid/f1_solve.py): solver đầy đủ (dùng pwntools) — tự reconnect tới khi tìm được feedback period-2, khôi phục `k0/k1` bằng column-collision, verify lại key, decrypt block thử thách rồi gửi flag.
```bash
python f1_solve.py <host> <port>
```

# Funny Helicopter Morphology – 3

> :helicopter: :helicopter: :helicopter: 

## Chall

Server viết bằng C++ dùng thư viện [OpenFHE](https://github.com/openfheorg/openfhe-development) (mã hoá đồng cấu kiểu BFV). Source: [server_new.cpp](Funny%20Helicopter%20Morphology%20-%203/server_new.cpp) (bundle gốc: [public.zip](Funny%20Helicopter%20Morphology%20-%203/public.zip)).

Mỗi lần connect, server tạo state bí mật mới (`init_challenge()` chạy mỗi `accept()`) và nhận 2 lệnh:

- `PARAMS` — in ra tham số BFV `n, q, q0`, **flag đã mã hoá**, và một vector **OTP**.
- `CHALLENGE <num> <msg...>` — trả về `num` "bản mã" nhiễu `C0 = a·S + e·r + m`, `C1 = a`.

Có 2 ring BFV: ring chính (dim 32, modulus `q` ~2²⁴⁰) chứa secret `S` — probe được qua `CHALLENGE`; ring phụ (dim 8, modulus `q_aux` ~2²⁴⁰, không leak trực tiếp) chứa secret `T` — nguồn gốc key để mã hoá flag.

## Solve

1. Đường "chính thống" mà bài hướng tới là tấn công lattice 2 tầng: (a) khôi phục `S` từ các sample `CHALLENGE` — vì error `e·r` cực nhỏ so với `q` nên stack các sample lại thành 1 bài LWE có gap khổng lồ, dùng Kannan embedding + CVP là ra `S` gần như ngay lập tức (đã verify chạy được); (b) từ `S` suy ra `s_aux = (S − OTP) mod q` — đây chính là hệ số của `B_i·T + K_i (mod q_aux)`, kiểu NTRU, cần khôi phục nốt `T` để suy ra key XOR flag. Vế (b) cần biết `q_aux` (không được leak trực tiếp — lệnh `EVALSUM` để lộ nó đã bị comment out trong source), nhưng có thể tái tạo bằng cách replicate đúng thuật toán chọn NTT-prime của OpenFHE (verify được vì ra đúng `q` của ring chính).
2. Trong lúc chưa làm xong vế (b), đọc kỹ hàm mã hoá flag (`InitEncryptedFlag`) thì phát hiện lỗi không cố ý: flag dài 64 byte nhưng keystream dùng tận 128 byte (16 byte thấp nhất của 8 hệ số `T`), nên **mỗi byte output bị XOR đúng 2 lần**: `out[p] = flag[p] ⊕ byte_j(T_c) ⊕ byte_j(T_{c+4})`.
3. Vì 2 lượt XOR dùng 2 hệ số `T` độc lập, xác suất `low128(T_c) == low128(T_{c+4})` không hề nhỏ (thực nghiệm ~25–30% mỗi chunk 16 byte) — khi trùng thì keystream chunk đó bằng 0, tức 16 byte plaintext gốc **lộ thẳng ra ASCII** trong bản mã. Do secret được re-random mỗi connection nhưng nội dung flag thì cố định, mình chỉ cần harvest thật nhiều connection, chunk nào decode ra được text in được thì giữ lại, rồi lấy chunk xuất hiện nhiều nhất (mode) ở mỗi vị trí.
4. Gom đủ 4 chunk 16-byte là ráp lại được full flag, không cần đụng tới vế lattice (b) nữa.

## Script

- [collect.py](Funny%20Helicopter%20Morphology%20-%203/collect.py): kết nối 1 lần, gọi `PARAMS` rồi `CHALLENGE` để lấy 1 bộ transcript tham số + sample, lưu ra `data.json` — dùng để dựng và thử nghiệm hướng lattice (Stage 1).
```bash
python collect.py
```

- [recollect.py](Funny%20Helicopter%20Morphology%20-%203/recollect.py): giống `collect.py` nhưng gọi `PARAMS` 2 lần trong cùng 1 kết nối để kiểm tra kết quả nhất quán (OTP/flag và `S` phải cùng đến từ 1 instance) trước khi tin dữ liệu.
```bash
python recollect.py
```

- [probe.sage](Funny%20Helicopter%20Morphology%20-%203/probe.sage): factor modulus `q` chính để xem pattern các RNS prime, và thử import trực tiếp OpenFHE (nếu có) để lấy `q_aux`.
```bash
sage probe.sage
```

- [solve_stage1.sage](Funny%20Helicopter%20Morphology%20-%203/solve_stage1.sage): Stage 1 của hướng lattice — dựng ma trận negacyclic từ các sample `CHALLENGE`, chạy CVP (Kannan embedding) để khôi phục secret `S`, rồi tính `s_aux = (S − OTP) mod q` để chuẩn bị cho Stage 2.
```bash
sage solve_stage1.sage
```

- [diag.sage](Funny%20Helicopter%20Morphology%20-%203/diag.sage): so sánh số bit của `S`, `OTP`, `s_aux`, và thử replicate thuật toán chọn NTT-prime giảm dần của OpenFHE để đoán `q_aux` cho ring phụ (phục vụ Stage 2, không bắt buộc cho hướng exploit cuối cùng).
```bash
sage diag.sage
```

- [harvest.py](Funny%20Helicopter%20Morphology%20-%203/harvest.py): script khai thác chính — spam connection, mỗi lần lấy `Encrypted flag`, giữ lại những chunk 16-byte decode ra toàn ký tự in được, vote theo tần suất xuất hiện để ráp lại flag.
```bash
python harvest.py
```

# NieR

> Tôi yêu Noah :bow: 

## Chall

Server viết bằng Rust ([chall.rs](Nier/chall.rs), bundle gốc: [public.zip](Nier/public.zip)), load flag thành số nguyên lớn `m`, rồi lặp `NDAT = 137` vòng, mỗi vòng in ra:

```rust
const C: u64 = 1337;
fn lcg(s, n) -> BigUint { (3*s + C) % n }   // LCG, multiplier 3, increment 1337

let e1 = lcg(&e, n);
let e2 = lcg(&e1, n);
let sum = m.modpow(&e1, n) + m.modpow(&e2, n);   // cộng nguyên, KHÔNG mod N
println!("{}", sum);
e = next_seed(i);                     // random seed mới
println!("[DEBUG] e = {}", e);        // <- leak seed cho vòng SAU
```

`p, q` là 2 số nguyên tố 137-bit nên `N = p·q` chỉ 274-bit. Output đưa cho mình ([output.txt](Nier/output.txt)) gồm `N`, rồi từng cặp `sum_i` / `[DEBUG] e = s_{i+1}` xen kẽ nhau.

## Solve

1. **Chỗ leak:** `sum_i` được tính bằng seed hiện tại, *sau đó* mới random seed mới rồi in ra ở dòng `[DEBUG]`. Nghĩa là seed in ra ngay sau `sum_i` chính là seed sẽ dùng cho `sum_{i+1}` → biết trước `s_{i+1}` là biết chính xác luôn `e1, e2` của `sum_{i+1}` (chạy lại đúng công thức LCG). Được 136 sample dùng được (bỏ `sum_0` vì seed gốc bí mật).
2. `N` chỉ 274-bit → factor bằng Sage trong vài phút ra `p, q`.
3. Với `e2 = 3·e1 + 1337 (mod N)`, đặt `t = m^{e1 mod (P-1)}` thì `m^{e2}` viết lại được thành `w_k · t³` (chỉ có 3 giá trị `w_k` tuỳ số lần "tràn" `k = ⌊(3e1+1337)/N⌋`) → mỗi sample trở thành 1 **phương trình bậc 3** theo ẩn riêng `t_i`, modulo `P` (`P ∈ {p, q}`).
4. Hướng "hiển nhiên" là dựng đa thức `x^{a_i} + x^{b_i} − S_i` rồi lấy `gcd` để tách nghiệm `m` — **không khả thi** vì số mũ full-size (~129-137 bit), gcd đầu tiên đã ra đa thức dày đặc bậc ~2¹³⁷ (không cách biểu diễn nào chịu nổi). Discrete log hay Groebner trực tiếp trên các phương trình bậc 3 cũng bế tắc (thiếu ẩn / số mũ quá lớn).
5. Hướng đúng: đưa vào 1 ẩn chung `x = m^{-C}` (`C = 1337`), mỗi sample là 1 cubic `A_i³ + x·A_i − S_i·x = 0` theo ẩn riêng `A_i = m^{e1_i mod (P-1)}` (không bao giờ tính `A_i` thật vì nó to khủng khiếp). Dùng **LLL** tìm 1 quan hệ nguyên ngắn `Σ c_i·a_i + C·d ≡ 0 (mod P-1)` giữa các số mũ đã biết `a_i` — quan hệ này nối các `A_i` lại với nhau: `∏ A_i^{c_i} = x^d`.
6. Từ quan hệ đó, tách theo dấu `c_i`, dựng 2 đa thức chứa toàn bộ tổ hợp nghiệm nhánh dương/âm rồi lấy resultant `F(x) = Res_Z(P_+, P_-)` — đây chính là bước loại bỏ hết các `A_i`, chỉ còn `x`, và `x0 = m^{-C}` là nghiệm của `F`. `F` bậc cực lớn (~10⁸) nên **không** tính resultant kiểu symbolic (tốn ~150GB) mà **evaluate rồi nội suy** (`O(deg F)` bộ nhớ).
7. `F` bậc ~10⁸ cũng không root-find trực tiếp được (`x^P mod F` mất vài ngày). Giải pháp: dựng **2 quan hệ LLL độc lập** ra `F1, F2`, cả hai đều triệt tiêu tại `x0` nhưng các nghiệm "rác" thì khác nhau → `gcd(F1, F2)` chỉ giữ lại nghiệm chung. Cần lưu ý `F` luôn có nhân tử `x^v` rất lớn (do `x → 0` làm mọi cubic suy biến) nên phải strip `x^v` ra khỏi gcd trước khi tìm nghiệm thật (bậc chỉ còn ~1).
8. Từ nghiệm `x0` suy ra `m mod P` (`m = x0^{-1/C}`), verify lại bằng cách khớp các sample thật. Làm cho cả `p` và `q` rồi **CRT** lại ra `m` → decode ra flag.

## Script

Có khá nhiều script thử nghiệm/debug trong quá trình làm, dưới đây là pipeline chính đi từ đầu đến flag (đã verify chạy full self-contained).

- [factor_N.sage](Nier/factor_N.sage): factor `N` (274-bit) ra `p, q`, in luôn factorization của `p-1, q-1` để biết cấu trúc số mũ.
```bash
sage factor_N.sage
```

- [nier_leak.py](Nier/nier_leak.py): tool Python thuần (không cần Sage) — parse `output.txt`, replay LCG trên từng seed leak để lấy chính xác cặp số mũ `(e1, e2)` của mỗi sample, verify flag ứng viên khớp toàn bộ 136 sample, và CRT gộp kết quả `cands_p.txt` / `cands_q.txt` cuối cùng.
```bash
python nier_leak.py verify                 # verify 1 flag đã biết
python nier_leak.py exponents [k]          # in thử k cặp số mũ đầu
python nier_leak.py combine                # CRT cands_p.txt x cands_q.txt -> flag
```

- [nier_final.sage](Nier/nier_final.sage): dựng quan hệ LLL (`prep`, `prep2` cho 2 relation độc lập theo từng prime `p`/`q`).
```bash
sage nier_final.sage prep p
sage nier_final.sage prep2 p
```

- [setup_kernel.py](Nier/setup_kernel.py) + [nier_kernel.pyx](Nier/nier_kernel.pyx): kernel Cython/GMP chạy đa nhân để evaluate `F(v)` tại hàng trăm triệu điểm — build 1 lần trước khi dùng `nier_flint.py`.
```bash
python setup_kernel.py build_ext --inplace
```

- [nier_flint.py](Nier/nier_flint.py): script chính dùng python-flint — build `F` bằng evaluate (gọi kernel C ở trên) + nội suy `O(n)` bộ nhớ, rồi `gcd(F1, F2)` (FLINT HGCD) + strip `x^v` + root-find ra `m mod P`.
```bash
python nier_flint.py buildF p 1   # F1: eval + interpolate -> Fpoly1_p.bin
python nier_flint.py buildF p 2   # F2: relation thứ 2, sample khác -> Fpoly2_p.bin
python nier_flint.py gcd p        # gcd, strip x^v -> m mod p -> cands_p.txt
# lặp lại tương tự cho q
```

- [check_oracle.sage](Nier/check_oracle.sage): kiểm tra nhanh (~1s) trên dữ liệu thật rằng `x0 = m^{-C}` đúng là nghiệm của phép loại `A_i` — xác nhận cả pipeline (cubic + LLL relation) đúng hướng trước khi chạy full (tốn hàng giờ).
```bash
sage check_oracle.sage
```