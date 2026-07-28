# Leek Writeup

## Summary

Local, offline crypto challenge - `leek.py` (found under `Leek/Leek/leek.py`) and `output.txt` are provided, no remote connection. This is a standard-looking RSA setup (512-bit strong primes, `e = 65537`, `d > n^0.292` explicitly asserted to rule out Boneh-Durfee) that is broken purely by algebra: a single leaked value `leek` mixes `p`, `q`, `e`, and `d` through several power terms, and substituting `q = n/p` and `d = (k(p-1)(q-1)+1)/e` (for the unknown but bounded RSA multiplier `k`, `0 <= k < e`) turns the leak into one polynomial in `p` for each of the 65537 candidate `k` values - no factoring algorithm is needed at all.

Flag:

```text
0160ca14{1_d0nt_kn0w_what_a_Gr0bner_basis_1s,_but_1_us3d_1t_anyway!!!}
```

## Triage

`leek.py` generates a textbook RSA keypair, explicitly guards against Boneh-Durfee by asserting a large private exponent, then leaks an unusual polynomial combination of `p`, `q`, `e`, and `d` instead of anything RSA-standard:

```python
p = getStrongPrime(512)
q = getStrongPrime(512)
n = p*q

e = 65537

phi = (p - 1)*(q - 1)
d = pow(e, -1, phi)

assert d > pow(n, 0.292) # chống lại Boneh-Durfee Attack (dù rằng nó hơi thừa) :D

m = bytes_to_long(flag)
c = pow(m, e, n)

leek = p*e**2 + q*d + (e**3)*(p**4) + 2005*(q**6)*(e**12) + q + p**3 + e + d**5 - 23120404*p**10 + (d**2)*(p**7) + 69*(p**13)*(q**22)
```

`output.txt` gives `n`, `e`, `c`, and `leek` in full; `n` is a normal 1024-bit RSA modulus:

```text
n = 149510653836845062754800187267571921735160737045856828989062389792661457040301436690123192316964044142864169709414977010555545460266649115436236073002980308266064009612382931653656406038037841114917289005102758794102352404766666002915687491161216393472647935623433191021643283192621714234668950784742145262161
e = 65537
c = 94948667719185156581853448604431086955412069829218238973809757818608263252610789631401212153821098644052357532311889319996587572025012754378914968425385537587964022928531215724448106564454690179802575693674692903216241335535419914874590986513726911132461721245205736386038936870712690723164969646366490958166
```

`leek`, by contrast, is a several-thousand-digit integer (dominated by the `69*p^13*q^22` term, which alone is on the order of `2^17920`), consistent with plugging 512-bit `p` and `q` into that degree-35 polynomial. The challenge even sets `sys.set_int_max_str_digits(8888)` just so the interpreter can print it. No source file for this challenge existed separately in the extracted archive at the top-level `Leek/` folder; the actual challenge source `leek.py` was found nested at `Leek/Leek/leek.py` alongside its own `output.txt`, and both were used directly here rather than being reconstructed from the solve script.

## Solve Path

Two RSA identities eliminate `q` and `d` from the leak, leaving only `p` and one bounded unknown:

```text
q = n / p
e*d - 1 = k*(p-1)*(q-1)   for some integer 0 <= k < e
=> d = (k*(p-1)*(q-1) + 1) / e
```

Substituting both into the `leek` expression and clearing denominators produces a single polynomial `F(p, k) = 0` in two unknowns - but `k` only ranges over `65537` possible small integers, so for each candidate `k` the equation collapses to a univariate polynomial in `p` alone whose integer roots can be searched directly. Sage's symbolic ring is used once to do the substitution and denominator-clearing (`.simplify_full()`), since it handles the fraction algebra cleanly:

```python
var('p k')

q_expr = n_val / p
D_expr = k * (p - 1) * (q_expr - 1) + 1
d_expr = D_expr / e_val

L_expr = (p * e_val^2
          + q_expr * d_expr
          + e_val^3 * p^4
          + 2005 * q_expr^6 * e_val^12
          + q_expr
          + p^3
          + e_val
          + d_expr^5
          - 23120404 * p^10
          + d_expr^2 * p^7
          + 69 * p^13 * q_expr^22)

F_expr = (L_expr - leek_val).simplify_full()
F_num = F_expr.numerator().expand()
```

The symbolic result is then moved into an explicit polynomial ring `QQ[k][p]` (univariate in `p`, with coefficients that are themselves polynomials in `k`), so evaluating a specific candidate `k` is just a cheap coefficient substitution rather than repeating the symbolic simplification:

```python
Rk = PolynomialRing(QQ, 'k')
Rkp = PolynomialRing(Rk, 'p')
F_poly = Rkp(F_num)
coeff_polys = F_poly.list()   # coeff_polys[i] = coefficient of p^i, as element of Rk
```

For each candidate `k`, plugging it into `coeff_polys` gives a plain univariate polynomial in `p`; any integer root that also divides `n` is the real `p`:

```python
for idx, kval in enumerate(k_range):
    coeffs = [c(kval) for c in coeff_polys]
    Fk = Rp(coeffs)
    for root, mult in Fk.roots():
        r = ZZ(root)
        if r > 1 and r < n_val and n_val % r == 0:
            found = (r, kval)
            break
```

Once `(p, k)` is found, `q`, `phi`, and `d` follow immediately, and the flag is recovered with ordinary RSA decryption:

```python
p_val, k_val = found
q_val = n_val // p_val
phi_val = (p_val - 1) * (q_val - 1)
d_val = inverse_mod(e_val, phi_val)
m = power_mod(c_val, d_val, n_val)
```

Because the search is up to `65537` iterations of a degree-~35 root-finding call over huge coefficients, the script supports sharding the `k` range across parallel processes via command-line arguments (`shard`, `nshards`), each covering a disjoint residue class of `k`.

## Exploit

[solve.sage](#Solve) builds the symbolic leak equation once, converts it to an explicit polynomial ring in `p` with coefficients in `k`, then iterates candidate `k` values (optionally sharded across parallel runs) looking for an integer root of the resulting univariate polynomial that also divides `n`; once found, it derives `q`, `d`, and decrypts `c` directly.

Run:

```bash
sage solve.sage
```

Optionally shard the `k` search across several parallel processes:

```bash
sage solve.sage 0 4 &
sage solve.sage 1 4 &
sage solve.sage 2 4 &
sage solve.sage 3 4 &
```

Key steps:

- `q_expr`, `D_expr`, `d_expr`: symbolic substitutions expressing `q` as `n/p` and `d` as `(k*(p-1)*(q-1)+1)/e`.
- `L_expr` / `F_expr` / `F_num`: the leaked polynomial rebuilt purely in terms of `p` and `k`, then simplified and cleared of denominators.
- `Rkp`, `coeff_polys`: conversion into an explicit `QQ[k][p]` ring so each candidate `k` only costs a coefficient substitution.
- the `k_range` loop with `Fk.roots()`: per-candidate univariate root search, filtered to integer roots that divide `n`.
- final block (`q_val`, `phi_val`, `d_val`, `m`): standard RSA decryption once `p` (and hence everything else) is known.

## Solve

```python=
import sys

n_val = Integer(149510653836845062754800187267571921735160737045856828989062389792661457040301436690123192316964044142864169709414977010555545460266649115436236073002980308266064009612382931653656406038037841114917289005102758794102352404766666002915687491161216393472647935623433191021643283192621714234668950784742145262161)
e_val = Integer(65537)
c_val = Integer(94948667719185156581853448604431086955412069829218238973809757818608263252610789631401212153821098644052357532311889319996587572025012754378914968425385537587964022928531215724448106564454690179802575693674692903216241335535419914874590986513726911132461721245205736386038936870712690723164969646366490958166)
leek_val = Integer(15346476162484328321446639285668265258445030866341455394824149847156952552196026087785086785518104026631996275189057994684786739048050463665611507942357207522219465269712535481190871042181084737821396733140513763838501126364064681892174168045870538073957156248461474410159590750188388819089895122030488966231808020673258580355035732664377375129216606903240387943500566611232252133623415515165277808808829315701068770272435361693366349000680748901281896940871633405685267821268818116400241267076195332248570988996069685450472644437685968699486599630718155362755046395517684187848873837276241518798376880622108545588940041766595464189173336704932616573897742218964959223313548464172878750117957810260752864747956475994830499001974045327456102661950790537349704750428145312951420360214323937308900978162650239107489107144937050522026796094252931930601659904742153148441627191538618439733072813556998973396915907921092525124291274429339446357368070220525220230319145420916812111858227634146959335166497365657985074341186076444143417483650056985345362021994860354726588259093444262347995329872632032188386817584697135923850121622657389514357806146004527508414022603936316197201486528548027521365714947792512816930812015729011577336336247917915392764413532737084206813487805927964893005464107844464880581496747999444949798958276621824738348100386790163838425774337899106499993637742871956179528736200693550890819238145182780715442146173596183144950274809195160578564022224469141898415210618187346161728252983731434902180690647797411879276668364848224732252861132566651618501207479407145893333376718886737981568308681047813281154530414215776897856532439538684761684287276397992655372387974064295461677359132390039095749809769857133999841276077553781492499106214484903198205952232901219561468113174799921046353387895007992959042729906907345814328516611271121528912873000766328704392910391466313105931390964112575965952353686443468548141827863063677382719921056617249319428760231232930349216851759864464185854234110749254340663237984996338015063888037823029499079041786549183147313118624011856764693339086482514391186500528506233840249865935526106722109295100621974685452602433298432397751389635477672045176533277394968433534966476976185039178225287769310859999305248644657583431482540185851211923278875443188253418730005631116872032016271651510792394907395913318360578308415806748945070173734997761648336954123599905175869571803456963721781643145143699485723097513095054838196039986005666256057241485819710189036477460014589395198603660251718919988347816265679174349230350455183056938545161811014311508704234013691307433679530229576074113876975623977061595298828909959047556752500617426170384391224145321858133815910598634590209596304002089982370612320282875343420663808670677392758520008394287986329744937848052313181078514971829093541164136622340390310812958944352818621784661056677478787174590680013196322324907201694158876003279038528687187436902948889217857442648585985506794519463894327583912136470246565903073007226206841827458785114279183572007923452949597223382408603253564036835056513748298712316042520508967653258136971893693063786691079190026021878506915010464084130107588898066568459884806670191333849447859197217647435620864690166351771145427769616793993219824017207385216102566736148062889395891023614327941950268035444314139021504853127717651609906817340178054942366442940898798635035525129308335202705436283163776448305268457581305330090050649427347759091642638868499730525995828522869811841776829907793253855375220032605231112743926449984263633947597776895316919349268255877614847425643769430589661814299243196405916607509591996910658717743648784404780797357708444267265456577316256737116705272190245197783864572397675693113398170137543295657369619312959276983956977235672266425575980778533756071930895089574996600836001710892717736868912539428690276094612816599521092663070261085767331648287435019594926512246199931194917559521204556020234018368199123442527484810489459055182300217365501484504715049736066138350215476501386915557897843626825698278457725821130751385252696492092829581053156160213775627296319809554666975575102836655071898572636325832216799926331247549950806013810425318999635411928873882666710220828436071436371846996348839064317424548846505724309309963015579969549844436061326795095098759382117966477237157993838604291665166070502400184363551754604445651606749902683625597029381698406917074170009901381293402995452579138642653969580802573080670120140992355267442608963191172318615992232908774737720780859971423551707837371193633057427346291236485428829430431050285115435347924732010708966107308858990870786911547487680117947804884209313378031764010911177572626185918944210670772558523152979935185143394165495018827168118679795178722036139704347958115087132698309351144692337336271480912256812287940624174064278525717284218393306251210902385698540439601918109418118779257744982833646073194076835075842517096573431009056963186179802205230302071578894633504027715176355525261197613446179803310951805578383377253111697414792228499251449532661840047702629981992983619603388893132516858312155232211643379719769331945288464002858690839504179395146359113117278687565237814194463279053926575823146401729871502799632407105860476870498369909425275690579150446450794194532054655624067908202636987829938939508330831734565323484073674713350954146396572729533020971790340790449142974)


var('p k')

q_expr = n_val / p
D_expr = k * (p - 1) * (q_expr - 1) + 1
d_expr = D_expr / e_val

L_expr = (p * e_val^2
          + q_expr * d_expr
          + e_val^3 * p^4
          + 2005 * q_expr^6 * e_val^12
          + q_expr
          + p^3
          + e_val
          + d_expr^5
          - 23120404 * p^10
          + d_expr^2 * p^7
          + 69 * p^13 * q_expr^22)

print("building and clearing the symbolic expression (this may take a bit)...")
F_expr = (L_expr - leek_val).simplify_full()
F_num = F_expr.numerator().expand()

# move to an explicit ring: QQ[k][p] (univariate in p, coefficients poly in k)
Rk = PolynomialRing(QQ, 'k')
Rkp = PolynomialRing(Rk, 'p')
F_poly = Rkp(F_num)
coeff_polys = F_poly.list()   # coeff_polys[i] = coefficient of p^i, as element of Rk
print(f"F(p,k) built: degree {len(coeff_polys)-1} in p, "
      f"degree {max(c.degree() for c in coeff_polys if c != 0)} in k")

Rp = PolynomialRing(QQ, 'x')

if len(sys.argv) == 3:
    shard, nshards = int(sys.argv[1]), int(sys.argv[2])
else:
    shard, nshards = 0, 1

found = None
k_range = range(1 + shard, int(e_val), nshards)
for idx, kval in enumerate(k_range):
    coeffs = [c(kval) for c in coeff_polys]
    Fk = Rp(coeffs)
    for root, mult in Fk.roots():
        r = ZZ(root)
        if r > 1 and r < n_val and n_val % r == 0:
            found = (r, kval)
            break
    if found:
        break
    if idx % 200 == 0:
        print(f"[shard {shard}/{nshards}] tried k = {kval} ...")

if found is None:
    print(f"[shard {shard}/{nshards}] no valid (p,k) found in this shard's range")
else:
    p_val, k_val = found
    q_val = n_val // p_val
    phi_val = (p_val - 1) * (q_val - 1)
    d_val = inverse_mod(e_val, phi_val)
    m = power_mod(c_val, d_val, n_val)

    flag = int(m).to_bytes((int(m).bit_length() + 7) // 8, "big")
    print("p =", p_val)
    print("k =", k_val)
    print("flag =", flag)
```

## Verification

> sage solve.sage 2 4
```text
[shard 2/4] tried k = 36003 ...
p = 11351930516523542315317906539924344774580985083821269661342348167707682743216582747512069801784045567342008801536938353101697666500649021589116009683451657
k = 36071
flag = b'0160ca14{1_d0nt_kn0w_what_a_Gr0bner_basis_1s,_but_1_us3d_1t_anyway!!!}'
```

> Other

```text
[shard ?/4] no valid (p,k) found in this shard's range
```

## Flag

```text
0160ca14{1_d0nt_kn0w_what_a_Gr0bner_basis_1s,_but_1_us3d_1t_anyway!!!}
```

## Lessons Learned

- A "leaked expression" mixing multiple secret RSA quantities (`p`, `q`, `d`) is not automatically safe just because it isn't `p`, `q`, or `d` directly - if every unknown in it can be re-expressed in terms of one variable plus a small-range parameter (here, the RSA multiplier `k` in `e*d - 1 = k*phi(N)`, which is always `< e`), the whole system collapses to a bounded search.
- `e*d - 1 = k*(p-1)(q-1)` is a generally useful substitution any time `d` appears in a leaked equation: it turns `d` from an unknown of RSA's size into a small-range integer `k` (bounded by `e`) that can be brute-forced.
- Explicit hardness assertions in challenge source (like `d > n^0.292` blocking Boneh-Durfee) are a signal about which attack the author intended to block - and a hint that a different, non-standard attack path is the intended one.
- Symbolic algebra systems (Sage's symbolic ring) are well suited for one-time heavy substitution/simplification of a complex leaked expression; converting the result to an explicit polynomial ring afterward keeps the repeated per-candidate work cheap.
- When no per-challenge source file is bundled with the solve script, check nested/duplicate folders in the extracted archive before assuming it must be reconstructed from the solver's comments alone.
