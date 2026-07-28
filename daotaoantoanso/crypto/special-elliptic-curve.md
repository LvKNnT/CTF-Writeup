# Special Elliptic Curve Writeup

## Summary

This chall builds an elliptic curve `E` not over a prime field `F_p` but over the ring `Z/p^5Z`, lifts a random point `P` onto it, and publishes `P` and `Q = m*P` where `m` is the 43-byte flag interpreted as an integer. No remote service is involved - everything needed is in `output.txt`. The core mechanic is that points on `E(Z/p^5Z)` split into an `F_p`-rational part plus a formal-group kernel of order `p^4`, and that kernel is isomorphic to `(Z/p^4Z, +)` via a p-adic logarithm, which turns the "hard" elliptic-curve discrete log into a division in `Q_p`.

Flag:

```text
0160ca14{3ll1pt1c_curv3_ov3r_p-adic_f13ld!}
```

## Triage

`special_elliptic_curve.py` generates a 512-bit prime `p`, two random 512-bit curve coefficients, and defines the curve over `Zmod(p**5)` - a ring, not a field:

```python
p = getPrime(512)
a1 = getrandbits(512)
a2 = getrandbits(512)
Fp = Zmod(p**5)
E = EllipticCurve(Fp, [a1, a2])

m = bytes_to_long(flag)
P = E.lift_x(Integer(getrandbits(512*5)))
Q = m * P
```

`assert len(flag) == 43` fixes `m` at 344 bits - far smaller than `p` (512 bits) or the ring's modulus `p^5` (2560 bits). `output.txt` contains the full affine coordinates of `P` and `Q` (as elements of `Z/p^5Z`, printed with an implicit `z = 1` projective-style third coordinate) plus `p`, `a1`, `a2`:

```text
P: (3140410916...096 : 1650165004...848 : 1)
Q: (1318255284...691 : 14319632160...211473 : 1)
p = 8056214885364405686222126654125867129615844411205519854451535576473155805503671461308303184163871680686334162003343415775884489186172469025432230101435373
a1 = 1704625448079672493725385696954489776449792965064371582831944842835294967987299772073039822182441688059147118386602445470071533689825641747045938850656920
a2 = 2761865023621674450464861320238411816379448538899506683273537115113283121281539547363316989306470150259789345310585224866168229184631297283344122088268930
```

Working over `Z/p^5Z` instead of `F_p` is the "special" part: reduction mod `p` gives a surjective group homomorphism `E(Z/p^5Z) -> E(F_p)` whose kernel has order `p^4` (the formal group of the curve). A point's discrete log therefore splits into an `F_p`-component (as hard as ordinary ECDLP) and a `p^4`-order formal-group component that is *linear* - no exponential-time DLP needed for that part.

## Solve Path

The plan is to isolate the easy formal-group component and read `m` off it directly, since `m < p` already fits inside a single p-adic digit of precision.

First, `solve.sage` computes `n1 = #E(F_p)` over the reduced curve, and confirms `gcd(n1, p) == 1` (the generic case for a curve with good reduction at `p`):

```python
Fp = GF(p)
E = EllipticCurve(Fp, [Fp(a1), Fp(a2)])
n1 = E.order()
print("gcd(n1, p) =", gcd(n1, p))
```

Because `gcd(n1, p) == 1`, multiplying any point on `E(Z/p^5Z)` by `n1` kills its `E(F_p)`-component entirely and leaves only its component inside the order-`p^4` kernel subgroup - exactly the formal group, which is analytically isomorphic to `(Z/p^4Z, +)`.

An earlier, abandoned approach is preserved in `factor.sage`: it takes a curve-order value `n` (whose leading ~80 decimal digits coincide with `p`'s, consistent with Hasse's bound `|#E(F_p) - (p+1)| <= 2*sqrt(p)` for a 512-bit `p`) and tries to factor it directly, having already found one ~512-bit prime factor by other means:

```python
factors = [(314880394190518103819508565727022361915803963697694737324664278931919320129119722403505037533315341268058299408305400057056443716609562880925202303179, 1)]
# factor the rest
factors = factor(n // factors[0][0])
```

`solve.sage` never imports or calls into `factor.sage` - it is a standalone precursor. The size of that surviving prime factor of `n1` makes a full Pohlig-Hellman discrete log on the `F_p`-rational part infeasible, which is exactly the dead end that motivates the pivot in `solve.sage`: annihilate the `n1`-order part by scalar multiplication instead of trying to solve a DLP in it. The bundled reference `978-3-642-04159-4_6.pdf` is a Springer book-chapter PDF (its filename is the book's ISBN plus a chapter number); given it sits alongside this exact construction, it is almost certainly the published source for the formal-group / anomalous-curve technique implemented below, rather than something original to the solve script.

With `n1` in hand, the actual break lifts both points into `Q_p(p, 5)` (a genuine p-adic *field*, matching the ring's precision) rather than working in `Zmod(p**5)` directly - arithmetic in `Zmod(p**5)` would hit non-invertible zero-divisor denominators once a point lands purely in the kernel, while `Qp` just tracks precision loss instead of throwing:

```python
PREC = 5
R = Qp(p, PREC)
ER = EllipticCurve(R, [R(a1), R(a2)])
Plift = ER(R(Px), R(Py))
Qlift = ER(R(Qx), R(Qy))

# kill the E(F_p)-component, leaving only the order-p^4 kernel component
Pk = n1 * Plift
Qk = n1 * Qlift
```

The kernel points are converted to their local parameter `t = -x/y` (the standard uniformizer used to define the formal group law), then run through the curve's formal-group logarithm, which linearizes the group law on the kernel:

```python
tP = -(xP / yP)
tQ = -(xQ / yQ)

log_series = ER.formal_group().log(prec=20)
logP = log_series(tP)
logQ = log_series(tQ)

m = Integer((logQ / logP).lift()) % p
```

Because `log` is a group homomorphism from the kernel to `(Z/p^4Z, +)`, `log(n1*Q) = m * log(n1*P)`, so `m` falls out of a single p-adic division - no discrete log search at all. Since `m < p` by construction (43-byte flag versus a 512-bit `p`), reducing the p-adic lift mod `p` recovers `m` exactly. The script closes with a direct sanity check, recomputing `m*P` and comparing it to the original lifted `Q`:

```python
check_ok = Integer(m) * Plift == Qlift
print("verification (m*P == Q):", check_ok)
```

## Exploit

[solve.sage](#Solve) hardcodes `p`, `a1`, `a2`, and the coordinates of `P`/`Q` from `output.txt`, computes `n1 = #E(F_p)`, lifts both points into `Qp(p, 5)`, kills the `E(F_p)`-component via multiplication by `n1`, applies the formal-group logarithm to linearize the remaining order-`p^4` component, recovers `m` by p-adic division, and converts it back to the 43-byte flag. [factordb](https://factordb.com/index.php?query=8056214885364405686222126654125867129615844411205519854451535576473155805503528097693676385289873006343271590361493660459789112489455666308471300926834715) is the earlier, standalone precursor that attempted to factor the curve order `n1` for a Pohlig-Hellman approach; it is not called by `solve.sage`.

Run:

```bash
sage solve.sage
```

Key steps:

- `E.order()` - computes `n1 = #E(F_p)`, the order of the easy/hard-to-avoid `F_p`-rational component.
- `Qp(p, 5)` / `EllipticCurve(R, ...)` - lifts the curve and points into a genuine p-adic field matching the challenge's `Z/p^5` precision, avoiding zero-divisor issues in `Zmod(p**5)`.
- `n1 * Plift`, `n1 * Qlift` - annihilate the `E(F_p)`-component, isolating the order-`p^4` formal-group kernel component.
- `-(x/y)` - computes the local parameter `t`, the standard uniformizer for the formal group.
- `ER.formal_group().log(prec=20)` - the formal-group logarithm that linearizes the kernel's group law.
- `Integer((logQ / logP).lift()) % p` - recovers `m` via p-adic division instead of a discrete-log search.

## Solve
```python=
p = 8056214885364405686222126654125867129615844411205519854451535576473155805503671461308303184163871680686334162003343415775884489186172469025432230101435373
a1 = 1704625448079672493725385696954489776449792965064371582831944842835294967987299772073039822182441688059147118386602445470071533689825641747045938850656920
a2 = 2761865023621674450464861320238411816379448538899506683273537115113283121281539547363316989306470150259789345310585224866168229184631297283344122088268930

Px = 31404109161421780193452637271217588346753427850955810154455319437156769041094943402981163627543634816917071618256296416183952848780141575442619852683896140003569837415186210951299111020661127129831497701671664775221729230817655637256181411221378635397359219397880935101591436272462480741008095573815389568672437544281393619238552592848256641902149434979195839008468122249169871586240568565421652821886120214539164441437410223220047780699479202967914599072984178702775039092425949270917008606545953044044352862636933054930713945787026347616069486220853883365473978065845591339032784865909204418560366635972893887387436995090185143803699607778434114381124632555352912034671469404198373517615075716157896867709539372026249040172498197918710283476267304030794688253314428826
Py = 1650165004758405364632729771756327800768600200474608342119257869412414504204784199329579632894331742735026983518426084479442387757098497079561700150857961658450089480544784314533421781546451978980208697096980763804547306056908656281768771822997440363914492676286954337494237559288134111074369815030186130293458867686949767930813966173706109642585936690477114590695292246348081195487980548198107134013176498110038095509383784015299081239268889469034948630556992012110920482977159621772707398592925499288941119548827578294412416209128220355853224464718664171917297857638133690871026304347764996898294458820280865543964677524109211893963332598572492190631704033515066903693847202637966405326462985190626763776505815625663524577810136223741873210959960936213359933786911848

Qx = 1318255284646675791538548167316756785247071836912500643400079790485961663052192807771398925779804931957009495746725249724944548760087678508510691783305777748143577200818279958834426336150225535448737258038017501009787676065109946129395047530779904234172843569090542989129998311572933531073533744921416221536028397355180559247560032395379818907934515540852948864919342314659338193659517656118991744785027582713054668293898347677484449890569657748302856508378887655265958902814440148297840919032063070475643194020966155600449415163830991206064313455753338063093458740501692071043631685367625330282424745101401175830692585629071428771509375995834341639356960103702470500337916531587033254699488994116413874921814534642064807224717040876210001515912086018703465867252769691
Qy = 14319632160412956633122525260926697791172296131626341607225710778580809856753776930572350812181316417552683677039337703258456295791669789150907678405389287273157746409586925658483389508394380281852580252839481478480484469799651721657080253221885989351458002549634814155108393856237937624782973113664794025646796746772318563624446949548824763262766657362855615490531822464622268123224719429937290550889194012193487175149041857441976919246600566193518555067472550556931009937578054730395811286629327030452435046812246638091781587593779789947231493991510346249731044404506650365296212572532182676658208665243262711007814341279577711338655525216348802597084054272404295039878931769336458705110448637408124881776289371888431470473814793261969795117401437363097973360304211473


Fp = GF(p)
E = EllipticCurve(Fp, [Fp(a1), Fp(a2)])

print("computing n1 = #E(F_p) ...")
n1 = E.order()
print("n1 =", n1)
print("gcd(n1, p) =", gcd(n1, p))

PREC = 5
R = Qp(p, PREC)
ER = EllipticCurve(R, [R(a1), R(a2)])
Plift = ER(R(Px), R(Py))
Qlift = ER(R(Qx), R(Qy))

Pk = n1 * Plift
Qk = n1 * Qlift

xP, yP = Pk.xy()
xQ, yQ = Qk.xy()

tP = -(xP / yP)
tQ = -(xQ / yQ)
print("valuations of tP, tQ:", tP.valuation(), tQ.valuation())

log_series = ER.formal_group().log(prec=20)
logP = log_series(tP)
logQ = log_series(tQ)

m = Integer((logQ / logP).lift()) % p

flag = int(m).to_bytes(43, "big")
print("m =", m)
print("flag =", flag)

# sanity check: does m*P actually reproduce Q?
check_ok = Integer(m) * Plift == Qlift
print("verification (m*P == Q):", check_ok)
if not check_ok:
    print("!! mismatch -- got:", (Integer(m) * Plift).xy())
    print("!! expected:", Qlift.xy())

```

## Verification

```text
computing n1 = #E(F_p) ...
n1 = 8056214885364405686222126654125867129615844411205519854451535576473155805503528097693676385289873006343271590361493660459789112489455666308471300926834715
gcd(n1, p) = 1
valuations of tP, tQ: 1 1
m = 6746143794948552479973616062368264558916975686092584220481293718809756025174582206074225057325402825085
flag = b'0160ca14{3ll1pt1c_curv3_ov3r_p-adic_f13ld!}'
verification (m*P == Q): True
```

## Flag

```text
0160ca14{3ll1pt1c_curv3_ov3r_p-adic_f13ld!}
```

## Lessons Learned

- A curve defined over `Z/p^kZ` instead of `F_p` is a strong signal to look at the formal group: reduction mod `p` is surjective with a kernel of size `p^(k-1)` that is *always* isomorphic to `(Z/p^(k-1)Z, +)`, regardless of how hard ECDLP is on the reduced curve.
- Multiplying a point by the order of the "hard" component (`n1 = #E(F_p)`) is a general trick for projecting onto an "easy" subgroup without ever solving a discrete log in the hard one.
- The formal-group logarithm turns elliptic-curve scalar multiplication into ordinary multiplication in the base ring for any point in the kernel of reduction - this is the same mechanism behind Smart's/SSSA's attack on anomalous curves (`#E(F_p) == p`), generalized here to `Z/p^k`.
- When a lattice/field computation risks hitting non-invertible zero divisors in a ring like `Zmod(p**k)`, lifting to the corresponding p-adic field (`Qp`/`Zp`) and tracking precision instead often sidesteps the failure entirely.
- Before committing to a heavy attack (factoring a large curve order for Pohlig-Hellman), check whether the specific ring/field the challenge uses admits a structural shortcut - the factoring precursor here was abandoned once the formal-group approach made the factorization irrelevant.
