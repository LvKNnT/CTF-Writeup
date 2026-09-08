# Composite Isogenies Writeup

## Summary

The challenge asks for a composite `3^13`-isogeny. The solve chains thirteen degree-3 isogenies, pushing the kernel generator forward after each step.

Flag:

```text
j(E') = 249510360818*i + 292990704480
```

## Triage

`solve.sage` contains the base curve, a point `K` of order `3^13`, and a loop that reduces the kernel order one power of 3 at a time.

## Solve Path

At each stage, scale the current kernel generator down to an order-3 point:

```python
ker_pt = (3^(order_left - 1)) * K_cur
phi = E_cur.isogeny(ker_pt)
K_cur = phi(K_cur)
E_cur = phi.codomain()
```

After 13 steps, `E_cur` is the codomain of the full composite isogeny.

## Exploit

Run:

```bash
sage solve.sage
```

## Verification

```text
$ sage solve.sage
j(E') = 249510360818*i + 292990704480
```

## Flag

```text
j(E') = 249510360818*i + 292990704480
```

## Lessons Learned

- Large prime-power isogenies can be evaluated as a chain of small-degree isogenies.
- The kernel generator must be pushed through each intermediate isogeny.
