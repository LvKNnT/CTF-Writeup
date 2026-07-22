# cython: language_level=3, boundscheck=False, wraparound=False, cdivision=True
# =====================================================================================
# nier_kernel.pyx -- C-speed per-point kernel for nier_flint phase 1 (GMP mpz_t).
#
# Reimplements F(v) = Res_Z(P_+(v), P_-(v)) exactly as nier_flint.py's pure-python F_at,
# but in C with reused mpz_t registers -> ~10-30x, no interpreter overhead per op.
# One NierKernel per worker process; eval_range(v0,v1) returns the F(v) as python ints.
#
# BUILD:   python setup_kernel.py build_ext --inplace     (needs cython + libgmp-dev)
# VERIFY:  nier_flint.py selftest cross-checks this against the python F_at automatically.
# =====================================================================================
from libc.stdlib cimport malloc, free

cdef extern from "gmp.h":
    ctypedef struct __mpz_struct:
        pass
    ctypedef __mpz_struct mpz_t[1]
    void mpz_init(mpz_t)
    void mpz_clear(mpz_t)
    void mpz_set(mpz_t, const mpz_t)
    void mpz_set_ui(mpz_t, unsigned long)
    int  mpz_set_str(mpz_t, const char*, int)
    void mpz_mul(mpz_t, const mpz_t, const mpz_t)
    void mpz_mul_ui(mpz_t, const mpz_t, unsigned long)
    void mpz_addmul(mpz_t, const mpz_t, const mpz_t)
    void mpz_submul(mpz_t, const mpz_t, const mpz_t)
    void mpz_add(mpz_t, const mpz_t, const mpz_t)
    void mpz_sub(mpz_t, const mpz_t, const mpz_t)
    void mpz_mod(mpz_t, const mpz_t, const mpz_t)
    void mpz_powm_ui(mpz_t, const mpz_t, unsigned long, const mpz_t)
    int  mpz_invert(mpz_t, const mpz_t, const mpz_t)
    int  mpz_sgn(const mpz_t)
    size_t mpz_sizeinbase(const mpz_t, int)
    char* mpz_get_str(char*, int, const mpz_t)


cdef mpz_t* _alloc(int n):
    cdef mpz_t* a = <mpz_t*>malloc(n * sizeof(mpz_t))
    cdef int i
    for i in range(n):
        mpz_init(a[i])
    return a

cdef void _free(mpz_t* a, int n):
    cdef int i
    for i in range(n):
        mpz_clear(a[i])
    free(a)


cdef class NierKernel:
    cdef mpz_t P
    cdef int npos, nneg, Npos, Nneg, maxN
    cdef long d, dabs
    cdef unsigned long* cpos_e
    cdef unsigned long* cneg_e
    cdef mpz_t* cpos_S
    cdef mpz_t* cneg_S
    cdef mpz_t* invk                                  # invk[k] = k^{-1} mod P
    cdef mpz_t* Pp
    cdef mpz_t* Pm
    cdef mpz_t* prodPs
    cdef mpz_t* e_sym
    # scratch registers (quotient mult / pow / side / scale / resultant)
    cdef mpz_t cc0, cc1, cc2, cc3, cc4
    cdef mpz_t pr0, pr1, pr2, bb0, bb1, bb2, tt0, tt1, tt2
    cdef mpz_t z0, z1, z2, ze0, ze1, ze2, cur0, cur1, cur2, nx0, nx1, nx2
    cdef mpz_t Sv, pk, tmpk, acc, term, vv, vd, runmul
    cdef mpz_t invlb, coef, rtmp, res, Fout

    def __cinit__(self, P_str, cpos, cneg, long d, int Npos, int Nneg):
        cdef int i, k
        mpz_init(self.P); mpz_set_str(self.P, P_str.encode(), 10)
        self.npos = len(cpos); self.nneg = len(cneg)
        self.Npos = Npos; self.Nneg = Nneg
        self.d = d; self.dabs = d if d >= 0 else -d
        self.maxN = Npos if Npos > Nneg else Nneg

        self.cpos_e = <unsigned long*>malloc(self.npos * sizeof(unsigned long))
        self.cpos_S = _alloc(self.npos)
        for i in range(self.npos):
            self.cpos_e[i] = <unsigned long>int(cpos[i][0])
            mpz_set_str(self.cpos_S[i], str(int(cpos[i][1])).encode(), 10)
        self.cneg_e = <unsigned long*>malloc(self.nneg * sizeof(unsigned long))
        self.cneg_S = _alloc(self.nneg)
        for i in range(self.nneg):
            self.cneg_e[i] = <unsigned long>int(cneg[i][0])
            mpz_set_str(self.cneg_S[i], str(int(cneg[i][1])).encode(), 10)

        self.invk = _alloc(self.maxN + 1)
        self.Pp = _alloc(self.maxN + 1); self.Pm = _alloc(self.maxN + 1)
        self.prodPs = _alloc(self.maxN + 1); self.e_sym = _alloc(self.maxN + 1)

        # mpz_t attribute registers: init exactly once.
        mpz_init(self.cc0); mpz_init(self.cc1); mpz_init(self.cc2); mpz_init(self.cc3); mpz_init(self.cc4)
        mpz_init(self.pr0); mpz_init(self.pr1); mpz_init(self.pr2)
        mpz_init(self.bb0); mpz_init(self.bb1); mpz_init(self.bb2)
        mpz_init(self.tt0); mpz_init(self.tt1); mpz_init(self.tt2)
        mpz_init(self.z0); mpz_init(self.z1); mpz_init(self.z2)
        mpz_init(self.ze0); mpz_init(self.ze1); mpz_init(self.ze2)
        mpz_init(self.cur0); mpz_init(self.cur1); mpz_init(self.cur2)
        mpz_init(self.nx0); mpz_init(self.nx1); mpz_init(self.nx2)
        mpz_init(self.Sv); mpz_init(self.pk); mpz_init(self.tmpk); mpz_init(self.acc); mpz_init(self.term)
        mpz_init(self.vv); mpz_init(self.vd); mpz_init(self.runmul)
        mpz_init(self.invlb); mpz_init(self.coef); mpz_init(self.rtmp); mpz_init(self.res); mpz_init(self.Fout)
        for k in range(1, self.maxN + 1):
            mpz_set_ui(self.tmpk, <unsigned long>k)
            mpz_invert(self.invk[k], self.tmpk, self.P)

    def __dealloc__(self):
        if self.cpos_e != NULL: free(self.cpos_e)
        if self.cneg_e != NULL: free(self.cneg_e)
        if self.cpos_S != NULL: _free(self.cpos_S, self.npos)
        if self.cneg_S != NULL: _free(self.cneg_S, self.nneg)
        if self.invk != NULL: _free(self.invk, self.maxN + 1)
        if self.Pp != NULL: _free(self.Pp, self.maxN + 1)
        if self.Pm != NULL: _free(self.Pm, self.maxN + 1)
        if self.prodPs != NULL: _free(self.prodPs, self.maxN + 1)
        if self.e_sym != NULL: _free(self.e_sym, self.maxN + 1)
        mpz_clear(self.cc0); mpz_clear(self.cc1); mpz_clear(self.cc2); mpz_clear(self.cc3); mpz_clear(self.cc4)
        mpz_clear(self.pr0); mpz_clear(self.pr1); mpz_clear(self.pr2)
        mpz_clear(self.bb0); mpz_clear(self.bb1); mpz_clear(self.bb2)
        mpz_clear(self.tt0); mpz_clear(self.tt1); mpz_clear(self.tt2)
        mpz_clear(self.z0); mpz_clear(self.z1); mpz_clear(self.z2)
        mpz_clear(self.ze0); mpz_clear(self.ze1); mpz_clear(self.ze2)
        mpz_clear(self.cur0); mpz_clear(self.cur1); mpz_clear(self.cur2)
        mpz_clear(self.nx0); mpz_clear(self.nx1); mpz_clear(self.nx2)
        mpz_clear(self.Sv); mpz_clear(self.pk); mpz_clear(self.tmpk); mpz_clear(self.acc); mpz_clear(self.term)
        mpz_clear(self.vv); mpz_clear(self.vd); mpz_clear(self.runmul)
        mpz_clear(self.invlb); mpz_clear(self.coef); mpz_clear(self.rtmp); mpz_clear(self.res); mpz_clear(self.Fout)

    # quotient GF(P)[z]/(z^3 + v z - Sv) multiply:  out = a*b   (out distinct from a,b)
    cdef void _cmul(self, mpz_t o0, mpz_t o1, mpz_t o2,
                    mpz_t a0, mpz_t a1, mpz_t a2, mpz_t b0, mpz_t b1, mpz_t b2,
                    mpz_t v, mpz_t Sv):
        mpz_mul(self.cc0, a0, b0)
        mpz_mul(self.cc1, a0, b1); mpz_addmul(self.cc1, a1, b0)
        mpz_mul(self.cc2, a0, b2); mpz_addmul(self.cc2, a1, b1); mpz_addmul(self.cc2, a2, b0)
        mpz_mul(self.cc3, a1, b2); mpz_addmul(self.cc3, a2, b1)
        mpz_mul(self.cc4, a2, b2)
        mpz_addmul(self.cc0, self.cc3, Sv);                    mpz_mod(o0, self.cc0, self.P)
        mpz_submul(self.cc1, self.cc3, v); mpz_addmul(self.cc1, self.cc4, Sv); mpz_mod(o1, self.cc1, self.P)
        mpz_submul(self.cc2, self.cc4, v);                     mpz_mod(o2, self.cc2, self.P)

    # z-side power  out = base^e  in the quotient
    cdef void _cpow(self, mpz_t o0, mpz_t o1, mpz_t o2,
                    mpz_t b0, mpz_t b1, mpz_t b2, unsigned long e, mpz_t v, mpz_t Sv):
        mpz_set_ui(self.pr0, 1); mpz_set_ui(self.pr1, 0); mpz_set_ui(self.pr2, 0)
        mpz_set(self.bb0, b0); mpz_set(self.bb1, b1); mpz_set(self.bb2, b2)
        while e > 0:
            if e & 1:
                self._cmul(self.tt0, self.tt1, self.tt2, self.pr0, self.pr1, self.pr2,
                           self.bb0, self.bb1, self.bb2, v, Sv)
                mpz_set(self.pr0, self.tt0); mpz_set(self.pr1, self.tt1); mpz_set(self.pr2, self.tt2)
            self._cmul(self.tt0, self.tt1, self.tt2, self.bb0, self.bb1, self.bb2,
                       self.bb0, self.bb1, self.bb2, v, Sv)
            mpz_set(self.bb0, self.tt0); mpz_set(self.bb1, self.tt1); mpz_set(self.bb2, self.tt2)
            e >>= 1
        mpz_set(o0, self.pr0); mpz_set(o1, self.pr1); mpz_set(o2, self.pr2)

    # composed-product poly (roots = prod r_i^{e_i}); coeffs low->high into out[0..Ntot]
    cdef void _side(self, int nsamp, unsigned long* exps, mpz_t* Ss, int Ntot, mpz_t v, mpz_t* out):
        cdef int s, k, j
        for k in range(1, Ntot + 1):
            mpz_set_ui(self.prodPs[k], 1)
        for s in range(nsamp):
            mpz_mul(self.Sv, Ss[s], v); mpz_mod(self.Sv, self.Sv, self.P)
            mpz_set_ui(self.z0, 0); mpz_set_ui(self.z1, 1); mpz_set_ui(self.z2, 0)
            self._cpow(self.ze0, self.ze1, self.ze2, self.z0, self.z1, self.z2, exps[s], v, self.Sv)
            mpz_set_ui(self.cur0, 1); mpz_set_ui(self.cur1, 0); mpz_set_ui(self.cur2, 0)
            for k in range(1, Ntot + 1):
                self._cmul(self.nx0, self.nx1, self.nx2, self.cur0, self.cur1, self.cur2,
                           self.ze0, self.ze1, self.ze2, v, self.Sv)
                mpz_set(self.cur0, self.nx0); mpz_set(self.cur1, self.nx1); mpz_set(self.cur2, self.nx2)
                mpz_mul_ui(self.pk, self.cur0, 3)                       # 3*a0
                mpz_mul_ui(self.tmpk, self.cur2, 2); mpz_mul(self.tmpk, self.tmpk, v)   # 2*v*a2
                mpz_sub(self.pk, self.pk, self.tmpk); mpz_mod(self.pk, self.pk, self.P)
                mpz_mul(self.prodPs[k], self.prodPs[k], self.pk); mpz_mod(self.prodPs[k], self.prodPs[k], self.P)
        mpz_set_ui(self.e_sym[0], 1)                                    # Newton
        for k in range(1, Ntot + 1):
            mpz_set_ui(self.acc, 0)
            for j in range(1, k + 1):
                mpz_mul(self.term, self.e_sym[k - j], self.prodPs[j])
                if (j - 1) & 1:
                    mpz_sub(self.acc, self.acc, self.term)
                else:
                    mpz_add(self.acc, self.acc, self.term)
            mpz_mod(self.acc, self.acc, self.P)
            mpz_mul(self.e_sym[k], self.acc, self.invk[k]); mpz_mod(self.e_sym[k], self.e_sym[k], self.P)
        for k in range(Ntot + 1):                                      # out[Ntot-k] = (-1)^k e[k]
            if k & 1:
                if mpz_sgn(self.e_sym[k]) != 0:
                    mpz_sub(out[Ntot - k], self.P, self.e_sym[k])
                else:
                    mpz_set_ui(out[Ntot - k], 0)
            else:
                mpz_set(out[Ntot - k], self.e_sym[k])

    cdef void _scale(self, mpz_t* poly, int deg, mpz_t vd):        # roots *= vd
        cdef int k
        mpz_set_ui(self.runmul, 1)
        for k in range(deg, -1, -1):
            mpz_mul(poly[k], poly[k], self.runmul); mpz_mod(poly[k], poly[k], self.P)
            mpz_mul(self.runmul, self.runmul, vd); mpz_mod(self.runmul, self.runmul, self.P)

    cdef void _resultant(self, mpz_t* A, int lA, mpz_t* B, int lB, mpz_t out):
        cdef mpz_t* pa = A
        cdef mpz_t* pb = B
        cdef mpz_t* tmp
        cdef int la = lA, lb = lB, m, n, top, j, dr, ti
        mpz_set_ui(self.res, 1)
        while la > 0 and mpz_sgn(pa[la - 1]) == 0: la -= 1
        while lb > 0 and mpz_sgn(pb[lb - 1]) == 0: lb -= 1
        if la == 0 or lb == 0:
            mpz_set_ui(out, 0); return
        while lb - 1 >= 1:
            m = la - 1; n = lb - 1
            mpz_invert(self.invlb, pb[lb - 1], self.P)
            while la - 1 >= n and la > 0:
                if mpz_sgn(pa[la - 1]) == 0:
                    la -= 1; continue
                mpz_mul(self.coef, pa[la - 1], self.invlb); mpz_mod(self.coef, self.coef, self.P)
                top = la - 1
                for j in range(n + 1):
                    mpz_submul(pa[top - n + j], self.coef, pb[j])
                    mpz_mod(pa[top - n + j], pa[top - n + j], self.P)
                la -= 1
            while la > 0 and mpz_sgn(pa[la - 1]) == 0: la -= 1
            if la == 0:
                mpz_set_ui(out, 0); return
            dr = la - 1
            if (m * n) & 1:
                if mpz_sgn(self.res) != 0:
                    mpz_sub(self.res, self.P, self.res)
            mpz_powm_ui(self.rtmp, pb[lb - 1], <unsigned long>(m - dr), self.P)
            mpz_mul(self.res, self.res, self.rtmp); mpz_mod(self.res, self.res, self.P)
            tmp = pa; pa = pb; pb = tmp
            ti = la; la = lb; lb = ti
        mpz_powm_ui(self.rtmp, pb[0], <unsigned long>(la - 1), self.P)
        mpz_mul(self.res, self.res, self.rtmp); mpz_mod(self.res, self.res, self.P)
        mpz_set(out, self.res)

    cdef void _F(self, unsigned long v):
        mpz_set_ui(self.vv, v); mpz_mod(self.vv, self.vv, self.P)
        self._side(self.npos, self.cpos_e, self.cpos_S, self.Npos, self.vv, self.Pp)
        self._side(self.nneg, self.cneg_e, self.cneg_S, self.Nneg, self.vv, self.Pm)
        if self.d >= 0:
            mpz_powm_ui(self.vd, self.vv, <unsigned long>self.dabs, self.P)
            self._scale(self.Pm, self.Nneg, self.vd)
        else:
            mpz_powm_ui(self.vd, self.vv, <unsigned long>self.dabs, self.P)
            self._scale(self.Pp, self.Npos, self.vd)
        self._resultant(self.Pp, self.Npos + 1, self.Pm, self.Nneg + 1, self.Fout)

    def eval_range(self, unsigned long v0, unsigned long v1):
        cdef list out = []
        cdef unsigned long v
        cdef size_t sz
        cdef char* buf
        for v in range(v0, v1):
            self._F(v)
            sz = mpz_sizeinbase(self.Fout, 10) + 2
            buf = <char*>malloc(sz)
            mpz_get_str(buf, 10, self.Fout)
            out.append(int((<bytes>buf).decode()))
            free(buf)
        return out
