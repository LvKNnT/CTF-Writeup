// Exact two-dimensional lattice search for the local CHIMERA puzzle.
// Built and invoked by solve.sage; requires GMP and a C++ compiler.
#include <gmpxx.h>
#include <algorithm>
#include <chrono>
#include <iostream>

using Z = mpz_class;
struct Vec { Z x, y; };
Z dot(const Vec &u, const Vec &v) { return u.x*v.x + u.y*v.y; }
Z mod(const Z &a, const Z &m) {
    Z r; mpz_mod(r.get_mpz_t(), a.get_mpz_t(), m.get_mpz_t()); return r;
}
Z floor_div(const Z &a, const Z &b) {
    Z q; mpz_fdiv_q(q.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t()); return q;
}
Z ceil_div(const Z &a, const Z &b) {
    Z q; mpz_cdiv_q(q.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t()); return q;
}

// An exact Gauss reduction, with nearest-integer quotients.
void reduce(Vec &u, Vec &v) {
    Z un = dot(u,u), vn = dot(v,v);
    for (;;) {
        if (vn < un) { std::swap(u,v); std::swap(un,vn); }
        Z uv = dot(u,v);
        Z q = floor_div(2*uv + un, 2*un);
        if (q == 0) break;
        v.x -= q*u.x; v.y -= q*u.y;
        vn = dot(v,v);
    }
}

// Constrain lo <= m <= hi using 0 <= c*m+t <= B.
bool intersect(const Z &c, const Z &t, const Z &B, Z &lo, Z &hi, bool &set) {
    if (c == 0) return t >= 0 && t <= B;
    Z a, b;
    if (c > 0) { a=ceil_div(-t,c); b=floor_div(B-t,c); }
    else { a=ceil_div(B-t,c); b=floor_div(-t,c); }
    if (!set) { lo=a; hi=b; set=true; }
    else { if (a>lo) lo=a; if (b<hi) hi=b; }
    return lo <= hi;
}

bool candidate(const Z &r, const Z &s, const Z &offset, const Z &M,
               const Z &N, const Z &B, const Vec &u, const Vec &v,
               const Z &n, Z &p, Z &q) {
    Z tx=n*v.x, ty=n*v.y+offset, lo, hi;
    bool set=false;
    if (!intersect(u.x,tx,B,lo,hi,set) ||
        !intersect(u.y,ty,B,lo,hi,set)) return false;
    Z p0=r+M*tx, p1=M*u.x, q0=s+M*ty, q1=M*u.y;
    auto check = [&](const Z &m) {
        if (m<lo || m>hi) return false;
        p=p0+p1*m; q=q0+q1*m;
        return p>1 && q>1 && p*q==N;
    };
    if (lo==hi) return check(lo);
    // A very short lattice vector can leave many box points. Solve the
    // quadratic product equation instead of enumerating that interval.
    Z A=p1*q1, C=p0*q0-N, D=p0*q1+p1*q0;
    if (A==0) {
        if (D==0 || !mpz_divisible_p(C.get_mpz_t(),D.get_mpz_t())) return false;
        return check(Z(-C/D));
    }
    Z discriminant=D*D-4*A*C;
    if (discriminant<0 || !mpz_perfect_square_p(discriminant.get_mpz_t())) return false;
    Z root; mpz_sqrt(root.get_mpz_t(),discriminant.get_mpz_t());
    Z denominator=2*A;
    for (int sign : {-1,1}) {
        Z numerator=-D+sign*root;
        if (mpz_divisible_p(numerator.get_mpz_t(),denominator.get_mpz_t()) &&
            check(Z(numerator/denominator))) return true;
    }
    return false;
}

int main() {
    Z N, M;
    unsigned long order;
    if (!(std::cin >> N >> M >> order)) return 2;
    Z bound=((Z(1)<<384)+M-1)/M, B=bound-1;
    Z nm=mod(N,M), nm2=mod(N,Z(M*M)), r=1, ir=1;
    Z ig; mpz_invert(ig.get_mpz_t(),Z(17).get_mpz_t(),M.get_mpz_t());
    auto started=std::chrono::steady_clock::now();
    for (unsigned long a=0; a<order; ++a) {
        Z s=mod(Z(nm*ir),M);
        Z slope=mod(Z(-s*ir),M);
        // Coordinates are (k, l-offset), so l-offset = slope*k mod M.
        Vec u{0,M}, v{1,slope};
        reduce(u,v);
        // Orient the reduced basis so det(u,v)=M.
        if (u.x*v.y-u.y*v.x<0) { v.x=-v.x; v.y=-v.y; }
        Z d=mod(Z((nm2-r*s)/M),M), offset=mod(Z(d*ir),M);
        // Inverse-basis coordinates of all four corners of the box give
        // an exact integer interval for n. Usually it is empty.
        Z low=-u.x*offset, high=low, dx=u.x*B, dy=-u.y*B;
        if (dx<0) low+=dx; else high+=dx;
        if (dy<0) low+=dy; else high+=dy;
        Z nlo=ceil_div(low,M), nhi=floor_div(high,M);
        for (Z n=nlo; n<=nhi; ++n) {
            Z p,q;
            if (candidate(r,s,offset,M,N,B,u,v,n,p,q)) {
                std::cerr << "recovered residue exponent a: " << a << std::endl;
                std::cout << p << '\n' << q << std::endl;
                return 0;
            }
        }
        r=mod(Z(r*17),M); ir=mod(Z(ir*ig),M);
        if ((a+1)%100000==0) {
            auto seconds=std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now()-started).count();
            std::cerr << "residue candidates checked: " << a+1 << '/' << order
                      << " (" << seconds << "s)" << std::endl;
        }
    }
    std::cerr << "no factor found in the complete residue subgroup" << std::endl;
    return 1;
}
