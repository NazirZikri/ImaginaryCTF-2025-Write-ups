Scalar Solution
Challenge
We are given this Sage check:
assert (
  (
    (E := EllipticCurve(
      GF(0xbde3c425157a83cbe69cee172d27e2ef9c1bd754ff052d4e7e6a26074efcea673eab9438dc45e0786c4ea54a89f9079ddb21),
      [5, 7]
    )).order().factor(limit=2**10)[3][0]
    * E.lift_x(ZZ(int.from_bytes((flag := input('ictf{')).encode())))
  ).x()
  == 0x686be42f9c3f431296a928c288145a847364bb259c9f5738270d48a7fba035377cc23b27f69d6ae0fad76d745fab25d504d5
)
It:
•	Defines an elliptic curve E:y2=x3+5x+7E: y^2 = x^3 + 5x + 7E:y2=x3+5x+7 over a big prime field.
•	Lets rrr be a small factor of ∣E∣|E|∣E∣ (457).
•	Takes the flag string, interprets it as bytes → integer → xxx-coordinate, and lifts to a point PPP.
•	Checks whether x([r]P)x([r]P)x([r]P) equals the given target.
So we need to invert [r][r][r] to recover PPP, then decode its xxx-coordinate back into ASCII.
________________________________________
Step 1 – Curve order and factor
Running Sage:
#E = 1915401112…68088
r = 457
v_r(#E) = 1
That means n=∣E∣=r⋅mn = |E| = r \cdot mn=∣E∣=r⋅m with rrr dividing nnn exactly once.
________________________________________
Step 2 – Modular inverse trick
If Q=[r]PQ = [r]PQ=[r]P, then mQ=OmQ = OmQ=O.
Let s≡r−1(modm)s \equiv r^{-1} \pmod ms≡r−1(modm). Then
[r]([s]Q)=[rs]Q=[1+km]Q=Q.[r]([s]Q) = [rs]Q = [1+km]Q = Q.[r]([s]Q)=[rs]Q=[1+km]Q=Q. 
So P0=[s]QP_0 = [s]QP0=[s]Q is a valid preimage.
But [r][r][r] has kernel of size rrr, so there are rrr different preimages: P0+jTP_0 + jTP0+jT, where TTT is a generator of the kernel.
________________________________________
Step 3 – Search the coset
Enumerate all r=457r=457r=457 candidates, interpret each x(P)x(P)x(P) as bytes, and look for printable text.
________________________________________
Final Flag
ictf{mayb3_d0nt_m4ke_th3_sca1ar_a_f4ctor_0f_the_ord3r}
________________________________________
Exploit Scripts
Sage Solver (solve.sage)
# solve.sage — invert [r] when v_r(|E|)=1 and search preimages

p = 0xbde3c425157a83cbe69cee172d27e2ef9c1bd754ff052d4e7e6a26074efcea673eab9438dc45e0786c4ea54a89f9079ddb21
E = EllipticCurve(GF(p), [5, 7])
target_x = 0x686be42f9c3f431296a928c288145a847364bb259c9f5738270d48a7fba035377cc23b27f69d6ae0fad76d745fab25d504d5

n = E.order()
r = n.factor(limit=2**10)[3][0]   # 457
m = n // r

print(f"[i] #E = {n}")
print(f"[i] r = {r}, m = {m}")

Q = E.lift_x(target_x)
s = inverse_mod(r, m)
P0 = s * Q

# find kernel generator T of order r
cof = n // r
def kernel_gen():
    while True:
        R = E.random_point()
        T = cof * R
        if T != E(0) and r*T == E(0):
            return T

T = kernel_gen()

# enumerate coset and try to decode x(P)
def try_decode(xi):
    x_int = int(xi)
    raw = x_int.to_bytes((x_int.bit_length()+7)//8, 'big')
    for pad in range(0, 32):
        try:
            s = (b"\x00"*pad + raw).decode()
            if s.startswith("ictf{") and s.endswith("}"):
                return s
            if s.isprintable():
                return "ictf{" + s + "}"
        except: pass
    return None

X = P0
for j in range(r):
    flag = try_decode(X.xy()[0])
    if flag:
        print("[+] Flag:", flag)
        break
    X += T
Run with Docker:
docker run --rm -it -v "$PWD:/work" -w /work sagemath/sagemath:latest sage solve.sage
________________________________________
Pure Python Solver (solve_python.py)
from random import randrange

# Params
p = int("0xbde3c425157a83cbe69cee172d27e2ef9c1bd754ff052d4e7e6a26074efcea673eab9438dc45e0786c4ea54a89f9079ddb21", 16)
a,b = 5,7
target_x = int("0x686be42f9c3f431296a928c288145a847364bb259c9f5738270d48a7fba035377cc23b27f69d6ae0fad76d745fab25d504d5",16)
n = 1915401112669764832155688444967632063685280552714174698559105795993909088154715053733286568457561836692127326936769038088
r = 457; m = n//r

def inv(x): return pow(x,p-2,p)
def tonelli(n_,p):
    if n_%p==0: return 0
    if pow(n_,(p-1)//2,p)!=1: return None
    q,s = p-1,0
    while q%2==0: q//=2; s+=1
    z=2
    while pow(z,(p-1)//2,p)!=p-1: z+=1
    m_=s; c=pow(z,q,p); t=pow(n_,q,p); r_=pow(n_,(q+1)//2,p)
    while t!=1:
        i=1; t2=pow(t,2,p)
        while t2!=1: t2=pow(t2,2,p); i+=1
        b=pow(c,1<<(m_-i-1),p); m_=i; c=(b*b)%p; t=(t*c)%p; r_=(r_*b)%p
    return r_
O=None
def add(P,Q):
    if P is None: return Q
    if Q is None: return P
    x1,y1=P; x2,y2=Q
    if x1==x2 and (y1+y2)%p==0: return O
    if P!=Q: lam=((y2-y1)*inv((x2-x1)%p))%p
    else:
        if y1%p==0: return O
        lam=((3*x1*x1+a)*inv((2*y1)%p))%p
    x3=(lam*lam-x1-x2)%p; y3=(lam*(x1-x3)-y1)%p
    return (x3,y3)
def mul(k,P):
    R=O; Q=P
    while k>0:
        if k&1: R=add(R,Q)
        Q=add(Q,Q); k>>=1
    return R
def neg(P): return (P[0],(-P[1])%p) if P else O
def lift_x(x):
    rhs=(pow(x,3,p)+a*x+b)%p; y=tonelli(rhs,p)
    return (x,y) if y else None

Q=lift_x(target_x); Qc=[Q,neg(Q)]

# s = r^-1 mod m
def egcd(a,b):
    if b==0: return (a,1,0)
    g,x,y=egcd(b,a%b); return (g,y,x-(a//b)*y)
g,x,y=egcd(r,m); s=x%m
P0=mul(s,Q)

# kernel generator T
cof=n//r
def kernel_gen():
    while True:
        P=None
        while P is None:
            P=lift_x(randrange(1,p))
        T=mul(cof,P)
        if T and mul(r,T)==O: return T
T=kernel_gen()

# search coset
def try_flag(xi):
    raw=xi.to_bytes((xi.bit_length()+7)//8,'big')
    for pad in range(0,32):
        buf=(b"\x00"*pad)+raw
        try:
            s=buf.decode()
            if s.startswith("ictf{") and s.endswith("}"): return s
            if s.isprintable(): return "ictf{"+s+"}"
        except: pass
    return None

X=P0
for j in range(r):
    flag=try_flag(X[0])
    if flag: print(flag); break
    X=add(X,T)
Run with plain Python 3.
________________________________________
Lessons Learned
•	[k][k][k] on elliptic curves is only bijective if gcd⁡(k,∣E∣)=1\gcd(k,|E|)=1gcd(k,∣E∣)=1.
•	Using a scalar that shares a factor with the group order makes inversion possible.
•	Always ensure curve parameters are chosen so that scalars in crypto protocols are safe.
________________________________________
✅ Flag:
ictf{mayb3_d0nt_m4ke_th3_sca1ar_a_f4ctor_0f_the_ord3r}
