---
layout: post
title: "xyctf 2024 crypto wp review"
date: 2025-03-26
categories: [ctf, Crypto]
tags: [ctf,Crypto]
author: l0fxxs
math: true
---


## xyctf 2024 crypto wp 

### complex_dlp
题目描述
```python
from Crypto.Util.number import *
from secrets import flag


class Complex:
    def __init__(self, re, im):
        self.re = re
        self.im = im

    def __mul__(self, c):
        re_ = self.re * c.re - self.im * c.im
        im_ = self.re * c.im + self.im * c.re
        return Complex(re_, im_)

    def __str__(self):
        if self.im == 0:
            return str(self.re)
        elif self.re == 0:
            if abs(self.im) == 1:
                return f"{'-' if self.im < 0 else ''}i"
            else:
                return f"{self.im}i"
        else:
            return f"{self.re} {'+' if self.im > 0 else '-'} {abs(self.im)}i"


def complex_pow(c, exp, n):
    result = Complex(1, 0)
    while exp > 0:
        if exp & 1:
            result = result * c
            result.re = result.re % n
            result.im = result.im % n
        c = c * c
        c.re = c.re % n
        c.im = c.im % n
        exp >>= 1
    return result


flag = flag.strip(b"XYCTF{").strip(b"}")
p = 1127236854942215744482170859284245684922507818478439319428888584898927520579579027
g = Complex(3, 7)
x = bytes_to_long(flag)
print(complex_pow(g, x, p))
# 5699996596230726507553778181714315375600519769517892864468100565238657988087817 + 198037503897625840198829901785272602849546728822078622977599179234202360717671908i
```

是一个复数域的dlp问题，考虑到$N(g)^x=N(m) \ mod\ p$转化为一个正常的dlp问题，$N(a+bi)=a^2+b^2$。
exp
```python
from sage.all import * # type: ignore
from Crypto.Util.number import *

class Complex:
    def __init__(self, re, im):
        self.re = re
        self.im = im

    def __mul__(self, c):
        re_ = self.re * c.re - self.im * c.im
        im_ = self.re * c.im + self.im * c.re
        return Complex(re_, im_)

    def N(self):
        return self.re**2+self.im**2

    def __str__(self):
        if self.im == 0:
            return str(self.re)
        elif self.re == 0:
            if abs(self.im) == 1:
                return f"{'-' if self.im < 0 else ''}i"
            else:
                return f"{self.im}i"
        else:
            return f"{self.re} {'+' if self.im > 0 else '-'} {abs(self.im)}i"

p = 1127236854942215744482170859284245684922507818478439319428888584898927520579579027
g = Complex(3, 7)
P=Complex(5699996596230726507553778181714315375600519769517892864468100565238657988087817,198037503897625840198829901785272602849546728822078622977599179234202360717671908)
k = int(pari(f"znlog({Complex.N(P)}, Mod({Complex.N(g)}, {p}))"))
print(b"XYCTF{"+long_to_bytes(k)+b"}")
```

### complex_rsa

题目描述
```python
from Crypto.Util.number import *
from secrets import flag


class Complex:
    def __init__(self, re, im):
        self.re = re
        self.im = im

    def __mul__(self, c):
        re_ = self.re * c.re - self.im * c.im
        im_ = self.re * c.im + self.im * c.re
        return Complex(re_, im_)

    def __str__(self):
        if self.im == 0:
            return str(self.re)
        elif self.re == 0:
            if abs(self.im) == 1:
                return f"{'-' if self.im < 0 else ''}i"
            else:
                return f"{self.im}i"
        else:
            return f"{self.re} {'+' if self.im > 0 else '-'} {abs(self.im)}i"


def complex_pow(c, exp, n):
    result = Complex(1, 0)
    while exp > 0:
        if exp & 1:
            result = result * c
            result.re = result.re % n
            result.im = result.im % n
        c = c * c
        c.re = c.re % n
        c.im = c.im % n
        exp >>= 1
    return result


m = bytes_to_long(flag) 
key = getRandomNBitInteger(m.bit_length())
c = m ^ key
com = Complex(key, c)
p = getPrime(512)
q = getPrime(512)
e = 9
enc = complex_pow(com, e, p * q)
print(enc)
print(Complex(p, q) * Complex(p, q))
# 66350931528185981323649477263900844564494528747802437244889229343520648562164950914433406604580038018765783183569276743239888668912948977370163046257917321742455772852779551569446155827368453262479370103326286297164105599131090881306108546341785251895116423206455175290083968296281375908109039893280371271943 + 65266730684129269806656018828265187384002656633231286337130178390517924611751697965395744944541329793503617856896706439809241745206839328124348693486741656130890593895436661857688522977866438805549144904296596887218275440542852887148071837153436265722614658566275517205322945316112048487893204059562830581004i
# -28814875173103880290298835537218644402443395484370652510062722255203946330565951328874411874019897676900075613671629765922970689802650462822117767927082712245512492082864958877932682404829188622269636302484189627580600076246836248427780151681898051243380477561480415972565859837597822263289141887833338111120 + 235362412848885579543400940934854106052672292040465052424316433330114813432317923674803623227280862945857543620663672974955235166884830751834386990766053503640556408758413592161122945636548462064584183165189050320898315823173824074873376450569212651128285746330837777597290934043912373820690250920839961482862i
```
这是一个复数域的rsa问题，题目给出两个复数，一个为公钥，一个为私钥，并且题目给出的私钥的实部和虚部都是质数，并且题目给出的公钥的实部为p，虚部为q，并且题目给出的e为9。
先把利用$(p+qi)\cdot (p+qi)$解p,q,发现$phi=(p^2-1)\cdot (q^2-1),不与$e$互质,用简单一点都AMM算法解决

```python
from sage.all import * # type: ignore
from Crypto.Util.number import *
import gmpy2 
import random

class Complex:
    def __init__(self, re, im):
        self.re = re
        self.im = im

    def __mul__(self, c):
        re_ = self.re * c.re - self.im * c.im
        im_ = self.re * c.im + self.im * c.re
        return Complex(re_, im_)

    def __str__(self):
        if self.im == 0:
            return str(self.re)
        elif self.re == 0:
            if abs(self.im) == 1:
                return f"{'-' if self.im < 0 else ''}i"
            else:
                return f"{self.im}i"
        else:
            return f"{self.re} {'+' if self.im > 0 else '-'} {abs(self.im)}i"

def complex_pow(c, exp, n):
    result = Complex(1, 0)
    while exp > 0:
        if exp & 1:
            result = result * c
            result.re = result.re % n
            result.im = result.im % n
        c = c * c
        c.re = c.re % n
        c.im = c.im % n
        exp >>= 1
    return result




#开两次三次方(这是简单情况，不过够用)

def AMM(c,p):
    phi_p=p*p-1
    s_p=phi_p//3
    d_p=gmpy2.invert(3,s_p)
    l_3=[]
    
    l_3.append(complex_pow(c,d_p,p))

    for i in range(1000):
        if(len(l_3)>=5):
            break
        a=Complex(random.randint(1,p-1),random.randint(1,p-1))
        a=complex_pow(a,(p**2-1)//3,p)
        a=a*l_3[0]
        a=complex_pow(a,1,p)
        if(a not in l_3):
            l_3.append(a)
    
    l_9=[]
    for i in range(len(l_3)):
        l_9.append(complex_pow(l_3[i],d_p,p))
        for j in range(1000):
            if(len(l_9)>=10):
                break
            a=Complex(random.randint(1,p-1),random.randint(1,p-1))
            a=complex_pow(a,(p**2-1)//3,p)
            a=a*l_9[i*3]
            a=complex_pow(a,1,p)
            if(a not in l_9):
                l_9.append(a)
    return l_9


a=-28814875173103880290298835537218644402443395484370652510062722255203946330565951328874411874019897676900075613671629765922970689802650462822117767927082712245512492082864958877932682404829188622269636302484189627580600076246836248427780151681898051243380477561480415972565859837597822263289141887833338111120 
b= 235362412848885579543400940934854106052672292040465052424316433330114813432317923674803623227280862945857543620663672974955235166884830751834386990766053503640556408758413592161122945636548462064584183165189050320898315823173824074873376450569212651128285746330837777597290934043912373820690250920839961482862
var('p q')
e=9
p_q=(solve([p**2-q**2==a,2*p*q==b],p,q))
for i in p_q:
    if(i[0].rhs()>0 and i[1].rhs()>0):
        p=int(i[0].rhs())
        q=int(i[1].rhs())


enc=Complex(66350931528185981323649477263900844564494528747802437244889229343520648562164950914433406604580038018765783183569276743239888668912948977370163046257917321742455772852779551569446155827368453262479370103326286297164105599131090881306108546341785251895116423206455175290083968296281375908109039893280371271943,65266730684129269806656018828265187384002656633231286337130178390517924611751697965395744944541329793503617856896706439809241745206839328124348693486741656130890593895436661857688522977866438805549144904296596887218275440542852887148071837153436265722614658566275517205322945316112048487893204059562830581004)

enc_p=complex_pow(enc,1,p)
enc_q=complex_pow(enc,1,q)

l_p=AMM(enc_p,p)
l_q=AMM(enc_q,q)

break_=0
for i in l_p:
    if(break_==1):
        break
    for j in l_q:
        im=crt([i.im,j.im],[p,q]) # type: ignore
        re=crt([i.re,j.re],[p,q]) # type: ignore
        
        flag=long_to_bytes(im^re)
        if(b"flag" in flag):
            print(flag)
            break_=1
            break
```

### LCG_and_HNP
题目描述
```python
from Crypto.Util.number import *
import random
from secrets import flag


class LCG:
    def __init__(self, seed, a, b, p):
        self.seed = seed
        self.a = a
        self.b = b
        self.p = p

    def next(self):
        self.seed = (self.seed * self.a + self.b) % self.p
        return self.seed >> (self.p.bit_length() - 8)#s_{i+1}=s_{i}*a+b mod p


m = bytes_to_long(flag)
p = getPrime(128)
a = random.randint(1, p)
b = random.randint(1, p)
seed = random.randint(1, p)
out = []
lcg = LCG(seed, a, b, p)
for i in range(30):
    out.append(lcg.next())
key = ""
while 1:
    key += str(lcg.next())
    if int(key) >= m:
        break

with open("out.txt", "w") as f:
    f.write(f"p={p}\n")
    f.write(f"a={a}\n")
    f.write(f"b={b}\n")
    f.write(f"out={out}\n")
    f.write(f"c={int(key)^m}")

'''
p=183640370379099520304414468793633666661
a=36108041497607074474855679331694767924
b=65925932211985158779695144876342622462
out=[34, 95, 100, 114, 16, 23, 17, 118, 115, 29, 73, 47, 12, 133, 78, 30, 30, 73, 87, 15, 85, 47, 20, 136, 6, 106, 74, 27, 116, 8]
c=6003642257316152022364486167163125577018867662610595926973616937741281227891381713617380
'''
```
大概是一个lcg生成随机数，a,b,p已知，seed的一些高位泄漏，求seed，最后在运算一些seed与c异或即可
$seed_{i+1}=a\cdot seed_i+b\ mod\ p$已知三十个seed的高八位

写成
{% raw %}
$seed_{i+1}^{'}+out_{i+1}=a\cdot seed_i+a\cdot out_{i}+b\ mod\ p$
{% endraw %}
令$b^{'}_i=b+a\cdot out_i-out_{i+1}$则
$seed_{i+1}^{'}=a\cdot seed_i+b^{'}_i\ mod\ p$

记第一个方程为$seed_{1}^{'}=a\cdot seed_0+b^{'}_0\ mod\ p$
逐个带入有$seed_{i}^{'}=a_i \cdot seed_0+b_i^{''}\ mod\ p$,  其中$a_i=a^{i+1}$,$b_i^{''}=\sum_{i=1}^{n} a_{i-1}i\cdot b^{'}_i$
所以有格
\[M=
\left(
\begin{array}{ccc}
  p & 0 & 0 & 0 & 0\\
  \vdots & p & 0 & 0 & 0\\
  0 &  & \ddots & \vdots & \vdots\\
  b_{0}^{''} & b_{1}^{''} & \cdots & 2^{119} &\\
  a_0 & a_{1} & \cdots & 0& 1\\
\end{array}
\right)
\]
有
$(k_0,k_1,...,k_{29},1,seed_{0}^{'})\cdot M=(seed^{'}_{1},...,seed^{'}_{29},2^{119},seed^{'}_{0})$
用LLL算法即可得到

exp
```python
from Crypto.Util.number import *
import gmpy2 
from sage.all import * # type: ignore

p=183640370379099520304414468793633666661
a=36108041497607074474855679331694767924
b=65925932211985158779695144876342622462
out=[34, 95, 100, 114, 16, 23, 17, 118, 115, 29, 73, 47, 12, 133, 78, 30, 30, 73, 87, 15, 85, 47, 20, 136, 6, 106, 74, 27, 116, 8]
c=6003642257316152022364486167163125577018867662610595926973616937741281227891381713617380

b_i=[]
for i in range(len(out)-1):
    b_i.append(((out[i]<< (p.bit_length() - 8))*a+b-(out[i+1]<< (p.bit_length() - 8)))%p)
b_i_=[]
for i in range(len(b_i)):
    b_i_.append(0)
    for j in range(i+1):
        b_i_[i]+=(b_i[j]*pow(a,i-j,p))%p
    b_i_[i]=(b_i_[i])%p


a_i=[]
for i in range(len(b_i)):
    a_i.append(pow(a,i+1,p))

M=matrix(ZZ,len(b_i)+2,len(b_i)+2) # type: ignore
for i in range(len(b_i)):
    M[i,i]=p
    M[len(b_i),i]=b_i_[i]
    M[len(b_i)+1,i]=a_i[i]

M[len(b_i),len(b_i)]=2**119
M[len(b_i)+1,len(b_i)+1]=1
M=M.LLL()
seed=[]
for i in range(len(b_i)+2):
    # if(abs(M[i,-2])==2**120):
        
    if((M[i,0]*a+b_i[1])%p==(M[i,1])%p and (M[i,1]*a+b_i[2])%p==(M[i,2])%p and (M[i,2]*a+b_i[3])%p==(M[i,3]) and (M[i,3]*a+b_i[4])%p==(M[i,4])):
        seed.append(M[i,-6]%p+(out[-4]<< (p.bit_length() - 8)))
        seed.append(M[i,-5]%p+(out[-3]<< (p.bit_length() - 8)))
        seed.append(M[i,-4]%p+(out[-2]<< (p.bit_length() - 8)))
        seed.append(M[i,-3]%p+(out[-1]<< (p.bit_length() - 8)))

class LCG:
    def __init__(self, seed, a, b, p):
        self.seed = seed
        self.a = a
        self.b = b
        self.p = p

    def next(self):
        self.seed = (self.seed * self.a + self.b) % self.p
        return self.seed >> (self.p.bit_length() - 8)

lcg = LCG(seed[3], a, b, p)

key = ""
while 1:
    key += str(lcg.next())
    if int(key) >= c:
        break

print(long_to_bytes(c^int(key)))
```










