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
先把利用$(p+qi)\cdot (p+qi)$解p,q,发现$phi=(p^2-1)\cdot (q^2-1)$,不与$e$互质,用简单一点都AMM算法解决

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
$$seed_{i+1}=a\cdot seed_i+b\ mod\ p$$已知三十个seed的高八位

写成
{% raw %}
$$seed_{i+1}^{'}+out_{i+1}=a\cdot seed_i+a\cdot out_{i}+b\ mod\ p$$

令 
{% raw %}
$$b^{'}_i=b+a\cdot out_i-out_{i+1}$$
{% endraw %}

则
{% raw %}
$$seed_{i+1}^{'}=a\cdot seed_i+b^{'}_i\ mod\ p$$
{% endraw %}


记第一个方程为
{% raw %}
$$seed_{1}^{'}=a\cdot seed_0+b^{'}_0\ mod\ p$$
{% endraw %}

逐个带入有
{% raw %}
$$seed_{i}^{'}=a_i \cdot seed_0+b_i^{''}\ mod\ p$$
{% endraw %}

其中
{% raw %}
$$
a_i = a^{i+1}, \quad b_i^{''} = \sum_{j=1}^{n} a_{j-1} \cdot b^{'}_j
$$
{% endraw %}

所以有格

{% raw %}
$$
M=
\left(
\begin{array}{ccccc}
  p & 0 & \cdots & 0 & 0\\
  \vdots & p & \cdots & 0 & 0\\
  0 & \vdots & \ddots & \vdots & \vdots\\
  b_{0}^{''} & b_{1}^{''} & \cdots & 2^{119} &\\
  a_0 & a_{1} & \cdots & 0& 1\\
\end{array}
\right)
$$
{% endraw %}
有
{% raw %}
$$(k_0,k_1,...,k_{29},1,seed_{0}^{'})\cdot M=(seed^{'}_{1},...,seed^{'}_{29},2^{119},seed^{'}_{0})$$
{% endraw %}
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
### 反方向的秘密_相思
题目描述
```python
from Crypto.Util.number import *
import hashlib
from secrets import flag


def hash(x):
    return hashlib.sha256(x.encode()).digest()


def pad(message):
    return message + hash(str(len(message)))


m = bytes_to_long(pad(flag))
p = getStrongPrime(512)
q = getStrongPrime(512)
n = p * q
e = 3
print(pow(m, e, n))
print(n)
# 120440199294949712392334113337541924034371176306546446428347114627162894108760435789068328282135879182130546564535108930827440004987170619301799710272329673259390065147556073101312748104743572369383346039000998822862286001416166288971531241789864076857299162050026949096919395896174243383291126202796610039053
# 143413213355903851638663645270518081058249439863120739973910994223793329606595495141951165221740599158773181585002460087410975579141155680671886930801733174300593785562287068287654547100320094291092508723488470015821072834947151827362715749438612812148855627557719115676595686347541785037035334177162406305243
```
这个题目看上去是一个e=3的低加密指数的rsa加密，或许可以爆破，好吧其实不行，分析pad()有hash(str(len(message)))会泄漏256位，加上flag的"XYCTF{"前置,直接可以爆破len(message)然后一元coppersmith就好

exp
```python
from Crypto.Util.number import *
import hashlib
from tqdm import tqdm

def hash(x):
    return hashlib.sha256(x.encode()).digest()

c=120440199294949712392334113337541924034371176306546446428347114627162894108760435789068328282135879182130546564535108930827440004987170619301799710272329673259390065147556073101312748104743572369383346039000998822862286001416166288971531241789864076857299162050026949096919395896174243383291126202796610039053
n=143413213355903851638663645270518081058249439863120739973910994223793329606595495141951165221740599158773181585002460087410975579141155680671886930801733174300593785562287068287654547100320094291092508723488470015821072834947151827362715749438612812148855627557719115676595686347541785037035334177162406305243

m_high=(bytes_to_long(b"XYCTF{"))
for i in tqdm(range(5,50)):
    pad = hash(str(i+7))
    m_low = bytes_to_long(b"}" + pad)
    m_high_=m_high*2^(256 + 8 + 8*i)

    R.<x> = PolynomialRing(Zmod(n))

    f=(m_high_+m_low+x*2^(256+8))^3-c
    
    f = f.monic()
    res = f.small_roots(X=256^i)
    if(res!=[]):
        print(b"XYCTF{"+long_to_bytes(int(res[0]))+b"}")
```

### 反方向的密码_情难
题目描述：
```python
import hashlib
from Crypto.Util.number import *
from secrets import flag


def hash(x):
    return hashlib.sha512(x.encode()).digest() * 2


def pad(message):
    return (message[: len(message) // 2] + hash(str(len(message))) + message[len(message) // 2 :])


p = getStrongPrime(1024)
q = getStrongPrime(1024)
n = p * q
e = 2
m = bytes_to_long(pad(flag))
print(pow(m, e, n))
print(n)
# 3335299537518434350008670067273514020883265809787658909900831303201069228111667477512288715627313377374377192065531931991830331266940281529429758933125645068623703704431432931062515459304407129764836169638068667723468109909932687335727824459807903558617156661138991973933280805156893120951135488168923425258119689993859896540097318197048436676318334502053269738046279338047497258783747007084564814994803144049365117574904704816542523015746396519693505167963245600047742456478545640334467678554748227823020862550712083249012329745708139070338928730226897923885785783461594034339595106377701306570280371612953393097739
# 26278624299187148406559772770865336226934633734285979741424867540828670397865189685966828527168795621543490979182417570078991930822041468539855006585233692884235331084907340302530060261742100702658312435180527335101284800616106884692498603300926488358017928867672861988448488439356448543527810620591324774111321619391264173779312033252573140028630441135269056099074531502841259940379636699304810677716177080486265721322966814104627525953974143476452058638927511594884002185219080847495835727300670028011001853179659250270200020884333850083063514830095064730932997593930711871108436386821290545084229347398808220810263

```

题目大差不差，不过会有两个变量，爆破然后用二元的coppersmith就行

exp
```python

```

### babyRSAMAX
题目描述：
```python
from Crypto.Util.number import *
from gmpy2 import *
from random import choice

flag = b'XYCTF{******}'
e = '?'
def getBabyPrime(nbits):
    while True:
        p = 1
        while p.bit_length() <= nbits:
            p *= choice(sieve_base)
        
        if isPrime(p+1):
            return p+1

p = getBabyPrime(512)
q = getBabyPrime(512)
n = p*q
gift1 = (pow(p,e,n)-pow(q,e,n)) % n
gift2 = pow(p+q,e,n)

t = 65537
x = bytes_to_long(e)
y = pow(x, t, n)

m = bytes_to_long(flag)
c = powmod(m, e, n)

print(f'n = {n}')
print(f'gift1 = {gift1}')
print(f'gift2 = {gift2}')
print(f'c = {c}')
print(f'y = {y}')

'''
n = 39332423872740210783246069030855946244104982381157166843977599780233911183158560901377359925435092326653303964261550158658551518626014048783435245471536959844874036516931542444719549997971482644905523459407775392702211086149279473784796202020281909706723380472571862792003687423791576530085747716706475220532321
gift1 = 4549402444746338327349007235818187793950285105091726167573552412678416759694660166956782755631447271662108564084382098562999950228708300902201571583419116299932264478381197034402338481872937576172197202519770782458343606060544694608852844228400457232100904217062914047342663534138668490328400022651816597367310
gift2 = 111061215998959709920736448050860427855012026815376672067601244053580566359594802604251992986382187891022583247997994146019970445247509119719411310760491983876636264003942870756402328634092146799825005835867245563420135253048223898334460067523975023732153230791136870324302259127159852763634051238811969161011462
c = 16938927825234407267026017561045490265698491840814929432152839745035946118743714566623315033802681009017695526374397370343984360997903165842591414203197184946588470355728984912522040744691974819630118163976259246941579063687857994193309554129816268931672391946592680578681270693589911021465752454315629283033043
y = 1813650001270967709841306491297716908969425248888510985109381881270362755031385564927869313112540534780853966341044526856705589020295048473305762088786992446350060024881117741041260391405962817182674421715239197211274668450947666394594121764333794138308442124114744892164155894256326961605137479286082964520217

'''
```

分两次加密第一次加密第二次的e
第一次
{% raw %}
$$
\begin{aligned}
gift1 \equiv p^e-q^e \pmod n\\
gift2 \equiv (p+q)^e \pmod n
\end{aligned}
$$
{% endraw %}
把gift2展开有
{% raw %}
$$
\begin{gather*}
gift2 \equiv (p^e+q^e) \pmod n\\
gift2+gift1 \equiv 2*q^e \pmod n\\
\end{gather*}
$$
{% endraw %}
与n，gcd求解得到p,q解开第一层得到e=4096
发现GCD(e,(p-1)*(q-1))==4
分别在modp，q下求AMM开方，然后用crt求解就行

```python
from Crypto.Util.number import *
from gmpy2 import *
from random import choice
from sage.all import *

n = 39332423872740210783246069030855946244104982381157166843977599780233911183158560901377359925435092326653303964261550158658551518626014048783435245471536959844874036516931542444719549997971482644905523459407775392702211086149279473784796202020281909706723380472571862792003687423791576530085747716706475220532321
gift1 = 4549402444746338327349007235818187793950285105091726167573552412678416759694660166956782755631447271662108564084382098562999950228708300902201571583419116299932264478381197034402338481872937576172197202519770782458343606060544694608852844228400457232100904217062914047342663534138668490328400022651816597367310
gift2 = 111061215998959709920736448050860427855012026815376672067601244053580566359594802604251992986382187891022583247997994146019970445247509119719411310760491983876636264003942870756402328634092146799825005835867245563420135253048223898334460067523975023732153230791136870324302259127159852763634051238811969161011462
c = 16938927825234407267026017561045490265698491840814929432152839745035946118743714566623315033802681009017695526374397370343984360997903165842591414203197184946588470355728984912522040744691974819630118163976259246941579063687857994193309554129816268931672391946592680578681270693589911021465752454315629283033043
y = 1813650001270967709841306491297716908969425248888510985109381881270362755031385564927869313112540534780853966341044526856705589020295048473305762088786992446350060024881117741041260391405962817182674421715239197211274668450947666394594121764333794138308442124114744892164155894256326961605137479286082964520217

p=(GCD((gift1+gift2),n))
q=n//p
phi=(p-1)*(q-1)
d=gmpy2.invert(65537,phi)
e=(pow(y,d,n))
e=long_to_bytes(e)

e=4096
c_p=c%p
c_q=c%q
print(GCD(e,p-1),GCD(e,q-1))
def amm(c,p):
    list=[]
    for c_ in c:
        c__=pow(c_,((p-1)//2+1)//2,p)
        if(c__ not in list):
            list.append(c__)
            list.append(p-c__)
        
    return list
list_p=[c_p]
list_q=[c_q]
while(pow(list_p[0],e,p)!=c%p):
    list_p=amm(list_p,p)
    list_q=amm(list_q,q)
print(list_p,list_q)
for i in list_p:
    for j in list_q:
        m=crt([i,j],[p,q])
        if b"XYCTF" in long_to_bytes(m):
            print(long_to_bytes(m)) 
       
```

### easy_ecc
题目描述
```python
from Crypto.Util.number import *
from hashlib import sha256
from secret import flag, secret,SECRET

assert flag[6:-1] == sha256(long_to_bytes(secret)).hexdigest().encode()


class ECC_easy:
    def __init__(self):
        self.a = 1365855822212045061018261334821659180641576788523935479
        self.b = 17329427219955161804703200105884322768704934833367341
        self.p = 1365855822212045061018261334821659180641576788523935481

    def add(self, P, Q):
        mul_inv = lambda x: pow(x, -1, self.p)
        x1, y1 = P
        x2, y2 = Q
        if P!=Q:
            l=(y2-y1)*inverse(x2-x1,self.p)%self.p
        else:l=(3*x1**2+2*self.a*x1+1)*inverse(2*self.b*y1,self.p)%self.p
        temp1 = (self.b*l**2-self.a-x1-x2)%self.p
        temp2 = ((2*x1+x2+self.a)*l-self.b*l**3-y1)%self.p
        x3 = temp1
        y3 = temp2
        return x3, y3

    def mul(self, x, P):
        Q = SECRET
        x = x % self.p
        while x > 0:
            if x & 1:
                Q = self.add(Q, P)
            P = self.add(P, P)
            x >>= 1
        return Q

    def ispoint(self, x, y):
        return (self.a * x ** 2 + x ** 3+x) % self.p == (self.b * y ** 2) % self.p


ecc = ECC_easy()
LLLL = (1060114032187482137663886206406014543797784561116139791,752764811411303365258802649951280929945966659818544966)
assert ecc.ispoint(LLLL[0], LLLL[1])
END = ecc.mul(secret, LLLL)
print(END)

# (695174082657148306737473938393010922439779304870471540,414626357054958506867453055549756701310099524292082869)
```

是一个
{% raw %}
$$
a*x^2+x^3+x=b*y^2
$$
{% endraw %}
椭圆曲线群下的加法加密，这个是蒙哥马利曲线，转化为维尔斯特拉斯曲线
{% raw %}
$$
\begin{gather*}
蒙哥马利曲线:K*t^2=s^3+Js^2+s\\
维尔斯特拉斯曲线:y^2=x^3+Ax+B\\
A=(3-J^2)/(3*K^2)\\
B=(2*J^3-9*J)/(27*K^3)
\end{gather*}
$$
{% endraw %}

点的转化
{% raw %}
$$
\begin{gather*}
x=(3*s+j)/(2*K)\\
y=y/K 
\end{gather*}
$$
{% endraw %}

转化后发现是一个Singular Curve，用同构为一个有限域的dlp问题来求解
此时曲线可表示为
{% raw %}
$$
y^2=(x+r1)^2*(x+r2)
$$
{% endraw %}
令t=x+r1,有
{% raw %}
$$
y^2=t^3+r*t2
$$
{% endraw %}
映射
{% raw %}
$$
\phi=(y+\alpha*x)/(y-\alpha*x),\alpha^2=1 \pmod r
$$
{% endraw %}
然后dlp求解就好