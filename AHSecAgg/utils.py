from random import randint
from sympy.ntheory import *
import base64
from Crypto.Cipher import AES
from hashlib import sha256,md5
from Cryptodome.Cipher import AES
import numpy as np
from init import *
from Crypto.Util import Counter
import binascii
iv = '1234567887654321' #AES加密初始向量

def is_prime(num :int, test_count: int) -> bool:
    if num == 1:
        return False
    if test_count >= num:
        test_count = num - 1
    for x in range(test_count):
        val = randint(1, num - 1)
        if pow(val, num-1, num) != 1:
            return False
    return True

def generate_big_prime(n: int) -> int:
    '''
    生成n位素数
    '''
    found_prime = False
    while not found_prime:
        p = randint(2**(n-1), 2**n)
        if is_prime(p, 1000):
            return p

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def mod_inverse(k, prime):
    k = k % prime
    if k < 0:
        r = egcd(prime, -k)[2]
    else:
        r = egcd(prime, k)[2]
    return (prime + r) % prime

def binpow(aa: int, b: int, m: int) -> int:
    '''
    快速模指数运算
    :param aa：底数
    :param b：指数
    :param m；模数
    :return：以aa为底b为指数模m的运算结果
    '''
    aa = aa % m
    res = 1
    while b > 0:
        if (b & 1):
            res = res * aa % m
        aa = aa * aa % m
        b >>= 1
    return res

def extendedEuclid(aa: int, b: int) -> int:
    '''
    根据扩展的欧几里得算法求模逆
    :param aa：待求其逆元
    :param b：模数
    :return：aa在模b意义下的逆元
    '''
    x = [1, 0, aa]
    y = [0, 1, b]
    while (y[2]):
        q = x[2] // y[2]
        t = [x[0] - q * y[0], x[1] - q * y[1], x[2] - q * y[2]]
        x = y
        y = t
    return x[0] % b

def generatePrimitiveRoot(pp: int) -> int:
    '''
    生成原根
    pp是强素数
    '''
    return primitive_root(pp)

# 将原始的明文用空格填充到16字节
def AES_pad(data: str) -> str:
    pad_data = data
    for i in range(0,16-len(data)):
        pad_data = pad_data + ' '
    return pad_data
 
# 将明文用AES加密，加密模式GCM
def AES_en(key: str, data: str) -> str:
    key = hashMd5(key) #128bits
    # 将长度不足16字节的字符串补齐
    if len(data) < 16:
        data = AES_pad(data)
    # 创建加密对象
    AES_obj = AES.new(key.encode("utf-8"), AES.MODE_GCM, iv.encode("utf-8"))
    # 完成加密
    AES_en_str = AES_obj.encrypt(data.encode("utf-8"))
    # 用base64编码一下
    AES_en_str = base64.b64encode(AES_en_str)
    # 最后将密文转化成字符串
    AES_en_str = AES_en_str.decode("utf-8")
    return AES_en_str
 
def AES_de(key: str, data: str) -> str:
    # 解密过程逆着加密过程写
    # 将密文字符串重新编码成二进制形式
    key = hashMd5(key)
    data = data.encode("utf-8")
    # 将base64的编码解开
    data = base64.b64decode(data)
    # 创建解密对象
    AES_de_obj = AES.new(key.encode("utf-8"), AES.MODE_GCM, iv.encode("utf-8"))
    # 完成解密
    AES_de_str = AES_de_obj.decrypt(data)
    # 去掉补上的空格
    AES_de_str = AES_de_str.strip()
    # 对明文解码
    AES_de_str = AES_de_str.decode("utf-8")
    return AES_de_str

def hashMd5(data: str) -> str:
    return md5(data.encode('utf8')).hexdigest()

class PRG():
    def __init__(self, seed: int):
        self.seed = seed
        self.times = 1
    def genRandint(self):
        res = int(sha256(str(self.times).encode('utf8')).hexdigest()[:7], 16)
        res = binpow(res, self.seed, DHp)
        self.times += 1
        return res
    
def NdarryToStr(data: np.ndarray) -> str:
    res = ' '.join(map(str, data.ravel().tolist()))
    return res

def StrToNdarry(data: str) -> np.ndarray:
    res = np.fromstring(data, sep=' ', dtype= 'int64')
    return res

def modular_lagrange_interpolation(t,list_index, q):
    lagrange_polynomial_l =[]
    if len(list_index)<t:
        return 
    else:
        list_index=list_index[0:t]
        #ze=Element.zero(pairing,Zr)
        for i in list_index:
            # evaluate the lagrange basis polynomial l_i(x)
            numerator, denominator = 1,1
            for j in list_index:
                # don't compute a polynomial fraction if i equals j
                if i == j:
                    continue
                # compute a fraction & update the existing numerator + denominator
                numerator = (numerator * (0- j))
                denominator = (denominator * (i - j))
            # get the polynomial from the numerator + denominator mod inverse
            lagrange_polynomial_l.append(numerator * mod_inverse(denominator,q))
        return lagrange_polynomial_l

def random_polynomial(degree, intercept, q):
    """ Generates a random polynomial with positive coefficients.
    """
    if degree < 0:
        raise ValueError('Degree must be a non-negative number.')
    coefficients = [intercept]
    for i in range(degree):
        random_coeff = randint(0,q-1)
        coefficients.append(random_coeff)
    return coefficients

def get_polynomial_points(coefficients, nodelist, q):
    """ Calculates the first n polynomial points.
        [  (1, f(1)), ... ,(n, f(n)) ]
    """
    points = {}
    for x in nodelist:
        # start with x=1 and calculate the value of y
        y = coefficients[0]
        # calculate each term and add it to y, using modular math
        for i in range(1, len(coefficients)):
            exponentiation = (x**i) % q
            term = (coefficients[i] * exponentiation) % q
            y = (y + term) % q
        # add the point to the list of points
        points[x] = y
    return points

def genShares(secret: int, t: int, nodelist, q) -> dict:
    coe = random_polynomial(t-1,secret,q)
    shares = get_polynomial_points(coe, nodelist, q)
    return shares

def recon(t, nodelist: list, secrets_get: list, q) -> int:
    li=modular_lagrange_interpolation(t, nodelist, q) 
    vi=0
    for i in range(len(li)):
        vi=(vi+secrets_get[i]*li[i]) % q
    return vi

class aesPrg():
    def __init__(self, seed) -> None:
        self.key = hashMd5(str(seed))
        iv_int = int(iv, 16)
        self.ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
        self.AES_obj = AES.new(self.key.encode("utf-8"), AES.MODE_CTR, counter=self.ctr)
    def genRandint(self) -> int:

        AES_en_str = self.AES_obj.encrypt(iv.encode("utf-8"))
        #self.iv = str(int(self.iv) + 1)[0:16]
        a = str(binascii.b2a_hex(AES_en_str))[2:-1]
        return int(a,16) % DHp   