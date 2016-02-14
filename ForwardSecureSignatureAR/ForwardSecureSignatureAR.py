from Crypto.Util import number
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.PublicKey.pubkey import *

class FSIGAR():

    def __init__(self, k, l, T, randfunc=None):
        if randfunc is None:
            randfunc = Random.new().read
        self._randfunc = randfunc
        self._k = k
        self._l = l
        self._T = T

    def randomingroup(self, N):
        while True:
            r = bignum(number.getRandomRange(3, N, self._randfunc))
            if 1 == GCD(r, N):
                return r

    def isbwinteger(self, p):
        if 3 == p % 4:
            return True
        else:
            return False


    def getbwinteger(self, bit):
        while True:
            p = bignum(number.getPrime(bit, self._randfunc))
            if self.isbwinteger(p):
                return p

    def keggen(self):
        safe=1
        p = self.getbwinteger(self._k/2)
        q = self.getbwinteger(self._k/2)
        if (p - 1)*(q - 1) < pow(2, self._k - 1):
            safe = 0
        if p*q >= pow(2, self._k):
            safe = 0

        if safe == 0:
            return None, None
        N=p*q
        while True:
            s = bignum(number.getRandomRange(3, N, self._randfunc))
            if 1 == GCD(s, N):
                break
        order = pow(2, self._l * (self._T + 1))
        temp = pow(s, order, N)
        u = inverse(temp, N)
        sk = [N, self._T, 0, s]
        pk = [N, u, self._T]
        return sk, pk

    def update(self, sk):
        if sk[2] == self._T:
            sk = None
        else:
            order = pow(2, self._l)
            sk[3] = pow(sk[3], order, sk[0])
            sk[2] += 1
        return sk

    def sign(self, M, sk):
        N = sk[0]
        T = sk[1]
        j = sk[2]
        s = sk[3]
        while True:
            r = bignum(number.getRandomRange(3, N, self._randfunc))
            if 1 == GCD(r, N):
                break
        order = pow(2, self._l * (T + 1 - j))
        y = pow(r, order, N)
        h = SHA256.new()
        h.update(long_to_bytes(j))
        h.update(long_to_bytes(y))
        h.update(M)
        sigma = h.digest()
        z = (r * pow(s, bytes_to_long(sigma), N)) % N
        return [j, [z, sigma]]

    def verify(self, M, pk, signature):
        N = pk[0]
        u = pk[1]
        T = pk[2]

        j = signature[0]
        z = signature[1][0]
        sigma = signature[1][1]

        if (z % N) == 0:
            return False
        else:
            order = pow(2, self._l * (T + 1 - j))
            y = (pow(z, order, N) * pow(u, bytes_to_long(sigma), N)) % N
            h = SHA256.new()
            h.update(long_to_bytes(j))
            h.update(long_to_bytes(y))
            h.update(M)
            result = h.digest()
            if sigma == result:
                return True
            else:
                return False

'''Test Vector'''

ar = FSIGAR(1024, 256, 10)

while True:
    sk, pk = ar.keggen()
    if sk is not None and pk is not None:
        break


sig = ar.sign("hello", sk)
print ar.verify("hello", pk, sig)

sk = ar.update(sk)
sig2 = ar.sign("hello2", sk)
print ar.verify("hello2", pk, sig2)
print ar.verify("hello", pk, sig)



