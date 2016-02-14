from Crypto.PublicKey.pubkey import *
from Crypto.Util import number
from Crypto import Random
from Crypto.Hash import SHA256
import time

class ForwardSecureSingnature():

    def __init__(self, k, l, T, randfunc=None):
        if randfunc is None:
            randfunc = Random.new().read
        self._randfunc = randfunc
        self._k = k
        self._l = l
        self._T = T

    def isbwinteger(self, p):
        if 3 == p % 4:
            return True
        else:
            return False


    def getbwinteger(self, bit):
        while True:
            p = number.getPrime(bit, self._randfunc)
            if self.isbwinteger(p):
                return p


    def keygen(self):
        p = bignum(self.getbwinteger(self._k/2))
        q = bignum(self.getbwinteger(self._k/2))
        N = p * q
        s = list()
        u = list()
        for i in range(0, self._l):
            while True:
                temp = number.getRandomRange(3, N, self._randfunc)
                if temp < N and 1 == GCD(temp, N):
                    s.append(temp)
                    break

        for i in range(0, self._l):
            order = pow(2, self._T + 1)
            temp = pow(s[i], order, N)
            u.append(temp)

        sk = [N, self._T, 0, s]
        pk = [N, self._T, u]
        return sk, pk


    def update(self, sk):
        if sk[2] == sk[1] + 1:
            return None
        s = list()
        for i in range(0, len(sk[3])):
            temp = pow(sk[3][i], 2, sk[0])
            s.append(temp)
        sk[2] += 1
        sk[3] = s
        return sk


    def sign(self, sk, m):
        r = getRandomRange(3, sk[0], self._randfunc)
        order = pow(2, sk[1] + 1 - sk[2])
        y = pow(r, order, sk[0])
        h = SHA256.new()
        h.update(long_to_bytes(sk[2]))
        h.update(long_to_bytes(y))
        h.update(m)
        c = h.digest()
        z = r
        for i in range(0, len(sk[3])):
            temp = ceil_shift(bytes_to_long(c), i)
            if temp % 2 == 1:
                z = (z*sk[3][i]) % sk[0]
        signature = [sk[2], y, z]
        return signature


    def verify(self, pk, m, signature):
        ver = signature[1]
        h = SHA256.new()
        h.update(long_to_bytes(signature[0]))
        h.update(long_to_bytes(signature[1]))
        h.update(m)
        c = h.digest()
        for i in range(0, len(pk[2])):
            temp = ceil_shift(bytes_to_long(c), i)
            if temp % 2 == 1:
                ver = (pk[2][i] * ver) % pk[0]

        order = pow(2, pk[1] + 1 - signature[0])
        z = pow(signature[2], order, pk[0])
        if ver == z:
            return True
        else:
            return False

''' Test Vector '''

ffs = ForwardSecureSingnature()
start = time.time()
sk, pk = ffs.keygen(2048, 160, 1000)
print "Keygen : %.8f" %(time.time() - start)

start = time.time()
sig = ffs.sign(sk, "hello")
print "Sign : %.8f" %(time.time() - start)

start = time.time()
print ffs.verify(pk, "hello", sig)
print "Verify : %.8f" %(time.time() - start)

start = time.time()
sk = ffs.update(sk)
print "Update : %.8f" %(time.time() - start)

start = time.time()
print ffs.verify(pk, "hello", sig)
print "Verify : %.8f" %(time.time() - start)

start = time.time()
sig2 = ffs.sign(sk, "hello2")
print "Sign : %.8f" %(time.time() - start)

start = time.time()
print ffs.verify(pk, "hello2", sig2)
print "Verify : %.8f" %(time.time() - start)