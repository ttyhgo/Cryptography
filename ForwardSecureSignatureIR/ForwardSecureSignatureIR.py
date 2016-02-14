from Crypto.PublicKey.pubkey import *
from Crypto.Util import number
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.PublicKey.pubkey import *
import time
from random import randrange, getrandbits
from itertools import repeat
import random

class FSSIR():
    def __init__(self, k, l, T, randfunc=None):
        if randfunc is None:
            self._randfunc = Random.new().read
        self._k = k
        self._l = l
        self._T = T

    def gensafeprime(self, bit):
        while True:
            q = number.getPrime(bit-1, self._randfunc)
            p = 2*q+1
            if number.isPrime(p, false_positive_prob=1e-06, randfunc=self._randfunc):
                return p

    def randomingroupstar(self, N):
        while True:
            r = number.getRandomRange(3, N, self._randfunc)
            if 1 == GCD(r, N):
                return r

    def isProbablePrime(self, n, t = 7):
        """Miller-Rabin primality test"""

        def isComposite(a):
            """Check if n is composite"""
            if pow(a, d, n) == 1:
                return False
            for i in range(s):
                if pow(a, 2 ** i * d, n) == n - 1:
                    return False
            return True

        assert n > 0
        if n < 3:
            return [False, False, True][n]
        elif not n & 1:
            return False
        else:
            s, d = 0, n - 1
            while not d & 1:
                s += 1
                d >>= 1
        for _ in repeat(None, t):
            if isComposite(randrange(2, n)):
                return False
        return True

    def getPrime(self, n):
        """Get a n-bit prime"""
        p = getrandbits(n)
        while not self.isProbablePrime(p):
            p = getrandbits(n)
        return p

    def getPrimeList(self, n, length, seed):
        random.seed(seed)
        list = []
        list.append(0)
        for i in range(1, length+1):
            list.append(self.getPrime(n))
        return list

    def keygen(self):
        p1 = self.gensafeprime(self._k/2)
        p2 = self.gensafeprime(self._k/2)

        n = p1*p2
        phin = (p1-1)*(p2-1)
        t1 = self.randomingroupstar(n)
        e= self.getPrimeList(self._l, self._T, "seed")
        '''
        for i in range(0, self._T):
            e.append(number.getPrime(self._l, self._randfunc))
       '''
        f2 = 1
        for i in range(1, self._T):
            f2 = f2*e[i] % phin

        s1 = pow(t1, f2, n)
        v = inverse(pow(s1, e[1], n), n)
        t2 = pow(t1, e[1], n)

        i = 1
        sk = [i, self._T, n, s1, t2, e[i], self._randfunc]
        pk = [n, v, self._T]

        return sk, pk

    def update(self, sk):
        j = sk[0]
        T = sk[1]
        n = sk[2]
        sj = sk[3]
        tj = sk[4]
        e = sk[5]
        randfunc = sk[6]

        if j == T-1:
            return None
        newe= self.getPrimeList(self._l, T, "seed")
        '''
        for i in range(0, self._T):
            if i <= j:
                newe.append(0)
            else:
                newe.append(getPrime(self._l, randfunc))
        '''
        sj = 1
        for i in range(j+1, T+1 ):
            sj = sj*pow(tj, newe[i], n) % n
        tj = pow(tj, newe[j+1], n)
        return (j+1, T, n, sj, tj, newe[j+1], randfunc)

    def sign(self, sk, M):
        j = sk[0]
        T = sk[1]
        n = sk[2]
        sj = sk[3]
        tj = sk[4]
        e = sk[5]
        randfunc = sk[6]

        r = self.randomingroupstar(n)
        y = pow(r, e, n)
        h = SHA256.new()
        h.update(long_to_bytes(j))
        h.update(long_to_bytes(e))
        h.update(long_to_bytes(y))
        h.update(M)
        sig = bytes_to_long(h.digest())
        z = r*pow(sj, sig, n) % n
        return [z, sig, j, e]

    def verify(self, pk, M, signature):
        n = pk[0]
        v = pk[1]
        T = pk[2]

        z = signature[0]
        sig = signature[1]
        j = signature[2]
        e = signature[3]

        #if e >= pow(2, self._l)*(1+(j+1)/T) or e < pow(2, self._l):
        #    return False
        if z % n == 0:
            return False
        y_ver = pow(z, e, n) * pow(v, sig, n) % n
        h = SHA256.new()
        h.update(long_to_bytes(j))
        h.update(long_to_bytes(e))
        h.update(long_to_bytes(y_ver))
        h.update(M)
        if sig == bytes_to_long(h.digest()):
            return True
        else:
            return False


'''Test Vector'''
fssir = FSSIR(2048, 160, 1000)

start = time.time()
sk, pk = fssir.keygen()
print "Keygen : %.8f" %(time.time() - start)

start = time.time()
signature = fssir.sign(sk, "hello")
print "Sign : %.8f" %(time.time() - start)

start = time.time()
print fssir.verify(pk, "hello", signature)
print "Verify : %.8f" %(time.time() - start)

start = time.time()
fssir.update(sk)
print "Update : %.8f" %(time.time() - start)

start = time.time()
signature2 = fssir.sign(sk, "hello2")
print "Sign : %.8f" %(time.time() - start)

start = time.time()
print fssir.verify(pk, "hello", signature)
print "Verify : %.8f" %(time.time() - start)

start = time.time()
print fssir.verify(pk, "hello2", signature2)
print "Verify : %.8f" %(time.time() - start)