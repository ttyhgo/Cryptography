from Crypto.PublicKey.pubkey import *
from Crypto.Util import number
from Crypto.Util import randpool
from Crypto import Random
from Crypto.Random import random
from Crypto.Hash import SHA256
from Crypto.PublicKey.pubkey import *
import time
import random
from random import randrange, getrandbits
from itertools import repeat



class FSSIROP():
    def __init__(self, k, l, T, randfunc=None, seed=None):
        if randfunc is None:
            self._randfunc = Random.new().read
        else:
            self._randfunc = randfunc
        if seed is None:
            self._seed = []
            self._seed.append(0)
            for i in range(1, T + 1):
                self._seed.append(long_to_bytes(i))
        else:
            self._seed = seed
        self._k = k
        self._l = l
        self._T = T
        self._L = []

    def gensafeprime(self, bit):
        while True:
            q = number.getPrime(bit - 1, self._randfunc)
            p = 2 * q + 1
            if number.isPrime(p, false_positive_prob=1e-06, randfunc=self._randfunc):
                return p

    def randomingroupstar(self, N):
        while True:
            r = number.getRandomRange(3, N, self._randfunc)
            if 1 == GCD(r, N):
                return r

    def getprimewithseed(self, bit, seed):
        random.seed(seed)
        return number.getPrime(bit, self._randfunc)

    def getPrimeList(self, bit, length, seedlist):

        list = []
        list.append(0)
        for i in range(1, length+1):
            list.append(self.getprimewithseed(bit, seedlist[i]))
        return list

    def keygen(self):

        p1 = self.gensafeprime(self._k/2)
        p2 = self.gensafeprime(self._k/2)

        n = p1 * p2
        phin = (p1 - 1) * (p2 - 1)
        t1 = self.randomingroupstar(n)
        '''
        self._e.append(0)
        for i in range(1, self._T + 1):
            self._e.append(number.getPrime(self._l, self._randfunc))
        '''
        #e = self.getPrimeList(self._l, self._T, self._seed)
        #f2 = 1
        #for i in range(1, self._T + 1):
        #    f2 = f2 * self._e[i] % phin

        #s1 = pow(t1, f2, n)
        #t2 = pow(t1, e[1], n)



        R = [t1, 1, self._T, 1, self._T]
        L = self._L
        L.append(R)
        for i in range(-((self._T - 2) / 2), 1):
            #print "pebble step ",i
            self.pebblestep(L, n)


        p =  L.pop(0)
        #print "first p",p
        s1 = p[0]
        e = self.getprimewithseed(self._l, self._seed[1])
        v = inverse(pow(s1, e, n), n)
        t2 = pow(t1, e, n)
        i = 1
        sk = [i, self._T, n, s1, t2, e, self._randfunc, L]
        pk = [n, v, self._T]
        print L
        return sk, pk

    def pebblestep(self, L, n):
        flag = 0
        i = 0
        #print "Pebble Step start"
        for p in L:
            if p[1] == p[2] or flag == 1:
                flag = 0
                None
            elif p[1] == p[3]:
                self.moveleft(p, L, i, n)
                if p[1] != p[2]:
                    self.moveleft(p, L, i, n)
                    flag = 1
            else:
                self.moveright(p, n)
            i += 1
        #print "L",L
        #print "Pebble Step End"

    def moveleft(self, p, L, i, n):
        #print "Pebble Left"
        if p[2] == p[4]:
            p1 = []
            p1.append(p[0])
            p1.append(p[1])
            p1.append(p[2])
            p1.append((p[3] + p[4] + 1) / 2)
            p1.append(p[4])
            L.insert(i+1, p1)
            p[4] = (p[3] + p[4] - 1) / 2
        e = self.getprimewithseed(self._l, self._seed[p[2]])
        p[0] = pow(p[0], e, n)
        p[2] -= 1
        #print "Pebble Left End"

    def moveright(self, p, n):
        #print "Pebble Right"
        e = self.getprimewithseed(self._l, self._seed[p[2]])
        p[0] = pow(p[0], e, n)
        p[1] += 1
        #print "Pebble Right End"

    def update(self, sk):

        j = sk[0]
        T = sk[1]
        n = sk[2]
        sj = sk[3]
        tj = sk[4]
        e = sk[5]
        randfunc = sk[6]
        L = sk[7]

        self.pebblestep(L, n)
        #print "Udating L",L
        p = L.pop(0)
        if j == T - 1:
            return None

        sj = p[0]
        e = self.getprimewithseed(self._l, self._seed[j + 1])
        tj = pow(tj, e, n)
        print "Update after L",L
        return [j + 1, T, n, sj, tj, e, randfunc, L]

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
        z = r * pow(sj, sig, n) % n
        # print sig
        return [z, sig, j, e]

    def verify(self, pk, M, signature):
        n = pk[0]
        v = pk[1]
        T = pk[2]

        z = signature[0]
        sig = signature[1]
        j = signature[2]
        e = signature[3]

        # if e >= pow(2, self._l)*(1+(j+1)/T) or e < pow(2, self._l):
        #    return False
        if z % n == 0:
            return False
        y_ver = pow(z, e, n) * pow(v, sig, n) % n
        h = SHA256.new()
        h.update(long_to_bytes(j))
        h.update(long_to_bytes(e))
        h.update(long_to_bytes(y_ver))
        h.update(M)
        # print bytes_to_long(h.digest())
        if sig == bytes_to_long(h.digest()):
            return True
        else:
            return False


'''Test Vector'''

fssir = FSSIROP(10, 10, 16)

start = time.time()
sk, pk = fssir.keygen()
print "Keygen : %.8f" % (time.time() - start)

start = time.time()
signature = fssir.sign(sk, "hello")
print "Sign : %.8f" % (time.time() - start)

start = time.time()
print fssir.verify(pk, "hello", signature)
print "Verify : %.8f" % (time.time() - start)

start = time.time()
fssir.update(sk)
print "Update : %.8f" % (time.time() - start)

start = time.time()
signature2 = fssir.sign(sk, "hello2")
print "Sign : %.8f" % (time.time() - start)

start = time.time()
print fssir.verify(pk, "hello2", signature)
print "Verify : %.8f" % (time.time() - start)

start = time.time()
print fssir.verify(pk, "hello2", signature2)
print "Verify : %.8f" % (time.time() - start)
