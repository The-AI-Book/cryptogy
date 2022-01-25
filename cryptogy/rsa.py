from .cipher import Cipher
import random 
import numpy as np
import math
from sympy import mod_inverse
from math import gcd
from typing import List

# Pre generated primes
first_primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                     31, 37, 41, 43, 47, 53, 59, 61, 67,
                     71, 73, 79, 83, 89, 97, 101, 103,
                     107, 109, 113, 127, 131, 137, 139,
                     149, 151, 157, 163, 167, 173, 179,
                     181, 191, 193, 197, 199, 211, 223,
                     227, 229, 233, 239, 241, 251, 257,
                     263, 269, 271, 277, 281, 283, 293,
                     307, 311, 313, 317, 331, 337, 347, 349]

def nBitRandom(n):
    return random.randrange(2**(n-1)+1, 2**n - 1)
 
def getLowLevelPrime(n):
    '''Generate a prime candidate divisible
    by first primes'''
    while True:
        # Obtain a random number
        pc = nBitRandom(n)
 
         # Test divisibility by pre-generated
         # primes
        for divisor in first_primes_list:
            if pc % divisor == 0 and divisor**2 <= pc:
                break
        else: return pc

def isPrime(mrc):
    '''Run 20 iterations of Rabin Miller Primality test'''
    maxDivisionsByTwo = 0
    ec = mrc-1
    while ec % 2 == 0:
        ec >>= 1
        maxDivisionsByTwo += 1
    assert(2**maxDivisionsByTwo * ec == mrc-1)
 
    def trialComposite(round_tester):
        if pow(round_tester, ec, mrc) == 1:
            return False
        for i in range(maxDivisionsByTwo):
            if pow(round_tester, 2**i * ec, mrc) == mrc-1:
                return False
        return True
 
    # Set number of trials here
    numberOfRabinTrials = 20
    for i in range(numberOfRabinTrials):
        round_tester = random.randrange(2, mrc)
        if trialComposite(round_tester):
            return False
    return True

def generateRandomPrimeNumber():
    """
    Generates a candidate prime number, runs Rabin Miller Primality test, it proposes another candidate if the test is failed
    """
    while True:
        prime_candidate = getLowLevelPrime(128)
        if not isPrime(prime_candidate):
            continue
        else:
            return prime_candidate


class RSACipher(Cipher):
    def __init__(self, key = None):
        super().__init__()
        self.key = self.iniKey(key)

    def validKey(self, key):
        return isPrime(key)

    def generateRandomKey(self):
        return generateRandomPrimeNumber()

    def generatePublicKey(self, pNumber : int, qNumber : int):
        n = pNumber * qNumber
        phi_n = (pNumber - 1) * (qNumber - 1)

        for i in range(phi_n - 1, 1, -1):
            if gcd(i, phi_n) == 1:
                eNumber = i
                break
        
        publicKey = (n, eNumber)
        return publicKey

    def generatePrivateKey(self, pNumber : int, qNumber : int):
        n = pNumber * qNumber
        phi_n = (pNumber - 1) * (qNumber - 1)

        for i in range(phi_n - 1, 1, -1):
            if gcd(i, phi_n) == 1:
                eNumber = i
                break
        
        dNumber = mod_inverse(eNumber, phi_n)
        privateKey = (n, dNumber)
        return privateKey

    def encode(self, pNumber : int, qNumber : int, cleartext: str = "hot", ):
        


    def decode(self, pNumber : int, qNumber : int, eNumber : int, ciphertext: str = "AXG"):  
        

if __name__ == "__main__":
