from .cipher import Cipher
import random
from sympy import mod_inverse
from math import gcd
import binascii
from typing import List

# Pre generated primes
first_primes_list = [
    2,
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
    101,
    103,
    107,
    109,
    113,
    127,
    131,
    137,
    139,
    149,
    151,
    157,
    163,
    167,
    173,
    179,
    181,
    191,
    193,
    197,
    199,
    211,
    223,
    227,
    229,
    233,
    239,
    241,
    251,
    257,
    263,
    269,
    271,
    277,
    281,
    283,
    293,
    307,
    311,
    313,
    317,
    331,
    337,
    347,
    349,
]

def nBitRandom(n):
    return random.randrange(2 ** (n - 1) + 1, 2 ** n - 1)

def getLowLevelPrime(n):
    """Generate a prime candidate divisible
    by first primes"""
    while True:
        # Obtain a random number
        pc = nBitRandom(n)

        # Test divisibility by pre-generated
        # primes
        for divisor in first_primes_list:
            if pc % divisor == 0 and divisor ** 2 <= pc:
                break
        else:
            return pc


def isPrime(mrc):
    """Run 20 iterations of Rabin Miller Primality test"""
    maxDivisionsByTwo = 0
    ec = mrc - 1
    while ec % 2 == 0:
        ec >>= 1
        maxDivisionsByTwo += 1
    assert 2 ** maxDivisionsByTwo * ec == mrc - 1

    def trialComposite(round_tester):
        if pow(round_tester, ec, mrc) == 1:
            return False
        for i in range(maxDivisionsByTwo):
            if pow(round_tester, 2 ** i * ec, mrc) == mrc - 1:
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
    Generates a candidate prime number, runs Rabin Miller Primality test, 
    it proposes another candidate if the test is failed, 
    otherwise returns the initial candidate
    """
    while True:
        prime_candidate = getLowLevelPrime(128)
        if not isPrime(prime_candidate):
            continue
        else:
            return prime_candidate


# Text to bits.
def text_to_bits(text, encoding="utf-8", errors="surrogatepass"):
    bits = bin(int(binascii.hexlify(text.encode(encoding, errors)), 16))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))


# Int2bytes.
def int2bytes(i):
    hex_string = "%x" % i
    n = len(hex_string)
    return binascii.unhexlify(hex_string.zfill(n + (n & 1)))


# IntToString.
def int2string(i, encoding="utf-8", errors="surrogatepass"):
    bytes_ = int2bytes(i)
    print(bytes_)
    return bytes_.decode(encoding, errors)

# String to int.
def string2int(text):
    bits_ = text_to_bits(text)
    return int(bits_, 2)


# Convert a string to a list of substring of length 4 or less.
def string_to_4list(text):
    list_of_messages = list()
    pos = 0
    while pos < len(text):
        try:
            list_of_messages.append(text[pos : pos + 4])
            pos += 4
        except:
            list_of_messages.append(text[pos : len(text)])
    return list_of_messages


class RSACipher(Cipher):
    def __init__(self, key=None):
        super().__init__()

    def validKey(self, key):
        return isPrime(key[0]) and isPrime(key[1]) and key[0] != key[1]

    def setKey(self, key):
        """
        Initializes the object with a given key.
        """
        self.key = key

    def generateRandomKey(self):
        pNumber = generateRandomPrimeNumber()
        qNumber = generateRandomPrimeNumber()
        return (pNumber, qNumber)

    def generatePublicKey(self, pNumber: int, qNumber: int):
        n = pNumber * qNumber
        phi_n = (pNumber - 1) * (qNumber - 1)
        eNumber = 1
        for i in range(phi_n - 1, 1, -1):
            if gcd(i, phi_n) == 1:
                eNumber = i
                break

        publicKey = (n, eNumber)
        return publicKey

    def generatePrivateKey(self, pNumber: int, qNumber: int):
        n = pNumber * qNumber
        phi_n = (pNumber - 1) * (qNumber - 1)

        for i in range(phi_n - 1, 1, -1):
            if gcd(i, phi_n) == 1:
                eNumber = i
                break

        dNumber = mod_inverse(eNumber, phi_n)
        privateKey = (n, dNumber)
        return privateKey

    def encode(self, pNumber: int, qNumber: int, cleartext: str):
        n, eNumber = RSACipher.generatePublicKey(self, pNumber, qNumber)

        ciphertext = list()
        list_of_messages = string_to_4list(cleartext)

        for subtext in list_of_messages:

            m = string2int(subtext)
            c = pow(m, eNumber, n)
            ciphertext.append(c)

        return ciphertext

    def decode(self, pNumber: int, qNumber: int, ciphertext: list):
        n, dNumber = RSACipher.generatePrivateKey(self, pNumber, qNumber)

        cleartext = list()

        for c in ciphertext:
            m = pow(c, dNumber, n)
            cleartext.append(int2string(m))

        return "".join(cleartext)


if __name__ == "__main__":
    
    #message = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s"
    message = "helloworld"
    cipher = RSACipher()
    p, q = cipher.generateRandomKey()
    ciphertext = cipher.encode(p, q, message)
    print(ciphertext)
    for i in ciphertext:
        print(type(i))
    cleartext = cipher.decode(p, q, ciphertext)
    print(cleartext)
