import math
import random
import codecs

# sobre 16 bits

def padding(plaintext):
    binary_str = bin(plaintext)
    output = binary_str + binary_str[-16:] 
    return int(output, 2)

def sqrt3mod4(a, p):
    r = pow(a, (p + 1) // 4, p)
    return r

def sqrt5mod8(a, p):
    d = pow(a, (p - 1) // 4, p)
    r =0
    if d == 1:
        r = pow(a, (p + 3) // 8, p)
    elif d == p - 1:
        r = 2 * a * pow(4 * a, (p - 5) // 8, p) % p

    return r

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, y, x = egcd(b % a, a)
        return gcd, x - (b // a) * y, y

def encryption(plaintext, n):
    plaintext = padding(plaintext)
    return plaintext ** 2 % n

def decryption(a, p, q):
    n = p * q
    r, s = 0, 0

    if p % 4 == 3:
        r = sqrt3mod4(a, p)
    elif p % 8 == 5:
        r = sqrt5mod8(a, p)

    if q % 4 == 3:
        s = sqrt3mod4(a, q)
    elif q % 8 == 5:
        s = sqrt5mod8(a, q)

    gcd, c, d = egcd(p, q)
    x = (r * d * q + s * c * p) % n
    y = (r * d * q - s * c * p) % n
    lst = [x, n - x, y, n - y]
    print (lst)
    plaintext = choose(lst)

    string = bin(plaintext)
    string = string[:-16]
    plaintext = int(string, 2)

    return plaintext

def choose(lst):

    for i in lst:
        binary = bin(i)
        append = binary[-16:]
        binary = binary[:-16]
        if append == binary[-16:]:
            return i
    return