from cipher import Cipher, CryptAnalizer
import random 
import numpy as np
import math
import sympy
from typing import List

class AutokeyCipher(Cipher):
    def __init__(self, key = "", key_stream = []):
        super().__init__()
        self.key = self.iniKey(key)
        self.key_stream = [self.key]

    def validKey(self, key):
        return key in range(0, 26)

    def generateRandomKey(self):
        a = random.randint(0, 25)
        return a

    def encode(self, cleartext: str = "hot"):
        a = self.key
        intList = Cipher.textToInt(cleartext)
        self.key_stream = [a] + intList[:-1]

        ciphertext = [sum(x) % 26 for x in zip(intList, self.key_stream)]
        ciphertext = ''.join( Cipher.intToText(ciphertext) )
        return ciphertext

    def decode(self, ciphertext: str = "AXG"):
        a = self.key
        ciphertext = ciphertext.lower()
        intList = Cipher.textToInt(ciphertext)
        plaintext = [(y - z) % 26 for y, z in zip(intList, self.key_stream)]
        plaintext = ''.join( Cipher.intToText(plaintext) )
        return plaintext

class AutokeyCryptAnalizer(CryptAnalizer):
    def __init__(self):
        super().__init__()

    @staticmethod
    def validKey(key): 
        return key in range(0, 26)

    def breakCipher(self, cleartext, ciphertext):
        cleartext = cleartext.lower()
        intListCleartext = Cipher.textToInt(cleartext)

        ciphertext = ciphertext.lower()
        intListCiphertext = Cipher.textToInt(ciphertext)

        keystream = [(y - z) % 26 for y, z in zip(intListCiphertext, intListCleartext)]
        k = keystream[0]
        return k, keystream

if __name__ == "__main__":
    cipher = AutokeyCipher(key = 8)
    encode = cipher.encode("rendezvous")
    print(encode)
    decode = cipher.decode(encode)
    print(decode)
    analyzer = AutokeyCryptAnalizer()
    result = analyzer.breakCipher(decode, encode)
    print(result)