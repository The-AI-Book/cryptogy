from .cipher import Cipher, CryptAnalizer
import numpy as np

import random 
import numpy as np
import math
import sympy
from typing import List

class StreamCipher(Cipher):
    def __init__(self):
        super().__init__()
        self.key = self.iniKey(key)

    def validKey(self, key):
        try:
            key = list(key)
        except TypeError:
            pass

    def encode(cleartext, key):
        encodeText = list(cleartext)
        n = 0
        while n < len(encodeText):
            if encodeText[n] == "A" or encodeText[n] == "a":
                encodeText[n] = 0
            elif encodeText[n] == "B" or encodeText[n] == "b":
                encodeText[n] = 1
            elif encodeText[n] == "C" or encodeText[n] == "c":
                encodeText[n] = 2
            elif encodeText[n] == "D" or encodeText[n] == "d":
                encodeText[n] = 3
            elif encodeText[n] == "E" or encodeText[n] == "e":
                encodeText[n] = 4
            elif encodeText[n] == "F" or  encodeText[n] == "f":
                encodeText[n] = 5
            elif encodeText[n] == "G" or encodeText[n] == "g":
                encodeText[n] = 6
            elif encodeText[n] == "H" or encodeText[n] == "h":
                encodeText[n] = 7
            elif encodeText[n] == "I" or encodeText[n] == "i":
                encodeText[n] = 8
            elif encodeText[n] == "J" or encodeText[n] == "j":
                encodeText[n] = 9
            elif encodeText[n] == "K" or encodeText[n] == "k":
                encodeText[n] = 10
            elif encodeText[n] == "L" or encodeText[n] == "l":
                encodeText[n] = 11
            elif encodeText[n] == "M" or encodeText[n] == "m":
                encodeText[n] = 12
            elif encodeText[n] == "N" or encodeText[n] == "n":
                encodeText[n] = 13
            elif encodeText[n] == "O" or encodeText[n] == "o":
                encodeText[n] = 14
            elif encodeText[n] == "P" or encodeText[n] == "p":
                encodeText[n] = 15
            elif encodeText[n] == "Q" or encodeText[n] == "q":
                encodeText[n] = 16
            elif encodeText[n] == "R" or encodeText[n] == "r":
                encodeText[n] = 17
            elif encodeText[n] == "S" or encodeText[n] == "s":
                encodeText[n] = 18
            elif encodeText[n] == "T" or encodeText[n] == "t":
                encodeText[n] = 19
            elif encodeText[n] == "U" or encodeText[n] == "u":
                encodeText[n] = 20
            elif encodeText[n] == "V" or encodeText[n] == "v":
                encodeText[n] = 21
            elif encodeText[n] == "W" or encodeText[n] == "w":
                encodeText[n] = 22
            elif encodeText[n] == "X" or encodeText[n] == "x":
                encodeText[n] = 23
            elif encodeText[n] == "Y" or encodeText[n] == "y":
                encodeText[n] = 24
            elif encodeText[n] == "Z" or encodeText[n] == "z":
                encodeText[n] = 25
            elif encodeText[n] == "0":
                encodeText[n] = 26
            elif encodeText[n] == "1":
                encodeText[n] = 27
            elif encodeText[n] == "2":
                encodeText[n] = 28
            elif encodeText[n] == "3":
                encodeText[n] = 29
            elif encodeText[n] == "4":
                encodeText[n] = 30
            elif encodeText[n] == "5":
                encodeText[n] = 31
            elif encodeText[n] == "6":
                encodeText[n] = 32
            elif encodeText[n] == "7":
                encodeText[n] = 33
            elif encodeText[n] == "8":
                encodeText[n] = 34
            elif encodeText[n] == "9":
                encodeText[n] = 35
            else:
                pass
            n += 1

        return "".join(encodeText).upper()
   
        
    def decode(ciphertext, key):
        decodeText = list(ciphertext)
        i = 0
        while i < len(decodeText):
            decodeText[i] = decodeText[i] - key[i % len(key)]
            while decodeText[i] < 0:
                decodeText[i] += 36
            if decodeText[i] > 35:
                decodeText[i] = decodeText[i] % 36
            i += 1

        n = 0
        while n < len(decodeText):
            if decodeText[n] == 0:
                decodeText[n] = "A"
            elif decodeText[n] == 1:
                decodeText[n] = "B"
            elif decodeText[n] == 2:
                decodeText[n] = "C"
            elif decodeText[n] == 3:
                decodeText[n] = "D"
            elif decodeText[n] == 4:
                decodeText[n] = "E"
            elif decodeText[n] == 5:
                decodeText[n] = "F"
            elif decodeText[n] == 6:
                decodeText[n] = "G"
            elif decodeText[n] == 7:
                decodeText[n] = "H"
            elif decodeText[n] == 8:
                decodeText[n] = "I"
            elif decodeText[n] == 9:
                decodeText[n] = "J"
            elif decodeText[n] == 10:
                decodeText[n] = "K"
            elif decodeText[n] == 11:
                decodeText[n] = "L"
            elif decodeText[n] == 12:
                decodeText[n] = "M"
            elif decodeText[n] == 13:
                decodeText[n] = "N"
            elif decodeText[n] == 14:
                decodeText[n] = "O"
            elif decodeText[n] == 15:
                decodeText[n] = "P"
            elif decodeText[n] == 16:
                decodeText[n] = "Q"
            elif decodeText[n] == 17:
                decodeText[n] = "R"
            elif decodeText[n] == 18:
                decodeText[n] = "S"
            elif decodeText[n] == 19:
                decodeText[n] = "T"
            elif decodeText[n] == 20:
                decodeText[n] = "U"
            elif decodeText[n] == 21:
                decodeText[n] = "V"
            elif decodeText[n] == 22:
                decodeText[n] = "W"
            elif decodeText[n] == 23:
                decodeText[n] = "X"
            elif decodeText[n] == 24:
                decodeText[n] = "Y"
            elif decodeText[n] == 25:
                decodeText[n] = "Z"
            elif decodeText[n] == 26:
                decodeText[n] = "0"
            elif decodeText[n] == 27:
                decodeText[n] = "1"
            elif decodeText[n] == 28:
                decodeText[n] = "2"
            elif decodeText[n] == 29:
                decodeText[n] = "3"
            elif decodeText[n] == 30:
                decodeText[n] = "4"
            elif decodeText[n] == 31:
                decodeText[n] = "5"
            elif decodeText[n] == 32:
                decodeText[n] = "6"
            elif decodeText[n] == 33:
                decodeText[n] = "7"
            elif decodeText[n] == 34:
                decodeText[n] = "8"
            elif decodeText[n] == 35:
                decodeText[n] = "9"
            n += 1
        return "".join(decodeText)

class AutokeyCipher(Cipher):
    def __init__(self, key = ""):
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
        return ciphertext, self.key_stream

    def decode(self, key_stream: List[int], ciphertext: str = "AXG"):
        
        print("decode")
        ciphertext = ciphertext.lower()
        print("ciphertext: ", ciphertext)
        intList = Cipher.textToInt(ciphertext)
        print(intList)
    
        plaintext = [(y - z) % 26 for y, z in zip(intList, key_stream)]
        print(plaintext)
        plaintext = ''.join( Cipher.intToText(plaintext) )
        print(plaintext)
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

        keystream = [str((y - z) % 26) for y, z in zip(intListCiphertext, intListCleartext)]
        k = keystream[0]

        string = "Keystream: " + "-".join(keystream) + "\n" + cleartext
        return string

if __name__ == "__main__":
    cipher = AutokeyCipher(key = 8)
    encode = cipher.encode("rendezvous")
    print(encode)
    decode = cipher.decode(encode)
    print(decode)
    analyzer = AutokeyCryptAnalizer()
    result = analyzer.breakCipher(decode, encode)
    print(result)
