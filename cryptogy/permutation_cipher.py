from cipher import Cipher, CryptAnalizer
import numpy as np
import math
import random

class PermutationCipher(Cipher):
    def __init__(self):
        super().__init__()
        self.key = self.iniKey(key)

    def validKey(self, key):
        return (key >= 0 and key <= 25)

    def generateRandomKey(self):
        return random.randint(0, 25)
        
    def encode(cleartext, key):
        encodeText = [""] * key

        for colum in range(key):
            p = colum
            while p < len(cleartext):
                encodeText[colum] += cleartext[p]
                p += key

        return "".join(encodeText).upper()

    
    def decode(ciphertext, key):

        columsNum = math.ceil(len(ciphertext) / key)
        rowsNum = key
        numShadedBoxes = (columsNum * rowsNum) - len(ciphertext)
        decodeText = [""] * columsNum
        colum = 0
        row = 0
 
        for symbol in ciphertext:
            ciphertext[colum] += symbol
            colum += 1
 
            if ((colum == columsNum)
                or (colum == columsNum - 1)
                and (row >= rowsNum - numShadedBoxes)):
                colum = 0
                row += 1
 
        return "".join(decodeText)

class PermutationCryptAnalizer(CryptAnalizer):
        def __init__(self):
            super().__init__()