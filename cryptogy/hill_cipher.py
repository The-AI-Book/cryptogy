from _typeshed import Self
from cipher import Cipher, CryptAnalizer
import numpy as np
import math
import random
import egcd

class HillCipher(Cipher):
    def _init_(self, key = "", alphabet = "abcdefghijklmnopqrstuvwxyz"):
        super().__init__()
        self.key = self.iniKey(key)
        self.alphabet = alphabet

    def generateRandomKey(self):
        return ""
    
    def validKey(self, key):
        return True

    def encode(self, cleartext: str, key):
        cleartextNum = Cipher.textToInt(cleartext.lower())

        splitCleartext = [
            cleartextNum[i : i + int(key.shape[0])]
            for i in range(0, len(cleartextNum), int(key.shape[0]))
        ]

        for splitCleartextNum in splitCleartext:
            splitCleartextNum = np.transpose(np.asarray(splitCleartextNum))[:, np.newaxis]

            while splitCleartextNum.shape[0] != key.shape[0]:
                splitCleartextNum = np.append(splitCleartextNum, Cipher.textToInt([" "]))[:, np.newaxis]

            numbers = np.dot(key, splitCleartextNum) % 26
            n = numbers.shape[0]  # length ciphertext (numbers)

            for idx in range(n):
                number = int(numbers[idx, 0])
            
            encodeText = Cipher.intToText(number)

        return "".join(encodeText).upper()

    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    def matrixModInv(matrix, modulus):

        det = int(np.round(np.linalg.det(matrix)))
        detInv = egcd(det, modulus)[1] % modulus 
        matrixModulusInv = (
            detInv * np.round(det * np.linalg.inv(matrix)).astype(int) % modulus
        )

        return matrixModulusInv

    def decode(self, ciphertext: str, keyInv):
        decodedText = ""
        ciphertextNum = Cipher.textToInt(ciphertext)

        splitCiphertext = [
            ciphertextNum[i : i + int(keyInv.shape[0])]
            for i in range(0, len(ciphertextNum), int(keyInv.shape[0]))
        ]

        for splitCiphertextNum in splitCiphertext:
            splitCiphertextNum = np.transpose(np.asarray(splitCiphertextNum))[:, np.newaxis]
            numbers = np.dot(keyInv, splitCiphertextNum) % 26
            n = numbers.shape[0]

            for idx in range(n):
                number = int(numbers[idx, 0])
            decodedText += Cipher.intToText(number)

        return "".join(decodedText)

class HillCryptAnalizer(CryptAnalizer):
    def __init__(self):
        super().__init__()

if __name__ == "_main_":
    cipher = HillCipher(key=1)
    cleartext = "helloworld"
    ciphertext = ""
    encode = cipher.encode(cleartext)
    print(encode)
    decode = cipher.decode(ciphertext)
    print(decode)