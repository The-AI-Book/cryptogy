from cipher import Cipher, CryptAnalizer
import numpy as np
import math
import random
from egcd import egcd

class HillCipher(Cipher):
    def _init_(self, key = ""):
        super().__init__()
        self.key = self.iniKey(key)

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

    def matrixModInv(matrix, modu):

        det = int(np.round(np.linalg.det(matrix)))
        detInv = egcd(det, modu)[1] % modu 
        matrixModuInv = (
            detInv * np.round(det * np.linalg.inv(matrix)).astype(int) % modu
        )

        return matrixModuInv

    def decode(self, ciphertext: str, key):
        keyMat = generateProperKey(key)
        keyInv = matrixModInv(keyMat, key)
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

        def generateRandomKey(self, n):
            matRand = 26*np.random.random((n,n))
            return matRand

        def generateProperKey(key):
            keyMat = [[0] * key for i in range(key)]
            k = 0
            for i in range(3):
                for j in range(3):
                    keyMat[i][j] = ord(key[k]) % 65
                    k += 1
            return keyMat

class HillCryptAnalizer(CryptAnalizer):
    def __init__(self):
        super().__init__()

if __name__ == "__main__":
    print("cualquier cosa")
    cipher = HillCipher(key=1)
    cleartext = "helloworld"
    ciphertext = ""
    encode = Cipher.encode(cleartext, )
    print(encode)
    decode = Cipher.decode(ciphertext, )
    print(decode)