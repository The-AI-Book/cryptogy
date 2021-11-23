from cipher import Cipher, CryptAnalizer
import numpy as np
import math
import random
from egcd import egcd
from sympy import Matrix
from itertools import combinations
import matplotlib.pyplot as plt
import matplotlib.image as mpimg
import numpy as gfg 

class HillCipher(Cipher):
    def _init_(self, m: int, key = ""):
        super().__init__()
        self.m = m
        self.key = self.iniKey(key)

    def generateRandomKey(self):
        matRand = (25 * np.random.random((self.m,self.m))).astype(int)
        if self.validKey(matRand):
            return matRand
        return None

    def setKey(self, key):
        return super().setKey(key)

    def validKey(self, key):
        det = int(np.round(np.linalg.det(key)))
        if det == 0:
            return False
        return True

    def encode(self, cleartext: str):
        cleartextNum = Cipher.textToInt(cleartext.lower())

        splitCleartext = [
            cleartextNum[i : i + int(self.key.shape[0])]
            for i in range(0, len(cleartextNum), int(self.key.shape[0]))
        ]

        for splitCleartextNum in splitCleartext:
            splitCleartextNum = np.transpose(np.asarray(splitCleartextNum))[:, np.newaxis]

            while splitCleartextNum.shape[0] != self.key.shape[0]:
                splitCleartextNum = np.append(splitCleartextNum, Cipher.textToInt([" "]))[:, np.newaxis]

            numbers = np.dot(self.key, splitCleartextNum) % 26
            n = numbers.shape[0]

            for idx in range(n):
                number = int(numbers[idx, 0])
            
            encodeText = Cipher.intToText(number)

        return "".join(encodeText).upper()

    def decode(self, ciphertext: str):
        keyMat = self.key
        keyInv = HillCipher.matrixModInv(keyMat, self.key)
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

    @staticmethod
    def imagToMat():
        img = mpimg.imread("imgInput.jpg")
        R, G, B = img[:,:,0], img[:,:,1], img[:,:,2]
        imgGray = 0.2989 * R + 0.5870 * G + 0.1140 * B
        imgMat = gfg.asarray(imgGray)
        return imgMat

    @staticmethod
    def matrixModInv(self):

        matrixModuInv = np.empty((self.m, self.m))
        det = int(np.round(np.linalg.det(self.key)))
        if det != 0:
            detInv = egcd(det, self.m)[1] % self.m
            matrixModuInv = (
                detInv * np.round(det * np.linalg.inv(self.key)).astype(int) % self.m
            )

        return matrixModuInv

    @staticmethod
    def generateProperKey(self, m):
        keyMat = [[0] * m for i in range(m)]
        k = 0
        for i in range(3):
            for j in range(3):
                keyMat[i][j] = ord(self.key[k]) % 65
                k += 1
        return keyMat

class HillCryptAnalizer(CryptAnalizer):
    def __init__(self):
        super().__init__()

    @staticmethod
    def validKey(key): 
        return (np.linalg.det(key) != 0)

    def breakCipher(self, ciphertext, cleartext, m):
        mat = []

        for i in range(0, len(cleartext), m):
            l_plaintext = []
            l_ciphertext = []
            for j in range(i, i + m):
                l_plaintext.append( ord(cleartext[j].upper()) - 65 )
                l_ciphertext.append( ord(ciphertext[j].upper()) - 65 )
            mat.append( (l_plaintext, l_ciphertext) )

        possible_comb_of_matrices = list( combinations(mat, m) )

        mX = []
        mY = []
        for i in possible_comb_of_matrices:
            mX.append( np.array([i[0][0], i[1][0]]) )
            mY.append( np.array([i[0][1], i[1][1]]) )

        for i in range( len(mX) ):
            detX = np.linalg.det(mX[i])
            if detX != 0:
                mat = Matrix(mX[i])
                inverseX = mat.inv_mod(26)
                K = np.dot(inverseX, mY[i])
                break

        key_guessed = K % 26
        result = "The key is: \n{}".format(key_guessed)
        return result

if __name__ == "__main__":
    cipher = HillCipher(key=1)
    cleartext = "friday"
    encode = cipher.encode(cleartext)
    print(encode)
    decode = cipher.decode(encode)
    print(decode)
    analyzer = HillCryptAnalizer()
    print( analyzer.breakCipher("pqcfku", "friday", 2) )
    
    print("cualquier cosa")
    cipher = HillCipher(key=1)
    cleartext = "helloworld"
    ciphertext = ""
    encode = Cipher.encode(cleartext, )
    print(encode)
    decode = Cipher.decode(ciphertext, )
    print(decode)

