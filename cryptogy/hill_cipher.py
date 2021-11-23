from sympy.series.residues import residue
from .cipher import Cipher, CryptAnalizer
import numpy as np
import math
import random
from egcd import egcd
import sympy
from itertools import combinations
import requests
from PIL import Image
from io import BytesIO

class HillCipher(Cipher):
    def __init__(self, m: int, key = ""):
        super().__init__()
        self.m = m
        self.key = self.iniKey(key)

    def generateRandomKey(self):
        matRand = (25 * np.random.random((self.m,self.m))).astype(int)
        while not self.validKey(matRand):
            matRand = (25 * np.random.random((self.m,self.m))).astype(int)
        return matRand

    def setKey(self, key):
        return super().setKey(key)

    def validKey(self, key):
        try:
            matrix_inv = sympy.Matrix(key)
            matrix_inv = matrix_inv.inv_mod(26)
            return True
        except: 
            return False

    def encode(self, cleartext: str):
        cleartextNum = Cipher.textToInt(cleartext.lower())
        residue = len(cleartextNum) % self.m
        dummytextNum = [23] * residue
        cleartextNum = cleartextNum + dummytextNum

        splitCleartext = [
            cleartextNum[i : i + int(self.key.shape[0])]
            for i in range(0, len(cleartextNum), int(self.key.shape[0]))
        ]
        encodedText = ""
        for vector in splitCleartext:
            if len(vector) == self.key.shape[0]:
                encoded_partition = np.dot(vector, self.key) % 26
                encodedText += "".join(Cipher.intToText(encoded_partition))
        return "".join(encodedText).upper()

    def decode(self, ciphertext: str):
        ciphertext = ciphertext.lower()
        key_inv = HillCipher.matrixModInv(self.key)

        ciphertextNum = Cipher.textToInt(ciphertext)
        residue = len(ciphertextNum) % self.m
        dummytextNum = [23] * residue
        ciphertextNum = ciphertextNum + dummytextNum

        splitCiphertext = [
            ciphertextNum[i : i + int(key_inv.shape[0])]
            for i in range(0, len(ciphertextNum), int(key_inv.shape[0]))
        ]
        decodedText = ""
        for vector in splitCiphertext:
            if len(vector) == key_inv.shape[0]:
                res = np.dot(vector, key_inv) % 26
                decodedText += "".join(Cipher.intToText(res))
        return "".join(decodedText)

    @staticmethod
    def imagToMat():
        url = " "
        r = requests.get(url)

        img = Image.open(BytesIO(r.content))
        img = img.resize([32,32])
        imgTemp = np.array(img)
        imgAux = np.zeros([32,32])
        for n in (range(imgTemp.shape[0])):
            for m in (range(imgTemp.shape[1])):
                R = 0
                G = 0
                B = 0
                cont = 0
                for i in (range(imgTemp.shape[2])):
                    if i == 0: 
                        R = imgTemp[n,m,i]*0.3
                        cont = cont + R
                    elif i == 1: 
                        G = imgTemp[n,m,i]*0.59
                        cont = cont + G
                    else: 
                        B = imgTemp[n,m,i]*0.11
                        cont = cont + B
                imgAux[n,i] = cont
        """
        imgRes = PIL.Image.fromarray(np.uint8(imgAux))
        """
        
        return imgAux

    @staticmethod
    def matrixModInv(key):
        matrix_inv = sympy.Matrix(key)
        matrix_inv = matrix_inv.inv_mod(26)
        return np.array(matrix_inv)

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
                l_plaintext.append(ord(cleartext[j].upper()) - 65)
                l_ciphertext.append(ord(ciphertext[j].upper()) - 65)
            mat.append((l_plaintext, l_ciphertext))

        possible_comb_of_matrices = list(combinations(mat, m))

        mX = []
        mY = []
        for i in possible_comb_of_matrices:
            mX.append( np.array([i[0][0], i[1][0]]) )
            mY.append( np.array([i[0][1], i[1][1]]) )

        cipher = HillCipher(m = m)
        for i in range( len(mX)):
            if cipher.validKey(mX[i]):
                inverseX = HillCipher.matrixModInv(mX[i])
                K = np.dot(inverseX, mY[i])
                break

        key_guessed = K % 26
        result = "The key is: \n{}".format(key_guessed) + "\n" + cleartext
        return result

if __name__ == "__main__":
    cipher = HillCipher(m = 2, key = np.array([[11, 8], [3, 7]]))
    cleartext = "friday"
    encode = cipher.encode(cleartext)
    print(encode)
    decode = cipher.decode(encode)
    print("decoded: ", decode)
    analyzer = HillCryptAnalizer()
    print( analyzer.breakCipher("pqcfku", "friday", 2) )
    

    a = np.array([5, 17])
    b = np.array([[18, 14], [5, 14]])
    res = np.dot(a, b) % 26
    print(res)