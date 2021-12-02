from sympy.series.residues import residue
from .cipher import Cipher, CryptAnalizer
import numpy as np
from collections import deque
import math
import random
from egcd import egcd
import sympy
from sympy import Matrix
from itertools import combinations
import requests
from PIL import Image
from io import BytesIO

class HillCipher(Cipher):
    def __init__(self, m: int, key = None, permutation_cipher = False):
        super().__init__()
        #print("init cipher...")
        self.m = m
        self.permutation_cipher = permutation_cipher
        self.key = self.iniKey(key)

    def generateRandomKey(self):
        if not self.permutation_cipher:
            matRand = (25 * np.random.random((self.m,self.m))).astype(int)
            while not self.validKey(matRand):
                matRand = (25 * np.random.random((self.m,self.m))).astype(int)
            return matRand
        else: 
            identity = np.identity(self.m)
            elemental = (np.random.permutation(identity)).astype(int)
            return elemental

    def setKey(self, key):
        return super().setKey(key)

    def validKey(self, key):
        #print("valid key-----")
        try:
            #print("valid key???")
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

    def encode_image(self, image: np.array):
        new_img = np.matmul(image, self.key)
        return Image.fromarray(new_img) 

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

    def decode_image(self, image: np.array):
        key_inv = HillCipher.matrixModInv(self.key)
        new_img = np.matmul(image, key_inv) 
        return Image.fromarray(new_img)

    @staticmethod
    def imagToMat(image, resize = 128):
        img = Image.open(image)
        img = img.resize((resize, resize))
        img = np.asarray(img.convert("L"))
        return img

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

    def chrToInt(c):
        c = c.upper()
        n = ord(c) - 65
        return n

class HillCryptAnalizer(CryptAnalizer):
    def __init__(self):
        super().__init__()

    @staticmethod
    def validKey(key): 
        return (np.linalg.det(key) != 0)

    def breakCipher(self, ciphertext, cleartext, m):
        i = 0
        mat = []
        for r in range( int(len(cleartext) / m) ):
            mat.append( (list( map(HillCipher.chrToInt, cleartext[i : i+m]) ), list( map(HillCipher.chrToInt, ciphertext[i : i+m]) )) )
            i += m

        possible_comb_of_matrices = list(combinations(mat, m))

        for mat in possible_comb_of_matrices:
            possible_mat_X = deque()
            possible_mat_Y = deque()
            for j in range(m):
                possible_mat_X.append(mat[j][0])
                possible_mat_Y.append(mat[j][1])

            possible_mat_X = np.array(possible_mat_X)
            possible_mat_Y = np.array(possible_mat_Y)

            #print(possible_mat_X)
            try:
                invMat = np.array( Matrix(possible_mat_X).inv_mod(26) )
                return "Key:\n" + np.array2string(np.dot(invMat, possible_mat_Y) % 26)
            except Exception as e:
                continue
        
        raise Exception("Error: Matrix is not invertible mod 26")

if __name__ == "__main__":
    cipher = HillCipher(m = 32)
    lists = cipher.key.tolist()
    import json
    json_str = json.dumps(lists)
    print(json_str)

    #analyzer = HillCryptAnalizer()
    #print( analyzer.breakCipher("IEVQCULSWKBUQARW", "abcdefghijklmnop", 4) )