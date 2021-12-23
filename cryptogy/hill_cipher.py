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
    def __init__(self, m: int, key = None, permutation_cipher = False, force_key = False):
        super().__init__()
        #print("init cipher...")
        self.m = m
        self.permutation_cipher = permutation_cipher
        if not force_key:
            self.key = self.iniKey(key)
        else: 
            self.key = key

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

    def decode_image(self, image: np.array, key_inv: np.array = None):
        if key_inv is None:
            key_inv = HillCipher.matrixModInv(self.key)
        new_img = np.matmul(key_inv, image) 
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
    #cipher = HillCipher(m = 32)
    #lists = cipher.key.tolist()
    #import json
    #json_str = json.dumps(lists)
    #print(json_str)

    #analyzer = HillCryptAnalizer()
    #print( analyzer.breakCipher("IEVQCULSWKBUQARW", "abcdefghijklmnop", 4) )

    import numpy as np
    key = np.array(  
    [[11, 1, 14, 16, 1, 14, 14, 1, 21, 13, 14, 5, 10, 24, 21, 14, 15, 10, 4, 1, 12, 6, 13, 0, 11, 16, 5, 23, 10, 15, 16, 4], 
    [4, 2, 16, 23, 24, 24, 0, 14, 17, 2, 15, 16, 18, 11, 8, 22, 22, 14, 13, 4, 17, 14, 14, 14, 1, 14, 17, 14, 4, 15, 8, 2], 
    [23, 9, 10, 3, 11, 12, 16, 12, 18, 16, 21, 20, 17, 1, 1, 7, 10, 2, 8, 18, 13, 7, 2, 3, 19, 19, 15, 20, 2, 2, 14, 11], 
    [21, 8, 10, 16, 9, 18, 1, 13, 10, 12, 7, 17, 10, 22, 16, 5, 3, 2, 2, 1, 8, 14, 20, 4, 14, 0, 16, 6, 4, 1, 1, 8], 
    [24, 19, 9, 24, 4, 9, 8, 7, 13, 7, 8, 13, 0, 10, 13, 21, 12, 2, 6, 1, 22, 14, 14, 19, 8, 14, 8, 15, 15, 6, 8, 21], 
    [24, 22, 1, 7, 9, 13, 19, 15, 6, 16, 24, 20, 14, 17, 12, 13, 6, 8, 6, 20, 2, 18, 5, 10, 12, 11, 11, 21, 12, 18, 14, 6],
    [21, 23, 16, 9, 22, 24, 22, 16, 4, 15, 1, 22, 22, 22, 13, 19, 23, 17, 8, 22, 1, 17, 18, 19, 10, 5, 6, 19, 23, 1, 17, 2], 
    [20, 3, 13, 24, 0, 5, 7, 18, 2, 18, 15, 13, 21, 24, 19, 13, 8, 10, 15, 3, 10, 11, 2, 20, 23, 11, 15, 3, 9, 1, 21, 16], 
    [0, 16, 12, 24, 6, 11, 16, 1, 20, 16, 2, 4, 7, 1, 11, 19, 22, 11, 2, 2, 11, 6, 16, 24, 19, 23, 8, 13, 13, 13, 6, 9], 
    [0, 16, 9, 22, 15, 3, 3, 16, 24, 11, 13, 20, 15, 9, 15, 18, 9, 10, 24, 21, 6, 10, 0, 7, 21, 8, 21, 15, 14, 11, 13, 5], 
    [21, 24, 14, 1, 16, 19, 18, 12, 20, 11, 12, 2, 1, 13, 6, 3, 22, 22, 6, 2, 15, 6, 17, 4, 22, 0, 22, 9, 19, 7, 6, 9], 
    [24, 6, 6, 12, 19, 14, 16, 16, 17, 21, 20, 19, 24, 13, 12, 9, 9, 20, 4, 20, 22, 1, 6, 9, 18, 12, 12, 5, 20, 15, 4, 20], 
    [17, 14, 24, 12, 2, 1, 1, 4, 22, 10, 7, 2, 15, 18, 6, 24, 7, 10, 20, 9, 3, 5, 23, 16, 23, 18, 14, 5, 22, 4, 13, 5], 
    [16, 3, 10, 13, 10, 11, 18, 17, 12, 2, 15, 6, 14, 16, 22, 17, 11, 22, 2, 4, 4, 8, 17, 7, 20, 19, 11, 15, 1, 21, 0, 13], 
    [1, 16, 6, 4, 14, 3, 16, 0, 8, 8, 8, 22, 14, 18, 2, 10, 11, 4, 21, 7, 8, 20, 17, 4, 8, 11, 12, 17, 8, 13, 0, 3], 
    [0, 16, 12, 23, 13, 21, 15, 19, 6, 9, 21, 19, 3, 14, 12, 9, 20, 11, 10, 8, 4, 22, 7, 10, 23, 10, 10, 19, 22, 2, 5, 24], 
    [0, 14, 4, 11, 4, 16, 12, 14, 20, 17, 7, 3, 8, 6, 14, 1, 17, 0, 10, 24, 20, 3, 15, 16, 13, 6, 11, 5, 19, 8, 18, 11], 
    [5, 10, 22, 24, 15, 13, 1, 7, 23, 22, 16, 1, 18, 17, 5, 16, 16, 1, 14, 22, 13, 11, 11, 9, 11, 20, 14, 5, 22, 11, 13, 7], 
    [22, 11, 18, 23, 12, 5, 24, 14, 14, 16, 6, 22, 1, 17, 24, 2, 2, 10, 20, 5, 1, 18, 14, 13, 6, 5, 22, 1, 5, 22, 5, 7], 
    [11, 8, 1, 19, 4, 11, 14, 4, 2, 17, 11, 22, 4, 21, 16, 4, 8, 16, 20, 18, 20, 10, 24, 14, 1, 15, 19, 3, 17, 10, 19, 13], 
    [20, 3, 22, 9, 19, 1, 1, 8, 16, 23, 5, 7, 13, 4, 23, 13, 19, 15, 4, 22, 13, 8, 1, 22, 11, 14, 18, 21, 13, 13, 10, 5], 
    [4, 1, 5, 20, 18, 4, 15, 20, 4, 7, 3, 7, 10, 15, 21, 4, 18, 16, 17, 13, 12, 21, 5, 2, 6, 13, 19, 21, 0, 24, 11, 16], 
    [24, 10, 19, 6, 0, 19, 10, 10, 20, 3, 9, 16, 19, 22, 2, 14, 9, 11, 16, 22, 3, 1, 5, 0, 5, 17, 17, 21, 2, 14, 12, 2], 
    [13, 2, 22, 5, 17, 12, 4, 22, 7, 23, 5, 24, 9, 5, 6, 19, 22, 3, 17, 6, 24, 17, 14, 9, 4, 19, 4, 4, 17, 12, 18, 7], 
    [6, 15, 23, 22, 12, 16, 9, 4, 1, 24, 14, 24, 1, 21, 10, 4, 20, 12, 14, 3, 5, 3, 5, 23, 8, 16, 2, 14, 2, 22, 11, 22], 
    [5, 14, 1, 1, 5, 0, 12, 20, 18, 2, 9, 11, 15, 12, 21, 3, 23, 4, 14, 1, 8, 4, 13, 6, 16, 13, 10, 20, 7, 6, 18, 24], 
    [22, 4, 4, 23, 6, 3, 7, 1, 0, 0, 14, 24, 14, 22, 5, 0, 10, 8, 5, 19, 2, 3, 10, 18, 13, 5, 14, 8, 0, 4, 23, 10], 
    [18, 18, 10, 9, 22, 0, 21, 24, 23, 3, 0, 1, 13, 16, 17, 16, 19, 13, 1, 6, 1, 24, 9, 2, 5, 22, 4, 21, 16, 10, 17, 9], 
    [12, 14, 20, 9, 21, 8, 0, 22, 14, 17, 10, 13, 19, 24, 11, 6, 23, 18, 4, 21, 12, 20, 1, 4, 13, 0, 2, 8, 7, 24, 3, 1], 
    [7, 8, 11, 15, 22, 24, 5, 0, 5, 24, 9, 16, 18, 17, 0, 2, 5, 4, 13, 16, 5, 18, 8, 2, 1, 17, 20, 6, 2, 6, 2, 13], 
    [12, 0, 19, 11, 4, 23, 8, 24, 4, 20, 18, 2, 14, 19, 3, 4, 8, 24, 0, 16, 7, 2, 20, 4, 24, 21, 20, 16, 22, 14, 10, 12], 
    [20, 14, 2, 23, 3, 11, 21, 2, 4, 1, 20, 14, 13, 4, 10, 13, 13, 18, 23, 24, 12, 20, 7, 8, 20, 17, 22, 8, 13, 9, 5, 19]])
    #res = HillCipher.matrixModInv(key)
    #np.savetxt("inv_matrix.txt", np.array(res).astype(int), delimiter = ",")