from .cipher import Cipher, CryptAnalizer
import numpy as np
import math
import random
from egcd import egcd
from sympy import Matrix
from itertools import combinations

class HillCipher(Cipher):
    def _init_(self, key = ""):
        super().__init__()
        self.key = self.iniKey(key)

    def generateRandomKey(self, n):
        matRand = (25 * np.random.random((n,n))).astype(int)
        return matRand

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


    def generateProperKey(key):
        keyMat = [[0] * key for i in range(key)]
        k = 0
        for i in range(3):
            for j in range(3):
                keyMat[i][j] = ord(key[k]) % 65
                k += 1
        return keyMat

    @staticmethod
    def findMultInv(det):
        multInv = -1
        for i in range(26):
            inverse = det * i
            if inverse % 26 == 1:
                multInv = i
                break
        return multInv

    @staticmethod
    def makeKey():
        det = 0
        A = None
        while True:
            cipher = input("Input 4 letter cipher: ")
            A = HillCipher.createMatrixIntToStr(cipher)
            det = A[0][0] * A[1][1] - A[0][1] * A[1][0]
            det = det % 26
            invElement = HillCipher.findMultInv(det)
            if invElement == -1:
                print("Determinant is not relatively prime to 26, uninvertible key")
            elif np.amax(A) > 26 and np.amin(A) < 0:
                print("Only a-z characters are accepted")
                print(np.amax(A), np.amin(A))
            else:
                break
        return A

    @staticmethod
    def createMatrixIntToStr(string):
        ints = [HillCipher.chrToInt(c) for c in string]
        leng = len(ints)
        M = np.zeros((2, int(leng / 2)), dtype=np.int32)
        i = 0
        for column in range(int(leng / 2)):
            for row in range(2):
                M[row][column] = ints[i]
                i += 1
        return M

    @staticmethod
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

