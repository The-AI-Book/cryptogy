from cipher import Cipher, CryptAnalizer
import numpy as np

class HillCipher(Cipher):
    def _init_(self, key = ""):
        self.key = self.iniKey(key)

    def generateRandomKey(self):
        return ""
    
    def validKey(self, key):
        #
        #
        #
        return super().validKey(key)

    def encode(self, cleartext: str):
        m = cleartext.replace(" ", "")
        C = makeKey()
        len_check = len(m) % 2 == 0
        if not len_check:
            m += "0"
        P = HillCipher.createMatrixIntToStr(m)
        m_len = int(len(m) / 2)
        encodeText = ""
        for i in range(m_len):
            row_0 = P[0][i] * C[0][0] + P[1][i] * C[0][1]
            integer = int(row_0 % 26 + 65)
            encodeText += chr(integer)
            row_1 = P[0][i] * C[1][0] + P[1][i] * C[1][1]
            integer = int(row_1 % 26 + 65)
            encodeText += chr(integer)
        return "".join(encodeText).upper()

    def decode(self, ciphertext: str =""):
        A = HillCipher.makeKey()
        det = A[0][0] * A[1][1] - A[0][1] * A[1][0]
        det = det % 26
        multInv = HillCipher.findMultInv(det)
        A_inv = A
        A_inv[0][0], A_inv[1][1] = A_inv[1, 1], A_inv[0, 0]
        A[0][1] *= -1
        A[1][0] *= -1
        for row in range(2):
            for column in range(2):
                A_inv[row][column] *= multInv
                A_inv[row][column] = A_inv[row][column] % 26

        P = HillCipher.createMatrixIntToStr(ciphertext)
        msg_len = int(len(ciphertext) / 2)
        decodedText = ""
        for i in range(msg_len):
            column_0 = P[0][i] * A_inv[0][0] + P[1][i] * A_inv[0][1]
            n = int(column_0 % 26 + 65)
            decodedText += chr(n)
            column_1 = P[0][i] * A_inv[1][0] + P[1][i] * A_inv[1][1]
            n = int(column_1 % 26 + 65)
            decodedText += chr(n)
        if decodedText[-1] == "0":
            decodedText = decodedText[:-1]
        return "".join(decodedText)

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

if __name__ == "_main_":
    cipher = HillCipher(key=1)
    cleartext = "helloworld"
    encode = cipher.encode(cleartext)
    print(encode)