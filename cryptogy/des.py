from math import exp
from cipher import Cipher, CryptAnalizer
import numpy as np
import copy
import random 
from typing import List

"""
Parameters        |  S-DES                      |  DES                        |
Plaintext Length  |  8 bits                     |  64 bits                    |
Ciphertext Length |  8 bits                     |  64 bits                    |
Key Length        |  10                         |  56                         |
Rounds operation  |  2                          |  16                         |
Number of subkeys |  2 keys (8 bits)            |  16 keys (54 bits)          |
S-Boxes           | input 4 bits, output 2 bits | input 6 bits, output 4 bits |
"""

class SDESCipher(Cipher):
    def __init__(self):
        pass



class DESCipher(Cipher):

    S1 = [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7], [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8], [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0], [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]]
    S2 = [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10], [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5], [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15], [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]]
    S3 = [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8], [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1], [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7], [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]]
    S4 = [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15], [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9], [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4], [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]]
    S5 = [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9], [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6], [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14], [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]]
    S6 = [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11], [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8], [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6], [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]]
    S7 = [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1], [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6], [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2], [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]]
    S8 = [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7], [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2], [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8], [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
    SM = [S1, S2, S3, S4, S5, S6, S7, S8]

    BLOCK_LENGTH = 64
    KEY_LENGTH = 56
    ROUNDS = 16

    @staticmethod
    def get64Blocks(bits):
        num = int((len(bits) / DESCipher.BLOCK_LENGTH) + 1)
        blocks = list()
        for i in range(num):
            blocks.append(bits[DESCipher.BLOCK_LENGTH*i:DESCipher.BLOCK_LENGTH*(i+1)])
        for j in range(num):
            if len(blocks[j]) != DESCipher.BLOCK_LENGTH:
                diff = DESCipher.BLOCK_LENGTH - len(blocks[j])
                blocks[j] = blocks[j] + [0] * diff
        return blocks


    @staticmethod
    def tobits(s):
        result = []
        for c in s:
            bits = bin(ord(c))[2:]
            bits = '00000000'[len(bits):] + bits
            result.extend([int(b) for b in bits])
        return result

    @staticmethod
    def frombits(bits):
        chars = []
        #print(len(bits) / 8)
        for b in range(int(len(bits) / 8)):
            byte = bits[b*8:(b+1)*8]
            chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
        return ''.join(chars)

    @staticmethod
    def inv(perm):
        inverse = [0] * len(perm)
        for i, p in enumerate(perm):
            inverse[p] = i
        return inverse

    def __init__(self, key = None):
        """
        DES is a 16-round Feistel cipher having block length 64:
        it encrypts a plaintext bistring x using a 56-bit key, K, obtaining a 
        ciphertext bistring (of length 64).
        """
        super().__init__()
        self.key = self.iniKey(key)
        self.permutation = DESCipher.generatePermutation(DESCipher.BLOCK_LENGTH)
        self.schedule = self.generateKeySchedule()

    @staticmethod
    def generatePermutation(length):
        range_ = np.array(list(range(length)), dtype = int)
        perm = list(np.random.permutation(range_, ))
        for i in range(len(perm)):
            perm[i] = int(perm[i])
        return perm

    @staticmethod
    def applyPermutation(permutation, block, shift = False):
        if shift: move = 1
        else: move = 0
        new_block = [0] * len(permutation)
        for i in range(len(permutation)):
            new_block[permutation[i] - move] = block[i]
        return new_block

    @staticmethod
    def computeXOR(a: List[int], b: List[int]):
        xor_list = list()
        if len(a) != len(b): raise Exception("Can't compute XOR over lists of different size.")
        for i in range(len(a)):
            bit_a = a[i]
            bit_b = b[i]
            result = int(bool(bit_a) != bool(bit_b))
            xor_list.append(result)
        return xor_list

    @staticmethod
    def expandBlock(block):
        """
        32 bits block.
        """
        bit_selection_table = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 
        9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 
        20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 
        29, 30, 31, 32, 1]
        expanded_block = list()
        for i in range(len(bit_selection_table)):
            bit_index = bit_selection_table[i]
            expanded_block.append(block[bit_index - 1])
        return expanded_block

    @staticmethod
    def funcPermutation(block):
        """
        32 bits block.
        """
        permutation = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31,
                       10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
        #print(len(permutation))
        return DESCipher.applyPermutation(permutation, block, shift = True)

    def roundFunction(self, A, J):
        ea = DESCipher.expandBlock(A)
        B = DESCipher.computeXOR(ea, J)
        #print("print bis")
        concatenation = ""
        for i in range(8):
            bj = B[i*6 : 6 * (i+1)]
            b1b6 = str(bj[0]) + str(bj[5])
            b2tob5 = "".join([str(x) for x in bj[1: 5]])
            y = int(b1b6, 2)
            x = int(b2tob5, 2)
            matrix = DESCipher.SM[i]
            number = format(matrix[y][x], "b")
            diff = 4 - len(number)
            number = ("0" * diff) + number
            concatenation += number
            #print("number: ", number, type(number))
        C = list()
        for s in concatenation: 
            C.append(int(s))
        #print(len(C))
        return DESCipher.funcPermutation(C)

    def validKey(self, key): 
        return 1.0
    
    def generateRandomKey(self):
        key = np.random.binomial(n = 1, p = 0.5, size=[KEY_LENGTH])
        return list(key)

    def generateKeySchedule(self):
        """
        The key schedule consists of 48-bit round keys that are derived from the 56-bit key, K.
        Each K^i is a certain permuted selection of bits from K.
        """
        schedule = list()
        for i in range(ROUNDS):
            key_copy = copy.deepcopy(self.key)
            for i in range(8):
                rand_num = random.randint(0, KEY_LENGTH - i - 1)
                del key_copy[rand_num]
            perm = DESCipher.generatePermutation(48)
            key_permuted = DESCipher.applyPermutation(perm, key_copy)
            schedule.append(key_permuted)
        return schedule
        
    def applyRounds(self, L, R):
        for i in range(DESCipher.ROUNDS):
            #print("Apply round!")
            f_RK = self.roundFunction(R, self.schedule[i])
            L = R
            R = DESCipher.computeXOR(L, f_RK)
        return L, R

    def encode(self, cleartext: str):
        # Get bits and blocks.
        bits = DESCipher.tobits(cleartext)
        blocks = DESCipher.get64Blocks(bits)

        # Encode text.
        ciphertext = ""
        for i in range(len(blocks)):
            blocks[i] = DESCipher.applyPermutation(self.permutation, blocks[i])
            L = blocks[i][0:32]
            R = blocks[i][32:64]
            L, R = self.applyRounds(L, R)
            blocks[i] = L + R
            blocks[i] = DESCipher.applyPermutation(DESCipher.inv(self.permutation), blocks[i])
            ciphertext += DESCipher.frombits(blocks[i])
        return ciphertext

    def decode(self, ciphertext: str):
        return self.encode(ciphertext)
        
if __name__ == '__main__':
    cleartext = "holamundo holamundo"
    cipher = DESCipher()
    res = cipher.encode(cleartext)
    print("res:")
    print(res)
    res2 = cipher.encode(res)
    print("res2:")
    print(res2)
    #print(len(res[1]))
    #print("from bits")
    #print(DESCipher.frombits(res))

    #cipher.generateKeySchedule()
    #print(DESCipher.frombits(res[1]))
    #print(permutation)
    #print(cipher.schedule)