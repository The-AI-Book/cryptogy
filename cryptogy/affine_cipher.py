from .cipher import Cipher, CryptAnalizer
import random 
import numpy as np
import math
import sympy
from typing import List

class AffineCipher(Cipher):
    def __init__(self, key = None):
        super().__init__()
        self.key = self.iniKey(key)

    def validKey(self, key):
        if len(key) != 2:
            return False
        a, b = key
        if not (a >= 0 and a <= 25) or not (b >= 0 and b <= 25):
            return False
        return (math.gcd(a, 26) == 1)

    def generateRandomKey(self):
        valid = False
        while not valid: 
            a = random.randint(0, 25)
            if (math.gcd(a, 26) == 1):
                valid = True
        b = random.randint(0, 25)
        return (a, b)

    def encode(self, cleartext: str = "hot"):
        intList = Cipher.textToInt(cleartext)
        a, b = self.key
        for i in range(len(intList)):
            intList[i] = (a * intList[i] + b) % 26
        encodeText = Cipher.intToText(intList)
        return "".join(encodeText).upper()

    def decode(self, ciphertext: str = "AXG"):  
        ciphertext = ciphertext.lower()
        intList = Cipher.textToInt(ciphertext)

        a, b = self.key
        a_inverse = sympy.mod_inverse(a, 26)

        for i in range(len(intList)):
            intList[i] = (a_inverse * (intList[i] - b)) % 26
        decodedText = Cipher.intToText(intList)
        return "".join(decodedText)

class AffineCryptAnalizer(CryptAnalizer):
    def __init__(self):
        super().__init__()

    @staticmethod
    def validKey(key): 
        return (math.gcd(key[0], 26) == 1)

    def breakCipher(self, ciphertext: str = "FMXVEDKAPHFERBNDKRXRSREFMORUDSDKDVSHVUFEDKAPRKDLYEVLRHHRH", max_tries: int = 8):
        frecuency = CryptAnalizer.getLettersFrecuency(ciphertext)
        index_frequency = CryptAnalizer.getArgMaxIndex(frecuency)
        possible_keys = self.getPossibleKey(index_frequency, max_tries = max_tries)
        decodedTexts = self.getDecodedTexts(ciphertext, possible_keys)
        result = ""
        for i in range(len(decodedTexts)): 
            result += "Key {key} generates text: {text} \n".format(key = possible_keys[i], text = decodedTexts[i])
        return result 

    def getDecodedTexts(self, ciphertext: str, possible_keys):
        decoded_texts = list()
        cipher = AffineCipher(key = None)
        for key in possible_keys:
            cipher.setKey(key)
            text = cipher.decode(ciphertext)
            decoded_texts.append(text)
        return decoded_texts

    def getPossibleKey(self, index_frequency, max_tries = 5):
        possible_keys = list()

        probability = CryptAnalizer.getListLettersProbability()
        index_probability = CryptAnalizer.getArgMaxIndex(probability)
        
        first_probable_index = index_probability[0] #e
        second_probable_index = index_probability[1] #t
        for i in range(max_tries):
            pair1 = index_frequency[i]
            relation1 = (first_probable_index, pair1)
            for j in range(max_tries):
                if index_frequency[j] != pair1:
                    pair2 = index_frequency[j]
                    relation2 = (second_probable_index, pair2)

                    a = sympy.Matrix([[relation1[0], 1], [relation2[0], 1]])
                    b = sympy.Matrix([relation1[1], relation2[1]])
                    m = 26

                    det = int(a.det())
                    if math.gcd(det, m) == 1:
                        ans =sympy.mod_inverse(det, m) * a.adjugate() @ b % m
                        a, b = ans
                        key = (a, b)
                        if not AffineCryptAnalizer.validKey(key):
                            pass
                        else:
                            possible_keys.append(key)
                    else:
                        pass
                    #print(alphabet[relation1[0]], alphabet[relation1[1]], alphabet[relation2[0]], alphabet[relation2[1]], " => ")
        return possible_keys

if __name__ == "__main__":
    #cipher = AffineCipher(key = (7, 3))
    #encode = cipher.encode("hot")
    #print(encode)
    #decode = cipher.decode(encode)
    #print(decode)
    encode = "FMXVEDKAPHFERBNDKRXRSREFMORUDSDKDVSHVUFEDKAPRKDLYEVLRHHRH"
    analyzer = AffineCryptAnalizer()
    analyzer.breakCipher(encode, max_tries = 10)