from .cipher import Cipher, CryptAnalizer
import random 
from typing import List
import re 
import math 

class VigenereCipher(Cipher):
    def __init__(self, m: int, zm: int = 26, key = ""):
        super().__init__()
        self.m = m
        self.key = self.iniKey(key)
        self.zm = zm

    def validKey(self, key):
        if len(key) != self.m:
            print("Key length is different from m!")
            return False
        for value in key:
            if type(value) != int:
                print("Array element is not an integer!")
                return False
        return True

    def generateRandomKey(self):
        key = list()
        for i in range(0, self.m):
            rand_number = random.randint(0, 25)
            key.append(rand_number)
        return key 

    def encode(self, cleartext: str = "thiscryptosystemisnotsecure"):
        intList = Cipher.textToInt(cleartext)
        for i in range(len(intList)):
            intList[i] += self.key[i % self.m]
            intList[i] = (intList[i] % self.zm)
        encodeText = Cipher.intToText(intList)
        return "".join(encodeText).upper()

    def decode(self, ciphertext: str = "vpxzgiaxivwpubttmjpwizitwzt"):
        intList = Cipher.textToInt(ciphertext.lower())
        #print("intList: ", intList)
        for i in range(len(intList)):
            intList[i] -= self.key[i % self.m]
            intList[i] = (intList[i] % self.zm)
        decodedText = Cipher.intToText(intList)
        return "".join(decodedText)

class VigenereCryptAnalizer(CryptAnalizer):
    def __init__(self):
        super().__init__()
    
    @staticmethod
    def mgQuantity(yi, g, zm = 26):
        letters_probability = CryptAnalizer.getListLettersProbability()
        letters_frequency = CryptAnalizer.getLettersFrecuency(yi)
        sum_ = 0
        n_prime = len(yi)
        for i in range(0, zm):
            sum_ += (letters_probability[i] * letters_frequency[(i + g) % zm]) 
        mg = (sum_ / n_prime)
        return mg

    @staticmethod
    def getMgValues(yis):
        mg_values = list()
        for yi in yis:
            mg_yi_values = list()
            for g in range(0, 26):
                mgQuantity = VigenereCryptAnalizer.mgQuantity(yi, g)
                mg_yi_values.append(mgQuantity)
            mg_values.append(mg_yi_values)
        return mg_values 

    def breakCipher(self, ciphertext):
        m = self.kasiskiTest(ciphertext)
        yis = self.breakText(ciphertext, m)
        mg_values = VigenereCryptAnalizer.getMgValues(yis)
        key = self.getPossibleKey(mg_values)
        cipher = VigenereCipher(len(key))
        cipher.setKey(key)
        decodeText = cipher.decode(ciphertext)
        res = "Key: " + str(key) + " \n" + decodeText
        return res

    def getPossibleKey(self, mg_values):
        key = list()
        for list_ in mg_values:
            key.append(list_.index(max(list_)))
        return key

    def kasiskiTest(self, ciphertext):
        triplet = ciphertext[0:3]
        positions = [m.start() for m in re.finditer(triplet, ciphertext)][1:]
        if len(positions) <= 1:
            raise Exception("Not enough ciphertext information to break Vigenere Cipher.")
        result = positions[0]
        for i in positions[1:]:
            result = math.gcd(result, i)
        return result

    def breakText(self, ciphertext, m):
        y_substrings = list()
        n = len(ciphertext)
        for i in range(0, m):
            yi = ""
            counter = 0
            #print(i + 1, end = ", ")
            for j in range(0, n - m, m):
                yi += ciphertext[(counter * m) + i]
                counter += 1
                #print(counter, "* m +",  i + 1, end = ", ")
            y_substrings.append(yi)
        return y_substrings
    

if __name__ == "__main__":
    cipher = VigenereCipher(m = 6)
    cipher.setKey(key = [2, 8, 15, 7, 4, 17])
    ciphertext = cipher.encode(cleartext = "thiscryptosystemisnotsecure")
    decodedText = cipher.decode(ciphertext)
    print(ciphertext)
    print(decodedText)
    
    analyzer = VigenereCryptAnalizer()
    ciphertext2 = "CHREEVOAHMAERATBIAXXWTNXBEEOPHBSBQMQEQERBWRVXUOAKXAOSXXWEAHBWGJMMQMNKGRFVGXWTRZXWIAKLXFPSKAUTEMNDCMGTSXMXBTUIADNGMGPSRELXNJELXVRVPRTULHDNQWTWDTYGBPHXTFALJHASVBFXNGLLCHRZBWELEKMSJIKNBHWRJGNMGJSGLXFEYPHAGNRBIEQUTAMRVLCRREMNDGLXRRIMGNSNRWCHRQHAEYEVTAQEBBIPEEWEVKAKOEWADREMXMTBHHCHRTKDNVRZCHRCLQOHPWQAIIWXNRMGWOIIFKEE"
    print(len(ciphertext2))
    result = analyzer.kasiskiTest(ciphertext2)
    yis = analyzer.breakText(ciphertext2, 5)

    print(analyzer.breakCipher(ciphertext2))