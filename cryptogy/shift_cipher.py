from cipher import Cipher, CryptAnalizer
import random 
import numpy as np

class ShiftCipher(Cipher):
    def __init__(self, name: str, key = ""):
        super().__init__(name)
        self.key = self.iniKey(key)

    def validKey(self, key):
        return (key >= 0 and key <= 25)

    def generateRandomKey(self):
        return random.randint(0, 25)

    def encode(self, cleartext: str = "wewillmeetatmidnight"):
        intList = Cipher.textToInt(cleartext)
        for i in range(len(intList)):
            intList[i] += self.key
            intList[i] = (intList[i] % 26)
        encodeText = Cipher.intToText(intList)
        return "".join(encodeText).upper()

    def decode(self, ciphertext: str = "vpxzgiaxivwpubttmjpwizitwzt"):
        intList = Cipher.textToInt(ciphertext.lower())
        for i in range(len(intList)):
            intList[i] -= self.key
            intList[i] = (intList[i] % 26)
        decodedText = Cipher.intToText(intList)
        return "".join(decodedText)

class ShiftCryptAnalizer(CryptAnalizer):
    def __init__(self):
        super().__init__()

    def bruteForceSearch(self, ciphertext):
        ciphertext = ciphertext.lower()
        decodedTexts = list()
        for i in range(0, 26):
            intList = Cipher.textToInt(ciphertext)
            candidateKey = i
            for j in range(len(intList)):
                intList[j] -= candidateKey
                intList[j] = (intList[j] % 26)
            decodedText = "".join(Cipher.intToText(intList))
            decodedTexts.append(decodedText)
        return decodedTexts
    
    def breakCipher(self, ciphertext):
        decodedTexts = self.bruteForceSearch(ciphertext)
        for i in range(len(decodedTexts)):
            print("Key {key} generates text: {text}".format(key = i, text = decodedTexts[i]))
    
if __name__ == "__main__":
    cipher = ShiftCipher("ShiftCipher", key = 11)
    encode = cipher.encode("wewillmeetatmidnight")
    print(encode)
    analyzer = ShiftCryptAnalizer()
    analyzer.breakCipher(encode)