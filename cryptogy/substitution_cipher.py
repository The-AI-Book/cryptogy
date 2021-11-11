from cipher import Cipher, CryptAnalizer
import numpy as np 
import copy

class SubstitutionCipher(Cipher):
    def __init__(self, name: str, key = ""):
        super().__init__(name)
        self.key = self.iniKey(key)

    def validKey(self, key: list):
        range_ = list(range(26))
        key_ = copy.deepcopy(key)
        key_.sort()
        return (range_ == key_)

    def generateRandomKey(self):
        range_ = np.array(list(range(26)))
        return list(np.random.permutation(range_))

    def encode(self, cleartext: str = "letsmeettomorrowmorning"):
        intList = Cipher.textToInt(cleartext)
        for i in range(len(intList)):
            intList[i] = self.key[intList[i]]
        encodeText = Cipher.intToText(intList)
        return "".join(encodeText).upper()

    def decode(self, ciphertext: str = "HFKMLFFKKBLBQQBPLBQDNDV"):
        intList = Cipher.textToInt(ciphertext.lower())
        for i in range(len(intList)):
            intList[i] = self.key.index(intList[i])
        decodedText = Cipher.intToText(intList)
        return "".join(decodedText)

class SubstitutionCryptAnalizer(CryptAnalizer):
    def __init__(self):
        super().__init__()

    def breakCipher(self, ciphertext: str = "YIFQFMZRWQFYVECFMDZPCVMRZWNMDZVEJBTXCDDUMJNDIFEFMDZCDMQZKCEYFCJMYRNCWJCSZREXCHZUNMXZNZUCDRJXYYSMRTMEYIFZWDYVZVYFZUMRZCRWNZDZJJXZWGCHSMRNMDHNCMFQCHZJMXJZWIEJYUCFWDJNZDIR", max_tries: int = 5):
        frecuency = CryptAnalizer.getLettersFrecuency(ciphertext)
        index_frequency = CryptAnalizer.getArgMaxIndex(frecuency)
        print(frecuency)
        print(index_frequency)


if __name__ == "__main__":
    cipher = SubstitutionCipher(
                "SubtitutionCipher", 
                key = [9, 23, 24, 25, 14, 16, 2, 3, 15, 4, 10, 20, 18, 8, 22, 11, 1, 12, 19, 0, 17, 7, 6, 13, 5, 21])
    print(cipher.key)
    cleartext = "letsmeettomorrowmorning"
    print(cleartext)
    ciphertext = cipher.encode(cleartext)
    print(ciphertext)
    decodedtext = cipher.decode(ciphertext)
    print(decodedtext)

    analyzer = SubstitutionCryptAnalizer()
    analyzer.breakCipher(ciphertext = "YIFQFMZRWQFYVECFMDZPCVMRZWNMDZVEJBTXCDDUMJNDIFEFMDZCDMQZKCEYFCJMYRNCWJCSZREXCHZUNMXZNZUCDRJXYYSMRTMEYIFZWDYVZVYFZUMRZCRWNZDZJJXZWGCHSMRNMDHNCMFQCHZJMXJZWIEJYUCFWDJNZDIR")
    