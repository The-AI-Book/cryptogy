from .cipher import Cipher, CryptAnalizer
import numpy as np 
import copy
from pycipher import SimpleSubstitution as SimpleSub
import random
import re
from ngram_score import ngram_score

class SubstitutionCipher(Cipher):
    def __init__(self, key = None):
        super().__init__()
        self.key = self.iniKey(key)

    def validKey(self, key: list):
        range_ = list(range(26))
        key_ = copy.deepcopy(key)
        key_.sort()
        return (range_ == key_)

    def generateRandomKey(self):
        range_ = np.array(list(range(26)), dtype = int)
        key = list(np.random.permutation(range_, ))
        for i in range(len(key)):
            key[i] = int(key[i])
        return key

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
        fitness = ngram_score('quadgrams.txt') # load our quadgram statistics
        ctext = re.sub('[^A-Z]','', ciphertext.upper())
        maxkey = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        maxscore = -99e9
        parentscore,parentkey = maxscore,maxkey[:]
        # keep going until we are killed by the user
        i = 0
        messages = list()
        while i <= 80:
            #print(i)
            i = i+1
            random.shuffle(parentkey)
            deciphered = SimpleSub(parentkey).decipher(ctext)
            parentscore = fitness.score(deciphered)
            count = 0
            while count < 1000:
                a = random.randint(0,25)
                b = random.randint(0,25)
                child = parentkey[:]
                # swap two characters in the child
                child[a],child[b] = child[b],child[a]
                deciphered = SimpleSub(child).decipher(ctext)
                score = fitness.score(deciphered)
                # if the child was better, replace the parent with it
                if score > parentscore:
                    parentscore = score
                    parentkey = child[:]
                    count = 0
                count = count+1
            # keep track of best score seen so far
            if parentscore > maxscore:
                maxscore,maxkey = parentscore,parentkey[:]
                ss = SimpleSub(maxkey)
                message = 'Key:' +  ','.join([str(x) for x in Cipher.textToInt(''.join(maxkey))]) + " generates \n" + str(ss.decipher(ctext)) + "\n"
                messages.append(message)
                #print(message, type(message))
        #print("Proceso terminado.")
        return " ".join(messages)

if __name__ == "__main__":
    analyzer = SubstitutionCryptAnalizer()
    analyzer.breakCipher(ciphertext = "CPDVCPIRDCGDVFCHJICYAHAJADCPDCAJCWEJSHDVARAWSPSPFCPIPDSDIESVR")
    