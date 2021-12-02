from .cipher import Cipher, CryptAnalizer
import random 
from typing import List
import re 
import math
#from .ngram_score import ngram_score
from pycipher import Vigenere
from itertools import permutations
#import os
#print(os.getcwd())

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
        print("ciphertext to decode: ", ciphertext)
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

    def breakCipher(self, ciphertext):
        #qgram = ngram_score("quadgrams.txt")
        #trigram = ngram_score('trigrams.txt')
        ctext = re.sub(r'[^A-Z]','', ciphertext.upper())

        class nbest(object):
            def __init__(self,N=1000):
                self.store = []
                self.N = N
                
            def add(self,item):
                self.store.append(item)
                self.store.sort(reverse=True)
                self.store = self.store[:self.N]
            
            def __getitem__(self,k):
                return self.store[k]

            def __len__(self):
                return len(self.store)
        
        N = 100
        for KLEN in range(6, 7):
            rec = nbest(N)

            for i in permutations('ABCDEFGHIJKLMNOPQRSTUVWXYZ',3):
                key = ''.join(i) + 'A'*(KLEN-len(i))
                pt = Vigenere(key).decipher(ctext)
                score = 0
                for j in range(0,len(ctext),KLEN):
                    score += trigram.score(pt[j:j+3])
                rec.add((score,''.join(i),pt[:30]))

            next_rec = nbest(N)
            for i in range(0,KLEN-3):
                for k in range(N):
                    for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                        key = rec[k][1] + c
                        fullkey = key + 'A'*(KLEN-len(key))
                        pt = Vigenere(fullkey).decipher(ctext)
                        score = 0
                        for j in range(0,len(ctext),KLEN):
                            score += qgram.score(pt[j:j+len(key)])
                        next_rec.add((score,key,pt[:30]))
                rec = next_rec
                next_rec = nbest(N)
            bestkey = rec[0][1]
            pt = Vigenere(bestkey).decipher(ctext)
            bestscore = qgram.score(pt)
            for i in range(N):
                pt = Vigenere(rec[i][1]).decipher(ctext)
                score = qgram.score(pt)
                if score > bestscore:
                    bestkey = rec[i][1]
                    bestscore = score       
            print('Intento para longitud de clave:', str(KLEN) + '. Clave:', bestkey + ', Texto en claro:', Vigenere(bestkey).decipher(ctext))
    

if __name__ == "__main__":
    analyzer = VigenereCryptAnalizer()
    ciphertext2 = "VPXZGIAXIVWPUBTTMJPWIZITWZT"
    analyzer.breakCipher(ciphertext2)