from typing import List
import copy
import string
#import numpy as np

class Cipher:
    def __init__(self):
        self.key = None
    
    @staticmethod
    def textToInt(text):
        return [ord(letter) - 96 - 1 for letter in text]

    @staticmethod
    def intToText(integers: List[int]):
        return [chr(number + 96 + 1) for number in integers]

    def iniKey(self, key):
        if key == "":
            return self.generateRandomKey()
        elif not self.validKey(key):
            raise Exception("An error occured when trying to set a key: invalid key.")
        else: 
            return key

    def validKey(self, key):
        return True

    def getKey(self):
        return self.key

    def setKey(self, key):
        if self.validKey(key):
            self.key = key
            return True
        else: 
            raise Exception("An error occured when trying to set a key: invalid key.")

    def generateRandomKey(self):
        pass

    def encode(self):
        pass

    def decode(self):
        pass

class CryptAnalizer:
    def __init__(self):
        pass

    @staticmethod
    def getAlphabet():
        return list(string.ascii_lowercase)

    @staticmethod
    def getDiccLettersProbability():
        dicc = {}
        dicc["A"] = 0.082
        dicc["B"] = 0.015
        dicc["C"] = 0.028
        dicc["D"] = 0.043
        dicc["E"] = 0.127
        dicc["F"] = 0.022
        dicc["G"] = 0.020
        dicc["H"] = 0.061
        dicc["I"] = 0.070
        dicc["J"] = 0.002
        dicc["K"] = 0.008
        dicc["L"] = 0.040
        dicc["M"] = 0.024
        dicc["N"] = 0.067
        dicc["O"] = 0.075
        dicc["P"] = 0.019
        dicc["Q"] = 0.001
        dicc["R"] = 0.060
        dicc["S"] = 0.063
        dicc["T"] = 0.091
        dicc["U"] = 0.028
        dicc["V"] = 0.010
        dicc["W"] = 0.023
        dicc["X"] = 0.001
        dicc["Y"] = 0.020
        dicc["Z"] = 0.001
        return dicc

    @staticmethod
    def getListLettersProbability():
        return [0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020,
        0.061, 0.070, 0.002, 0.008, 0.040, 0.024, 0.067, 0.075,
        0.019, 0.001, 0.060, 0.063, 0.091, 0.028, 0.010, 0.023,
        0.001, 0.020, 0.001]

    @staticmethod
    def getLettersFrecuency(text):
        from collections import Counter
        from string import ascii_letters, ascii_lowercase
        filtered = [c for c in text.lower() if c in ascii_letters]
        dicc = dict(Counter(filtered))
        letters_frequency = list()
        for letter in list(ascii_lowercase):
            if letter in dicc:
                letters_frequency.append(dicc[letter])
            else: 
                letters_frequency.append(0)
        return letters_frequency
    
    @staticmethod
    def index_of_coincidence(text):
        n = len(text)
        frequencies = CryptAnalizer.getLettersFrecuency(text)
        sum_ = 0
        for i in range(0, 25):
            sum_ += (frequencies[i]) * (frequencies[i] - 1)
        return sum_ / (n * (n-1))

    @staticmethod
    def getArgMaxIndex(list_: List[float]):
        index_list = list()
        ban_positions = list()
        biggest = min(list_)
        candidate_index = -1
        for j in range(0, len(list_)):
            for i in range(0, len(list_)):
                element = list_[i]
                if element >= biggest and i not in ban_positions:
                    biggest = element
                    candidate_index = i
            index_list.append(candidate_index)
            ban_positions.append(candidate_index)
            biggest = min(list_)
        return index_list

    def getPossibleKey(self):
        pass