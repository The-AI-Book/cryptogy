import cryptogy
import numpy as np 
def format_key(key):

    try:
        if key.find(";") != -1:
            matrix = list()
            rows = key.split(";")[:-1]
            for row in rows: 
                values = list()
                for number in row.split(","):
                    values.append(int(number))
                matrix.append(values)
            return np.array(matrix)
    except: 
        pass

    if isinstance(key, list) or isinstance(key, int):
        return key
    try:
        return int(key)
    except: 
        list_ = list()
        for val in key.split(","): 
            list_.append(int(val))
        return list_

def format_darray(matrix: np.array):
    n = matrix.shape[0]
    m = matrix.shape[1]
    string = ""
    for i in range(n):
        for j in range(m):
            string += str(matrix[i][j]) 
            if (j < m - 1):
                string += ","
        string += ";" 
    return string

def get_analyzer(data: dict): 
    cipher = data["cipher"]
    if cipher == "shift":
        return cryptogy.ShiftCryptAnalizer()
    elif cipher == "substitution":
        return cryptogy.SubstitutionCryptAnalizer()
    elif cipher == "affine":
        return cryptogy.AffineCryptAnalizer()
    elif cipher == "vigenere":
        return cryptogy.VigenereCryptAnalizer()
    elif cipher == "hill":
        return cryptogy.HillCryptAnalizer()
    elif cipher == "permutation":
        return cryptogy.HillCryptAnalizer()
    elif cipher == "stream":
        return cryptogy.AutokeyCryptAnalizer()

def get_cipher(data: dict):
   
    cipher = data["cipher"]
    if cipher == "shift":
        return cryptogy.ShiftCipher()
    elif cipher == "substitution":
        return cryptogy.SubstitutionCipher()
    elif cipher == "affine":
        return cryptogy.AffineCipher()
    elif cipher == "vigenere":
        return cryptogy.VigenereCipher(m = int(data["keyLength"]))
    elif cipher == "hill":
        return cryptogy.HillCipher(m = int(data["numPartitions"]))
    elif cipher == "permutation":
        return cryptogy.HillCipher(m = int(data["numPartitions"]), permutation_cipher=True)
    elif cipher == "stream":
        return cryptogy.AutokeyCipher()