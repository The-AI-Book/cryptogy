import cryptogy
import numpy as np
from typing import List


def format_key(key, return_np=True):

    try:
        if key.find(";") != -1:
            matrix = list()
            rows = key.split(";")[:-1]
            for row in rows:
                values = list()
                for number in row.split(","):
                    values.append(int(number))
                matrix.append(values)
            if return_np:
                return np.array(matrix)
            else:
                return matrix
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


def format_str_to_list(array: str):
    list_ = array.split(",")
    for i in range(len(list_)):
        list_[i] = int(list_[i])
    return list_


def format_darray(matrix: np.array):
    n = matrix.shape[0]
    m = matrix.shape[1]
    string = ""
    for i in range(n):
        for j in range(m):
            string += str(matrix[i][j])
            if j < m - 1:
                string += ","
        string += ";"
    return string


def format_list(list: List[int]):
    string = ""
    for bit in list:
        string += str(bit) + ","
    return string[:-1]


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
        return cryptogy.VigenereCipher(m=int(data["keyLength"]))
    elif cipher == "hill":
        return cryptogy.HillCipher(m=int(data["numPartitions"]))
    elif cipher == "permutation":
        return cryptogy.HillCipher(
            m=int(data["numPartitions"]), permutation_cipher=True
        )
    elif cipher == "stream":
        return cryptogy.AutokeyCipher()
    elif cipher == "sdes":
        return cryptogy.SDESCipher()
    elif cipher == "des":
        return cryptogy.DESCipher()
    elif cipher == "3des":
        return cryptogy.TripleDESCipher()
    elif cipher == "aes":
        keyLength = int(data["keyLength"])

        key = b"P" * 16
        if keyLength == 16:
            key = b"P" * 16
        elif keyLength == 24:
            key = b"P" * 24
        elif keyLength == 32:
            key = b"P" * 32
        cipher = cryptogy.AESCipher()
        cipher.setKey(key)
        return cipher

    elif cipher == "gamma-pentagonal":
        return cryptogy.GammaPentagonalCipher()
