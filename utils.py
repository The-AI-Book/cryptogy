import cryptogy

def format_key(key):
    if type(key) == list or type(key) == int:
        return key
    try:
        return int(key)
    except: 
        list_ = list()
        for val in key.split(","): 
            list_.append(int(val))
        return list_


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
        return None
    elif cipher == "permutation":
        return None
    elif cipher == "stream":
        return None

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
        return None
    elif cipher == "permutation":
        return None
    elif cipher == "stream":
        return None