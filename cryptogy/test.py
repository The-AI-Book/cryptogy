from Crypto.Cipher import DES
from secrets import token_bytes
key = token_bytes(8)
def encrypt(msg):
    cipher = DES.new(key, DES.MODE_EAX)
print(key)