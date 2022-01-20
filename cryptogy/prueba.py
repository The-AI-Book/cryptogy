from Crypto import Random
from Crypto.Cipher import DES
key = Random.new().read(DES.key_size)
iv = Random.new().read(DES.block_size)
print(key)
print(iv)