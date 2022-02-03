class DigitalSignature:
    def __init__(self, key = None): 
        self.key = self.iniKey(key)

    def iniKey(self, key):
        if key is None:
            return self.generateRandomKey()
        elif not self.validKey(key):
            raise Exception("An error occured when trying to set a key: invalid key.")
        else: 
            return key

    def validKey(self, key):
        pass

    def generateRandomKey(self):
        pass

    def getSignature(self, cleartext):
        pass

    def verifySignature(self, key, signature):
        pass

class DSS_Signature(DigitalSignature):
    from Crypto.PublicKey import DSA
    from Crypto.Signature import DSS
    from Crypto.Hash import SHA256

    def __init__(self, key = None):
        super().__init__(key)

    def validKey(self, key):
        return True
    
    def generateRandomKey(self):
        key = DSS_Signature.DSA.generate(2048)
        return key

    def getSignature(self, cleartext: bytes):
        hash_obj = DSS_Signature.SHA256.new(cleartext)
        signer = DSS_Signature.DSS.new(self.key, 'fips-186-3')
        signature = signer.sign(hash_obj)
        return self.key.publickey(), signature

    def verifySignature(self, publickey, cleartext, signature):
        hash_obj = DSS_Signature.SHA256.new(cleartext)
        pkey = DSS_Signature.DSS.new(publickey,'fips-186-3')
        return pkey.verify(hash_obj, signature) == False


dss = DSS_Signature()
publickey, signature = dss.getSignature(b"Hello")
print(type(publickey))
print(signature)
#message = b"Hello"
#hash_obj = SHA256.new(message)
#print(hash_obj)

#signer = DSS.new(key, 'fips-186-3')
#signature = signer.sign(hash_obj)

#print(signature)

#pkey=DSS.new(publickey,'fips-186-3')
#pkey.verify(hash_obj,signature) == False