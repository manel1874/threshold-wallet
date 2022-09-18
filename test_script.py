#from pycoin.ecdsa.secp256k1 import _Gx
from pycoin.ecdsa.Generator import Generator
import hashlib #, secrets

#from pycoin.ecdsa import secp256k1


_a = 0x0000000000000000000000000000000000000000000000000000000000000000
_b = 0x0000000000000000000000000000000000000000000000000000000000000007
_p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
_Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
_r = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

secp256k1 = Generator(_p, _a, _b, (_Gx, _Gy), _r)

def sha3_256Hash(msg):
    hashBytes = hashlib.sha256(msg.encode("utf8")).digest()
    return int.from_bytes(hashBytes, byteorder="big")

def signECDSAsecp256k1(msg, privKey):
    msgHash = sha3_256Hash(msg)
    signature = secp256k1.sign(privKey, msgHash)
    return signature

def signECDSAsecp256k1_with_recid(msg, privKey):
    msgHash = sha3_256Hash(msg)
    signature = secp256k1.sign_with_recid(privKey, msgHash)
    return signature

def verifyECDSAsecp256k1(msg, signature, pubKey):
    msgHash = sha3_256Hash(msg)
    valid = secp256k1.verify(pubKey, msgHash, signature)
    return valid


# ECDSA sign message (using the curve secp256k1 + SHA3-256)
msg = "lord"
#privKey = secrets.randbelow(generator_secp256k1.order())
privKey = '0x157c76391e58451ee77d087ad3642d6cc5292f3db43a16094a21b6490605afdd4'
signature = signECDSAsecp256k1(msg, privKey)
print("Message:", msg)
print("Private key:", hex(privKey))
print("Signature: r=" + hex(signature[0]) + ", s=" + hex(signature[1]))

"""

# ECDSA sign message (using the curve secp256k1 + SHA3-256)
msg = "lord"
privKey = secrets.randbelow(generator_secp256k1.order())
signature = signECDSAsecp256k1(msg, privKey)
print("Message:", msg)
print("Private key:", hex(privKey))
print("Signature: r=" + hex(signature[0]) + ", s=" + hex(signature[1]))

# ECDSA verify signature (using the curve secp256k1 + SHA3-256)
pubKey = (generator_secp256k1 * privKey).pair()
valid = verifyECDSAsecp256k1(msg, signature, pubKey)
print("\nMessage:", msg)
print("Public key: (" + hex(pubKey[0]) + ", " + hex(pubKey[1]) + ")")
print("Signature valid?", valid)

# ECDSA verify tampered signature (using the curve secp256k1 + SHA3-256)
msg = "Tampered message"
valid = verifyECDSAsecp256k1(msg, signature, pubKey)
print("\nMessage:", msg)
print("Signature (tampered msg) valid?", valid)
"""