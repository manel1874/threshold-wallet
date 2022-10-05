#from pycoin.ecdsa.secp256k1 import _Gx
from pycoin.ecdsa.Generator import Generator
import hashlib #, secrets
import json
from nummaster.basic import sqrtmod

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








def format_point(point):

    array_int = point[1:]
    is_odd = int(point[0]) % 2
    array_hex = "0x"+bytes(array_int).hex()

    x = int(array_hex, 0)
    
    return x, is_odd


def format_scalar(scalar):

    scalar_hex = "0x"+bytes(scalar).hex()
    x = int(scalar_hex, 0)

    return x


def uncompress_key(curve, compressed_key):
  x, is_odd = compressed_key
  p, a, b = curve._p, curve._a, curve._b

  y = sqrtmod(pow(x, 3, p) + a * x + b, p)

  if bool(is_odd) == bool(y & 1):
    return (x, y)

  return (x, p - y)

"""

print("\nCheck that pk_vec[0] is equal to g^x0\n")

with open("sks/local-share1.json", "r") as f:
        local_share = json.load(f)
        ## Get X0
        pk_vec0 = local_share['pk_vec'][0]['point']
        ## Get x0
        x0_scalar = local_share['keys_linear']['x_i']['scalar']

# Process X0

x, y = uncompress_key(secp256k1, format_point(pk_vec0))
pk0 = secp256k1.Point(x, y)

# Process x0
x0 = format_scalar(x0_scalar)

## X0 == g^x0

val = pk0 == secp256k1.raw_mul(x0)

print(val)

"""

print("\nCheck that sum_pk_vec is equal to g^(sum)\n")

with open("sks/local-share1.json", "r") as f:
        local_share = json.load(f)
        ## Get Xi's
        pk_vec0 = local_share['pk_vec'][0]['point']
        pk_vec1 = local_share['pk_vec'][1]['point']
        pk_vec2 = local_share['pk_vec'][2]['point']
        ## Get x0
        x0_scalar = local_share['keys_linear']['x_i']['scalar']

with open("sks/local-share2.json", "r") as f:
        local_share = json.load(f)
        x1_scalar = local_share['keys_linear']['x_i']['scalar']

with open("sks/local-share3.json", "r") as f:
        local_share = json.load(f)
        x2_scalar = local_share['keys_linear']['x_i']['scalar']  

# Process Xis'
x0, y0 = uncompress_key(secp256k1, format_point(pk_vec0))
pk0 = secp256k1.Point(x0, y0)
x1, y1 = uncompress_key(secp256k1, format_point(pk_vec1))
pk1 = secp256k1.Point(x1, y1)
x2, y2 = uncompress_key(secp256k1, format_point(pk_vec2))
pk2 = secp256k1.Point(x2, y2)

# Add Xi's

pk = pk0
pk = secp256k1.add(pk,pk1)
pk = secp256k1.add(pk,pk2)

# Process x0
x0 = format_scalar(x0_scalar)
x1 = format_scalar(x1_scalar)
x2 = format_scalar(x2_scalar)

my_privk = (x0 + x1 + x2) % _r

## X0 == g^x0

val = pk == secp256k1.raw_mul(my_privk)

print(val)

#print("raw_mul result:" + str(secp256k1.raw_mul(my_privk)))
print("Private key:" + str(hex(my_privk)))
print("Public key:" + str(hex(pk[0])) + " " + str(hex(pk[1])))




print("\nSign msg: lord\n")
# ECDSA sign message (using the curve secp256k1 + SHA3-256)
msg = "lord"
#privKey = secrets.randbelow(secp256k1.order())
privKey = my_privk
signature = signECDSAsecp256k1(msg, privKey)
print("Message:", msg)
print("Private key:", hex(privKey))
print("Signature: r=" + hex(signature[0]) + ", s=" + hex(signature[1]))


# ECDSA sign message (using the curve secp256k1 + SHA3-256)
msg = "lord"
#privKey = secrets.randbelow(secp256k1.order())
privKey = my_privk
signature_with_recid = signECDSAsecp256k1_with_recid(msg, privKey)
print("Message:", msg)
print("Private key:", privKey)
print("Signature: r=" + hex(signature_with_recid[0]) + ", s=" + hex(signature_with_recid[1]) + ", v=" + hex(signature_with_recid[2]))


print("\nVerify signature\n")
# ECDSA verify signature (using the curve secp256k1 + SHA3-256)
pubKey = secp256k1.raw_mul(privKey)
valid = verifyECDSAsecp256k1(msg, signature, pubKey)
print("\nMessage:", msg)
print("Public key: (" + hex(pubKey[0]) + ", " + hex(pubKey[1]) + ")")
print("Signature valid?", valid)

print("\nVerify my signature")

with open("signature/signature1.json", "r") as f:
        local_share = json.load(f)
        #y_point = local_share['y_sum_s']['point']
        r = local_share['r']['scalar']
        s = local_share['s']['scalar']
        v = local_share['recid']

r_hex = "0x"+bytes(r).hex()
s_hex = "0x"+bytes(s).hex()

my_sig = (int(r_hex, 0), int(s_hex, 0))
print("Signature: r=" + hex(my_sig[0]) + ", s=" + hex(my_sig[1]) + ", v=" + hex(v))


# ECDSA verify signature (using the curve secp256k1 + SHA3-256)
pubKey = secp256k1.raw_mul(privKey)
valid = verifyECDSAsecp256k1(msg, my_sig, pubKey)
print("\nMessage:", msg)
print("Public key: (" + hex(pubKey[0]) + ", " + hex(pubKey[1]) + ")")
print("Signature valid?", valid)


print("\nRecover PK from signature")
def recoverPubKeyFromSignature(msg, signature):
    msgHash = sha3_256Hash(msg)
    recoveredPubKeys = secp256k1.possible_public_pairs_for_signature(msgHash, signature)
    return recoveredPubKeys

msg = "lord"
recoveredPubKeys = recoverPubKeyFromSignature(msg, signature)
print("\nMessage:", msg)
print("Signature: r=" + hex(signature[0]) + ", s=" + hex(signature[1]))
for pk in recoveredPubKeys:
    print("Recovered public key from signature: (" +
          hex(pk[0]) + ", " + hex(pk[1]) + ")")

print("\nRecover PK from my signature")
def recoverPubKeyFromSignature(msg, signature):
    msgHash = sha3_256Hash(msg)
    recoveredPubKeys = secp256k1.possible_public_pairs_for_signature(msgHash, signature)
    return recoveredPubKeys

msg = "lord"
recoveredPubKeys = recoverPubKeyFromSignature(msg, my_sig)
print("\nMessage:", msg)
print("Signature: r=" + hex(my_sig[0]) + ", s=" + hex(my_sig[1]))
for pk in recoveredPubKeys:
    print("Recovered public key from signature: (" +
          hex(pk[0]) + ", " + hex(pk[1]) + ")")



#keccak_hash = keccak.new(digest_bits=256)
#keccak_hash.update("hello")
#keccak_digest = keccak_hash.hexdigest()
#print(keccak)