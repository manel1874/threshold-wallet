
"""
Auxiliary functions
"""

import json
import codecs

from Crypto.Hash import keccak
from pycoin.ecdsa.Curve import Curve
from pycoin.ecdsa.Generator import Generator
from nummaster.basic import sqrtmod

_a = 0x0000000000000000000000000000000000000000000000000000000000000000
_b = 0x0000000000000000000000000000000000000000000000000000000000000007
_p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
_Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
_r = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

secp256k1 = Generator(_p, _a, _b, (_Gx, _Gy), _r)


def getPK(nOfShares):
    # Sum all public key shares


    with open("sks/local-share1.json", "r") as f:
        local_share = json.load(f)
        y_point = local_share['keys_linear']['y']['point']
    
    x_yPoint, y_yPoint = uncompress_key(secp256k1, format_point(y_point))

    print(x_yPoint, y_yPoint)
    print(hex(x_yPoint), hex(y_yPoint))

    pk_vec = parse_pk_vec("sks/local-share1.json")
    pk_vec_0_point = pk_vec[0]["point"]

    x, y = uncompress_key(secp256k1, format_point(pk_vec_0_point))
    public_key = secp256k1.Point(x, y)
    
    for i in range(1, nOfShares):
        pk_vec_i_point = pk_vec[i]["point"]
        x, y = uncompress_key(secp256k1, format_point(pk_vec_i_point))
        i_point = secp256k1.Point(x, y)

        public_key = secp256k1.add(public_key, i_point)

    #Gen = secp256k1
    #other_pub = (, 155495596836202816797655827683372320298316051115419340788855808592089936756180)

    pk_x = public_key[0]
    pk_y = public_key[1]

    hex_pk_x = hex(pk_x)
    hex_pk_y = hex(pk_y)

    # Concatenate
    hex_pk = "04"+hex_pk_x[2:]+hex_pk_y[2:]

    public_key_int = public_key
    public_key_hex = hex_pk
    return public_key_int, public_key_hex

def pkToAddr(public_key):

    public_key = public_key[2:]
    public_key_bytes = codecs.decode(public_key, 'hex')
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(public_key_bytes)
    keccak_digest = keccak_hash.hexdigest()
    # Take last 20 bytes
    wallet_len = 40
    wallet = '0x' + keccak_digest[-wallet_len:]

    return wallet


def uncompress_key(curve, compressed_key):
  x, is_odd = compressed_key
  p, a, b = curve._p, curve._a, curve._b

  y = sqrtmod(pow(x, 3, p) + a * x + b, p)

  if bool(is_odd) == bool(y & 1):
    return (x, y)

  return (x, p - y)



def parse_pk_vec(lshare):
    with open(lshare, "r") as f:
        local_share = json.load(f)
        pk_vec = local_share['pk_vec']

    return pk_vec


def format_point(point):

    array_int = point[1:]
    is_odd = int(point[0]) % 2
    array_hex = "0x"+bytes(array_int).hex()

    x = int(array_hex, 0)
    
    return x, is_odd



def getSign():
    
    path = "signature/signature1.json"
    with open(path, "r") as f:
        signature = json.load(f)

    r_scalar = signature["r"]["scalar"]
    s_scalar = signature["s"]["scalar"]
    v = signature["recid"] # Can be this

    r_hex = format_scalar(r_scalar)
    s_hex = format_scalar(s_scalar)

    v_hex=""
    if v==0:
        v_hex = "1b"
    elif v==1:
        v_hex = "1c"

    # Concatenate
    sign = "0x" + str(r_hex)+str(s_hex)+v_hex


    return sign


def format_scalar(scalar):

    scalar_hex = bytes(scalar).hex()

    return scalar_hex



