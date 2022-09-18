
"""
Auxiliary functions
"""

import json
import codecs

from Crypto.Hash import keccak
from pycoin.ecdsa.Curve import Curve
from nummaster.basic import sqrtmod

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0x0000000000000000000000000000000000000000000000000000000000000000
b = 0x0000000000000000000000000000000000000000000000000000000000000007
secp256k1 = Curve(p, a, b)


def getPK(nOfShares):
    # Sum all public key shares

    pk_vec = parse_pk_vec("sks/local-share1.json")
    pk_vec_0_point = pk_vec[0]["point"]

    x, y = uncompress_key(secp256k1, format_point(pk_vec_0_point))
    public_key = secp256k1.Point(x, y)
    
    for i in range(nOfShares):
        pk_vec_i_point = pk_vec[i]["point"]
        x, y = uncompress_key(secp256k1, format_point(pk_vec_i_point))
        i_point = secp256k1.Point(x, y)

        public_key = secp256k1.add(public_key, i_point)


    pk_x = public_key[0]
    pk_y = public_key[1]

    hex_pk_x = hex(pk_x)
    hex_pk_y = hex(pk_y)

    # Concatenate
    hex_pk = "04"+str(hex_pk_x)[2:]+str(hex_pk_y)[2:]

    public_key_int = public_key
    public_key_hex = hex_pk
    return public_key_int, public_key_hex

def pkToAddr(public_key):

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
    array_hex = '0x' + ''.join([format(int(hex(c), 16), '02X') for c in array_int])
    x = int(array_hex, 0)
    
    return x, is_odd



def getSign():
    
    path = "signature/signature1.json"
    with open(path, "r") as f:
        signature = json.load(f)

    r_scalar = signature["r"]["scalar"]
    s_scalar = signature["s"]["scalar"]
    v = signature["recid"]

    r_hex = format_scalar(r_scalar)
    s_hex = format_scalar(s_scalar)

    v_hex=""
    if v==0:
        v_hex = "1B"
    elif v==1:
        v_hex = "1C"

    # Concatenate
    sign = "0x" + str(r_hex)+str(s_hex)+v_hex


    return sign


def format_scalar(scalar):

    scalar_hex = ''.join([format(int(hex(c), 16), '02X') for c in scalar])

    return scalar_hex



