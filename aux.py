
"""
Auxiliary functions
"""

import json

from pycoin.ecdsa.Curve import Curve
from nummaster.basic import sqrtmod

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0x0000000000000000000000000000000000000000000000000000000000000000
b = 0x0000000000000000000000000000000000000000000000000000000000000007
secp256k1 = Curve(p, a, b)


def getPK(nOfShares):
    
    pk_vec = parse_pk_vec("sks/local-share1.json")
    first_comp_key = pk_vec[0]["point"]
    x1 = first_comp_key[0:]
    is_odd1 = first_comp_key[0]

    #array_hex = [hex(i) for i in x1]
    array_hex = '0x' + ''.join([format(int(hex(c), 16), '02X') for c in x1])
    print(array_hex)
    """
    # Sum all public key shares
    x, y = uncompress_key(secp256k1, first_comp_key)
    public_key = secp256k1.Point(x, y)
    
    for i in range(nOfShares):
        comp_key = pk_vec[i]["point"]
        x, y = uncompress_key(secp256k1, comp_key)
        i_point = secp256k1.Point(x, y)

        public_key = secp256k1.add(public_key, i_point)

    return public_key
    """
    return 1


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


