# pygost.CURVES['id-GostR3410-2001-CryptoPro-A-ParamSet']
import hashlib
import sys

from fastecdsa.curve import Curve
from fastecdsa.point import Point
from pygost.gost34112012 import GOST34112012
from app.crypto import gen_random_from_scalar_field, create_point, square_root_3_mod_4, square_root_exists
from binascii import hexlify
from app.helper import long_to_bytes

a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94
b = 166
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97
q = 0xffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893
x_base = 1
y_base = 0x8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14

curve = Curve('GOST3210-2001', p, a, b, q, x_base, y_base)
base = Point(x_base, y_base, curve)
point_at_infinity = base - base


def gost_point_validate(P):
    try:
        Point(P[0], P[1], curve)
        return True
    except:
        return False


def l2bLE(coord):
    res = (long_to_bytes(coord, 'little', 64))
    return res


def create_point(seed, curve):
    if p % 4 != 3:
        sys.exit('Case p % 4 != 3 is not supported!')
    h = hashlib.sha256()
    h.update(bytes(seed, encoding='utf-8'))

    x = int(h.hexdigest(), 16)
    x = x % p

    right_part = (x ** 3 + a * x + b) % p
    y = square_root_3_mod_4(right_part, p)

    while (square_root_exists(right_part, p) == False) or (q * Point(x, y, curve) != point_at_infinity):
        x = x + 1
        right_part = (x ** 3 + a * x + b) % p
        y = square_root_3_mod_4(right_part, p)

    R = Point(x, y, curve)
    if q * R != point_at_infinity:
        sys.exit('Failure: base point for blinding in Pedersen commit is NOT in subgroup of order q ! ')
    return R


def hash_to_point(info):
    # @todo remove hardcode
    if info == 'seed-for-test':
        return Point(0x8e7e4fd43549adbc1d1114eba80fd4a41a1bc823b0e1b0dc3f75580979a7b188,
                     0xcecb5cf337d7908efcfea414d9b6f9ced465a94b086cbfc056180ba978a778d0, curve)

    return create_point(info, curve)


def hash_for_blind_signature(A, B, Z, message):
    msgToHash = (l2bLE(A.x) + l2bLE(A.y) + l2bLE(B.x) + l2bLE(B.y) + l2bLE(Z.x) + l2bLE(Z.y) + (bytes(message, encoding='utf-8')))
    hash = GOST34112012(digest_size=32)
    hash.update(msgToHash)
    digest = hexlify(hash.digest()[::-1])
    epsilon = int(bytes('0x', encoding='utf-8') + digest, 16) % q
    return epsilon


def blind_signature_verify(rho, omega, sigma, delta, Z, message, public_key):
    public_key = Point(public_key[0], public_key[1], curve)
    Z = Point(Z[0], Z[1], curve)
    A = rho * base + omega * public_key
    B = sigma * base + delta * Z
    hash = hash_for_blind_signature(A, B, Z, message)
    return (omega + delta) % q == hash


def blind_signature_step_one(info):
    u = gen_random_from_scalar_field()
    s = gen_random_from_scalar_field()
    d = gen_random_from_scalar_field()
    Z = hash_to_point(info)
    A = u * base
    B = s * base + d * Z
    return A, B, u, s, d


def blind_signature_step_two(private_key, e, d, s, u):
    c = (e - d) % q
    r = (u - c * private_key) % q
    return r, c, s, d


def blind_signature_client_step_one(public_key, A, B, info, message):
    t1 = gen_random_from_scalar_field()
    t2 = gen_random_from_scalar_field()
    t3 = gen_random_from_scalar_field()
    t4 = gen_random_from_scalar_field()
    Z = hash_to_point(info)
    Alpha = A + t1 * base + t2 * public_key
    Beta = B + t3 * base + t4 * Z
    epsilon = hash_for_blind_signature(Alpha, Beta, Z, message)
    e = (epsilon - t2 - t4) % q
    return e, t1, t2, t3, t4


def blind_signature_client_step_two(r, c, s, d, t1, t2, t3, t4):
    rho = (r + t1) % q
    omega = (c + t2) % q
    sigma = (s + t3) % q
    delta = (d + t4) % q

    return rho, omega, sigma, delta


# ---------
# TEST DATA
# message = 'Hello!'
# publicKey = [0x6759e62a193e065a3cec290e5f2cf5f3589fa4e5f7baad71e1309eeb8c7e2281L,
#              0xdbbde452aa819a9762438ac007c5c476a23f6a05f9d58dcc71d71625a8dd792L]
#
# Z = [0x8e7e4fd43549adbc1d1114eba80fd4a41a1bc823b0e1b0dc3f75580979a7b188L,
#     0xcecb5cf337d7908efcfea414d9b6f9ced465a94b086cbfc056180ba978a778d0L]
#
# rho = 0x85f834e0df7dc3943c87f210b10cd763a5b682537bde72459b29a49a8e5827b8L
# omega = 0x2cf48d086b892aa2851a35cf9cd543a9c35951e36d11847a04323afc622c3090L
# sigma = 0x29b842d946676253b273571dfdc8b0974e0cd194616fb22e9b46c6449629e456L
# delta = 0x272bf8c85013f4ab008683fccb18f0f2a0b73e40c7984d707add6e90f51aaf93L
#
# now = datetime.now()
# for i in range(10):
#     signatureOK = blind_signature_verify(rho, omega, sigma, delta, Z, message, publicKey)
#     print(signatureOK)
#
# print datetime.now() - now


# ---------
def dummy_blind_signature_generate(message):
    private_key = 0x4a15f47b688da7f9784a23e72f5c01274b13f50278ff07697c48bd823d03318d
    public_key = private_key * base
    info = 'seed-for-test'
    Z = hash_to_point(info)
    A, B, u, s, d = blind_signature_step_one(info)
    e, t1, t2, t3, t4 = blind_signature_client_step_one(public_key, A, B, info, message)
    r, c, s, d = blind_signature_step_two(private_key, e, d, s, u)
    rho, omega, sigma, delta = blind_signature_client_step_two(r, c, s, d, t1, t2, t3, t4)
    return rho, omega, sigma, delta, Z, public_key

