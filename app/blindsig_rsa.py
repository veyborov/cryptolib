import hashlib
import random
import rsa

from app.helper import int_to_bytes
from app.config import mod_len_bits
from app.rsa_keys import modulo, public_exp, private_exp


def mod_inverse(a, m):
    m0 = m
    y = 0
    x = 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        t = m
        m = a % m
        a = t
        t = y
        y = x - q * y
        x = t
    if x < 0:
        x = x + m0
    return x


def FDH_padding(message, modulo, mod_len_bits):
    intlist = []
    bytelist = bytes(intlist)
    i = 0
    # error
    if mod_len_bits % 256 != 0:
        print("Supported only lengths divisible by 256")
        return 0
    num_of_blocks = mod_len_bits // 256
    for i in range(num_of_blocks):
        h = hashlib.sha256()
        h.update(int_to_bytes(i, 4) + message)
        digest = h.digest()
        if i == num_of_blocks - 1:
            j = 1
            while int.from_bytes(bytelist + digest, "little") > modulo:
                h = hashlib.sha256()
                h.update(int_to_bytes(i + j, 4) + message)
                digest = h.digest()
                j += 1
        bytelist += digest
        i += 1
    return int.from_bytes(bytelist, "little")


def blind_signature_verify_rsa(signature, message, public_exp, modulo):
    padded_message = FDH_padding(message, modulo, mod_len_bits)
    m1 = rsa.core.decrypt_int(signature, public_exp, modulo)
    return padded_message == m1


def dummy_blind_signature_generate_rsa(message):
    padded_message = FDH_padding(message, modulo, mod_len_bits)
    r = random.randrange(modulo)
    masked_message = (padded_message * rsa.core.decrypt_int(r, public_exp, modulo)) % modulo
    masked_signature = rsa.core.decrypt_int(masked_message, private_exp, modulo)
    signature = (masked_signature * mod_inverse(r, modulo)) % modulo
    return signature
