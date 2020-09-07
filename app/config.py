import os

port = 3010

x_base = int(os.getenv('X_BASE', 55066263022277343669578718895168534326250603453777594175500187360389116729240))
y_base = int(os.getenv('Y_BASE', 32670510020758816978083085130507043184471273380659243275938904335757337482424))

a = int(os.getenv('A', 0))
b = int(os.getenv('B', 7))
p = int(os.getenv('P', 2 ** 256 - 2 ** 32 - 977))
q = int(os.getenv('Q', 115792089237316195423570985008687907852837564279074904382605163141518161494337))

hash_length = int(os.getenv('HASH_LENGTH', 256))

pedersen_seed = os.getenv('SEED', 'pedersen_seed')

mod_len_bits = int(os.getenv('RSA_LENGTH', 4096))

