import hashlib
import random
import sys

from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
from fastecdsa import keys
from coincurve import PublicKey

from app.config import a, b, p, q, x_base, y_base, hash_length, pedersen_seed
from app.helper import long_to_bytes

base = Point(x_base, y_base, secp256k1)
point_at_infinity = base - base


def get_base_point():
    return base


def create_point(seed):
    if p % 4 != 3:
        sys.exit('Case p % 4 != 3 is not supported!')
    h = hashlib.sha256()
    h.update(bytes(seed, encoding='utf-8'))

    x = int(h.hexdigest(), 16)
    x = x % p

    right_part = (x ** 3 + a * x + b) % p
    y = square_root_3_mod_4(right_part, p)

    while (square_root_exists(right_part, p) is False) or (q * Point(x, y, secp256k1) != point_at_infinity):
        x = x + 1
        right_part = (x ** 3 + a * x + b) % p
        y = square_root_3_mod_4(right_part, p)

    R = Point(x, y, secp256k1)
    if q * R != point_at_infinity:
        sys.exit('Failure: base point for blinding in Pedersen commit is NOT in subgroup of order q ! ')
    return R


def power(x, y, p):
    res = 1
    x = x % p
    while y > 0:
        if y & 1:
            res = (res * x) % p
        y = y >> 1
        x = (x * x) % p
    return res


def gen_random_from_scalar_field():
    return keys.gen_private_key(secp256k1)


def generate_key_pair():
    private_key = gen_random_from_scalar_field()
    public_key = private_key * base
    return private_key, public_key


def mult_inv_in_scalar_field(a):
    return power(a, q - 2, q)


def square_root_exists(n, p):
    if power(n, (p - 1) // 2, p) == 1:
        return True
    return False


def square_root_3_mod_4(n, p):
    if p % 4 != 3:
        sys.exit('Case p % 4 != 3 is not supported!')
    s_root = power(n, (p + 1) // 4, p)
    return s_root


def pedersen_commit(x, r):
    R = create_point(pedersen_seed)
    return x * base + r * R


def unblind_pedersen_commit(commit, r):
    R = create_point(pedersen_seed)
    return Point(commit[0], commit[1], secp256k1) - r * R


def unblind_public_keys(public_keys_commits, secret_keys_of_commits):
    all_unblinded_public_keys = []
    for i in range(len(public_keys_commits)):
        unblinded_public_key = unblind_pedersen_commit(public_keys_commits[i], secret_keys_of_commits[i])
        all_unblinded_public_keys.append(unblinded_public_key)
    return all_unblinded_public_keys


def calculate_main_key(public_keys_commits, secret_keys_of_commits):
    unblinded_public_keys = unblind_public_keys(public_keys_commits, secret_keys_of_commits)
    public_key = point_at_infinity
    for unblinded_public_key in unblinded_public_keys:
        public_key = public_key + unblinded_public_key
    return public_key


def generate_pair():
    private_key = gen_random_from_scalar_field()
    pub_key = private_key * base
    return private_key, pub_key


def generate_polynomial_coefficients(f_i0, k):
    coefficients = [f_i0]
    for j in range(1, k):
        f_ij = gen_random_from_scalar_field()
        coefficients.append(f_ij)
    return coefficients


# shadows (f)
def calculate_polynomial(j, coefficients):
    sum = 0
    for i in range(len(coefficients)):
        sum = sum + coefficients[i] * (j ** i)
    return sum % q


def calculate_polynomial_coefficients_exponents(coefficients):
    return map(lambda coefficient: int(coefficient) * base, coefficients)


def hash(data):
    h = hashlib.sha256()
    h.update(bytes(data, encoding='utf-8'))
    return int(h.hexdigest(), 16)


def calculate_lagrange_coefficient(j, indexes):
    mult = 1
    for x_i in indexes:
        if x_i != j:
            mult *= x_i * mult_inv_in_scalar_field(x_i - j)
            mult = mult % q
    return mult % q


def restore_common_secret(indexes, decrypted_shadows_sums):
    s = 0
    for l in indexes:
        s += decrypted_shadows_sums[l - 1] * calculate_lagrange_coefficient(l, indexes)
        s = s % q
    return s


def encrypt_shadow(shadow, public_key):
    r, R = generate_pair()
    shared_secret = int(r) * Point(public_key[0], public_key[1], secp256k1)
    enc = hash(str(shared_secret)) ^ int(shadow)
    return enc, R


def check_shadow(shadow, j, exponents):
    sum = point_at_infinity
    x = 1

    for exponent in exponents:
        sum = sum + x * Point(exponent[0], exponent[1], secp256k1)
        x = x * j

    return shadow * base == sum


def decrypt_shadow(cipher_text, public_key, private_key):
    R = Point(public_key[0], public_key[1], secp256k1)
    shared_secret = int(private_key) * R
    return int(cipher_text) ^ hash(str(shared_secret))


def calculate_encrypted_shadows(polynomial_coefficients, unblinded_public_keys):
    encrypted_shadows = []
    for i in range(len(unblinded_public_keys)):
        shadow_for_user_i = calculate_polynomial(i + 1, polynomial_coefficients)
        encrypted_shadow_for_user_i = encrypt_shadow(shadow_for_user_i, unblinded_public_keys[i])
        encrypted_shadows.append(encrypted_shadow_for_user_i)
    return encrypted_shadows


def decrypt_and_check_shadows(private_key, idx, encrypted_shadows, polynomial_coefficients_exponents,
                              unblinded_public_keys):
    decrypted_shadows = []

    for i in range(len(unblinded_public_keys)):
        shadow = decrypt_shadow(encrypted_shadows[i][0], encrypted_shadows[i][1], private_key)

        if unblinded_public_keys[i] != polynomial_coefficients_exponents[i][0]:
            print("First shadow coefficient must be equal to public key. Pub key ia Stop the DKG protocol. ")
            return {
                "status": "error",
                "message": "First shadow coefficient must be equal to public key. Stop the DKG protocol",
                "idx": i
            }

        if not check_shadow(shadow, idx + 1, polynomial_coefficients_exponents[i]):
            print("Failed check_shadow !")
            print("Shadow from service number", i)
            print(shadow)
            return {
                "status": "error",
                "message": "Shadow for service " + str(i) + " incorrect",
                "idx": i
            }

        decrypted_shadows.append(shadow)

    return {
        "status": "ok",
        "sum": str(sum(decrypted_shadows) % q)
    }


def hash_points(points):
    h = hashlib.sha256()
    for p in points:
        x = p.x
        y = p.y
        h.update(bytes(str(x) + ',' + str(y) + ',', encoding='utf-8'))

    return int(h.hexdigest(), 16)


def P(point):
    if point[0] == 0 and point[1] == 1:
        return point_at_infinity
    else:
        return Point(int(point[0]), int(point[1]), secp256k1)


def verify_range_proof(public_key, A, B, A0_s, A1_s, B0_s, B1_s, c0, c1, r0_ss, r1_ss):
    n = 2 ** hash_length
    b0 = (r0_ss * base == P(A0_s) + c0 * P(A))
    b1 = (r1_ss * base == P(A1_s) + c1 * P(A))
    b2 = (r0_ss * public_key == P(B0_s) + c0 * P(B))
    b3 = (r1_ss * public_key == P(B1_s) + c1 * (P(B) - base))
    c = hash_points([public_key, P(A), P(B), P(A0_s), P(B0_s), P(A1_s), P(B1_s)])
    b4 = ((c0 + c1) % n == c)
    return b0 and b1 and b2 and b3 and b4


def verify_range_proof_fast(public_key, A, B, A0_s, A1_s, B0_s, B1_s, c0, c1, r0_ss, r1_ss):
    try:
        n = 2 ** hash_length
        r0_ss_ = long_to_bytes(r0_ss)
        c0_ = long_to_bytes(c0)
        r1_ss_ = long_to_bytes(r1_ss)
        c1_ = long_to_bytes(c1)

        base_ = PublicKey.from_point(base.x, base.y)
        public_key_ = PublicKey.from_point(public_key.x, public_key.y)
        A0_s_ = PublicKey.from_point(A0_s[0], A0_s[1])
        A_ = PublicKey.from_point(A[0], A[1])
        A1_s_ = PublicKey.from_point(A1_s[0], A1_s[1])
        B0_s_ = PublicKey.from_point(B0_s[0], B0_s[1])
        B_ = PublicKey.from_point(B[0], B[1])
        B1_s_ = PublicKey.from_point(B1_s[0], B1_s[1])

        b0 = (base_.multiply(r0_ss_) == A0_s_.combine([A0_s_, A_.multiply(c0_)]))
        b1 = (base_.multiply(r1_ss_) == A1_s_.combine([A1_s_, A_.multiply(c1_)]))
        b2 = (public_key_.multiply(r0_ss_) == B0_s_.combine([B0_s_, B_.multiply(c0_)]))
        b3 = (public_key_.multiply(r1_ss_) == B1_s_.combine(
            [B1_s_, base_.combine([B_, PublicKey.from_point(base.x, p - base.y)]).multiply(c1_)]))
        c = hash_points([public_key, P(A), P(B), P(A0_s), P(B0_s), P(A1_s), P(B1_s)])
        b4 = ((c0 + c1) % n == c)
        return b0 and b1 and b2 and b3 and b4
    except:
        return False


def verify_encrypted_bulletin(encrypted_bulletin, proof, main_key):
    sum_a = point_at_infinity
    sum_b = point_at_infinity
    Rs = []

    try:
        main_key = P(main_key)
    except:
        print("Invalid Main Key")
        return False

    for vote in encrypted_bulletin:
        if verify_range_proof_fast(main_key, vote[0], vote[1], vote[2], vote[3], vote[4], vote[5], vote[6], vote[7],
                                   vote[8], vote[9]):
            sum_a += P(vote[0])
            sum_b += P(vote[1])
            Rs.append(vote[0])
        else:
            print("Range proof is incorrect!")
            return False

    if verify_equality_of_dl(proof[0], proof[1], proof[2], base, sum_a, main_key, sum_b - base, Rs):
        return True
    else:
        print("VerifyRangeProof Failed!")
        return False


def verify_encrypted_bulletins(encrypted_bulletins, main_key):
    verified = []

    for encrypted_bulletin, proof in encrypted_bulletins:
        if verify_encrypted_bulletin(encrypted_bulletin, proof, main_key):
            verified.append([encrypted_bulletin, proof])

    return verified


def verify_encrypted_bulletins_v2(encrypted_bulletins, main_key):
    verified = []

    for encrypted_bulletin, proof in encrypted_bulletins:
        verified.append(int(verify_encrypted_bulletin(encrypted_bulletin, proof, main_key)))

    return verified


def make_range_proof(msg, A, B, r, public_key):
    n = 2 ** hash_length

    A0_s = 0
    A1_s = 0
    B0_s = 0
    B1_s = 0
    c0 = 0
    c1 = 0
    r0_ss = 0
    r1_ss = 0

    if msg == 0:

        c1 = random.randrange(0, n)

        r1_ss = gen_random_from_scalar_field()

        B_s = B - base
        A1_s = r1_ss * base - c1 * A
        B1_s = r1_ss * public_key - c1 * B_s

        r0_s = gen_random_from_scalar_field()
        A0_s = r0_s * base
        B0_s = r0_s * public_key

        c = hash_points([public_key, A, B, A0_s, B0_s, A1_s, B1_s])
        c0 = (c - c1) % n

        r0_ss = (r0_s + c0 * r) % q

    elif msg == 1:

        c0 = random.randrange(0, n)

        r0_ss = gen_random_from_scalar_field()

        B_s = B
        A0_s = r0_ss * base - c0 * A
        B0_s = r0_ss * public_key - c0 * B_s

        r1_s = gen_random_from_scalar_field()

        A1_s = r1_s * base
        B1_s = r1_s * public_key

        c = hash_points([public_key, A, B, A0_s, B0_s, A1_s, B1_s])
        c1 = (c - c0) % n

        r1_ss = (r1_s + c1 * r) % q

    else:

        return point_at_infinity, point_at_infinity, point_at_infinity, point_at_infinity, point_at_infinity, point_at_infinity, 0, 0, 0, 0

    return [A, B, A0_s, A1_s, B0_s, B1_s, c0, c1, r0_ss, r1_ss]


def make_encrypted_bulletin(bulletin, public_key):
    encrypted_bulletin = []
    sum_vote = 0
    sum_R = point_at_infinity
    sum_C = point_at_infinity
    sum_r = 0
    Rs = []

    public_key = P(public_key)

    for vote in bulletin:
        sum_vote = sum_vote + vote
        message = vote * base

        # encrypt Message on ElGamal:
        r, R = generate_pair()
        C = message + int(r) * public_key

        sum_R = sum_R + R
        sum_C = sum_C + C
        sum_r = sum_r + r

        sum_r = sum_r % q

        encrypted_bulletin.append(make_range_proof(vote, R, C, r, public_key))
        Rs.append(R)

    proof = prove_equality_of_dl(sum_r, base, sum_R, public_key, sum_C - base, Rs)

    return encrypted_bulletin, [proof[0], [proof[1].x, proof[1].y], [proof[2].x, proof[2].y]]


def add_encrypted_bulletins_to_sum(encrypted_bulletins, main_key, prev_sums=False):
    sum_A = []
    sum_B = []
    number_of_candidates = len(encrypted_bulletins[0][0])

    for i in range(number_of_candidates):
        if prev_sums and len(prev_sums["sum_A"]):
            sum_A.append(P(prev_sums["sum_A"][i]))
            sum_B.append(P(prev_sums["sum_B"][i]))
        else:
            sum_A.append(point_at_infinity)
            sum_B.append(point_at_infinity)

    for encrypted_bulletin in encrypted_bulletins:
        if verify_encrypted_bulletin(encrypted_bulletin[0], encrypted_bulletin[1],
                                     main_key):
            for idx, encrypted_vote in enumerate(encrypted_bulletin[0]):
                sum_A[idx] += P(encrypted_vote[0])
                sum_B[idx] += P(encrypted_vote[1])

    return sum_A, sum_B


def subtract_encrypted_bulletins_from_sum(encrypted_bulletins, main_key, prev_sums):
    sum_A = []
    sum_B = []
    number_of_candidates = len(encrypted_bulletins[0][0])

    for i in range(number_of_candidates):
        sum_A.append(P(prev_sums["sum_A"][i]))
        sum_B.append(P(prev_sums["sum_B"][i]))

    for encrypted_bulletin in encrypted_bulletins:
        if verify_encrypted_bulletin(encrypted_bulletin[0], encrypted_bulletin[1],
                                     main_key):
            for idx, encrypted_vote in enumerate(encrypted_bulletin[0]):
                sum_A[idx] -= P(encrypted_vote[0])
                sum_B[idx] -= P(encrypted_vote[1])

    return sum_A, sum_B


def prove_equality_of_dl(x, G1, Y1, G2, Y2, Rs=[]):
    u = gen_random_from_scalar_field()
    U1 = u * G1
    U2 = u * G2
    v = hash_points([U1, U2, base, Y1, G2, Y2] + Rs)
    w = x * v + u
    w = w % q
    return w, U1, U2


def partially_decrypt_sum_a(sum_A, private_key):
    partially_decrypted_A = []
    public_key = private_key * base
    for A in sum_A:
        partially_decrypted = private_key * P(A)
        w, U1, U2 = prove_equality_of_dl(private_key, base, public_key, P(A), partially_decrypted)
        partially_decrypted_A.append([partially_decrypted, w, U1, U2])

    return partially_decrypted_A


def calculate_sum_shadow_exponent(j, polynomial_coefficients_exponents):
    sum_exponent = point_at_infinity
    for i in range(len(polynomial_coefficients_exponents)):
        Exp_s_i = point_at_infinity
        l = 0
        for exponent in polynomial_coefficients_exponents[i]:
            Exp_s_i += (j ** l) * P(exponent)
            l += 1
        sum_exponent += Exp_s_i
    return sum_exponent


def verify_equality_of_dl(w, U1, U2, G1, Y1, G2, Y2, Rs=[]):
    U1 = P(U1)
    U2 = P(U2)
    Rs = list(map(lambda point: P(point), Rs))

    v = hash_points([U1, U2, G1, Y1, G2, Y2] + Rs)
    knowledge_ok1 = (w * G1 == v * Y1 + U1)
    knowledge_ok2 = (w * G2 == v * Y2 + U2)
    return knowledge_ok1 and knowledge_ok2


def verify_equality_of_dl_wrapped(dec, sum_A, public_key):
    for idx in range(len(dec)):
        partially_decrypted = P(dec[idx][0])
        w = dec[idx][1]
        U1 = dec[idx][2]
        U2 = dec[idx][3]
        if verify_equality_of_dl(w, U1, U2, P(public_key), base, P(sum_A[idx]), partially_decrypted):
            return False
    return True


def solve_dlp(Q, n):
    for x in range(n + 1):
        if x * base == Q:
            return x
    return -1


def calculate_voting_result(group_of_k_servers, number_of_voters, number_of_candidates,
                            polynomial_coefficients_exponents, partial_decrypts,
                            sum_A, sum_B,
                            main_key):
    sum_A = map(lambda sum: P(sum), sum_A)
    sum_B = map(lambda sum: P(sum), sum_B)

    exponents_of_sum_of_shadows = []
    j = 1
    while j <= len(polynomial_coefficients_exponents):
        exponents_of_sum_of_shadows.append(calculate_sum_shadow_exponent(j, polynomial_coefficients_exponents))
        j += 1

    sum_of_verified_partial_decrypts = []
    for i in range(number_of_candidates):
        sum_of_verified_partial_decrypts.append(point_at_infinity)

    lagrange_sum = point_at_infinity
    for j in group_of_k_servers:
        lagrange_coefficient = int(calculate_lagrange_coefficient(j, group_of_k_servers))
        lagrange_sum += lagrange_coefficient * exponents_of_sum_of_shadows[j - 1]

    if not (lagrange_sum == P(main_key)):
        print("lagrange_sum != public_key. Calculate voting result failed")
        return False, {"message": "lagrange_sum != public_key. Calculate voting result failed"}

    for j in group_of_k_servers:
        pub = exponents_of_sum_of_shadows[j - 1]
        dec = partial_decrypts[j - 1]
        for idx in range(len(sum_of_verified_partial_decrypts)):
            partially_decrypted = P(dec[idx][0])
            w = dec[idx][1]
            U1 = dec[idx][2]
            U2 = dec[idx][3]
            if verify_equality_of_dl(w, U1, U2, base, pub, sum_A[idx], partially_decrypted):
                lagrange_coefficient = int(calculate_lagrange_coefficient(j, group_of_k_servers))
                sum_of_verified_partial_decrypts[idx] += lagrange_coefficient * partially_decrypted
            else:
                print("Public key of cheating server:")
                print(pub)
                return False, {"message": "public key of cheating server", "idx": j,
                               "public_key": [str(pub.x), str(pub.y)]}

    result_of_voting = []
    for i in range(number_of_candidates):
        sum_votes_for_candidate = sum_B[i] - sum_of_verified_partial_decrypts[i]
        num_of_votes_for_candidate = solve_dlp(sum_votes_for_candidate, number_of_voters)
        if num_of_votes_for_candidate == -1:
            print("solve dlp failed")
            return False, {"message": "solve dlp failed"}

        result_of_voting.append(num_of_votes_for_candidate)

    return result_of_voting, {}


#########################################
# Calculate results with observers part #
#########################################
def calculate_voting_result_rtk(group_of_k_servers, number_of_voters, number_of_candidates,
                                polynomial_coefficients_exponents, partial_decrypts,
                                sum_A, sum_B, decrypt_key, commission_key, commission_decrypt):
    sum_A = list(map(lambda sum: P(sum), sum_A))
    sum_B = list(map(lambda sum: P(sum), sum_B))

    exponents_of_sum_of_shadows = []
    j = 1
    while j <= len(polynomial_coefficients_exponents):
        exponents_of_sum_of_shadows.append(calculate_sum_shadow_exponent(j, polynomial_coefficients_exponents))
        j += 1

    sum_of_verified_partial_decrypts = []
    for i in range(number_of_candidates):
        sum_of_verified_partial_decrypts.append(point_at_infinity)

    lagrange_sum = point_at_infinity
    for j in group_of_k_servers:
        lagrange_coefficient = int(calculate_lagrange_coefficient(j, group_of_k_servers))
        lagrange_sum += lagrange_coefficient * exponents_of_sum_of_shadows[j - 1]

    if not (lagrange_sum == P(decrypt_key)):
        print("lagrange_sum != public_key. Calculate voting result failed")
        return False, {"message": "lagrange_sum != public_key. Calculate voting result failed"}

    for j in group_of_k_servers:
        pub = exponents_of_sum_of_shadows[j - 1]
        dec = partial_decrypts[j - 1]
        for idx in range(len(sum_of_verified_partial_decrypts)):
            partially_decrypted = P(dec[idx][0])
            w = dec[idx][1]
            U1 = dec[idx][2]
            U2 = dec[idx][3]
            if verify_equality_of_dl(w, U1, U2, base, pub, sum_A[idx], partially_decrypted):
                lagrange_coefficient = int(calculate_lagrange_coefficient(j, group_of_k_servers))
                sum_of_verified_partial_decrypts[idx] += lagrange_coefficient * partially_decrypted
            else:
                print("Public key of cheating server:")
                print(pub)
                return False, {"message": "public key of cheating server", "idx": j,
                               "public_key": [str(pub.x), str(pub.y)]}

    h1 = hash_points([P(decrypt_key), P(commission_key)])
    h2 = hash_points([P(commission_key), P(decrypt_key)])

    result_of_voting = []
    for i in range(number_of_candidates):
        common_decrypt = h1 * sum_of_verified_partial_decrypts[i] + h2 * P(commission_decrypt[i][0])
        sum_votes_for_candidate = sum_B[i] - common_decrypt
        num_of_votes_for_candidate = solve_dlp(sum_votes_for_candidate, number_of_voters)
        if num_of_votes_for_candidate == -1:
            print("solve dlp failed")
            return False, {"message": "solve dlp failed"}

        result_of_voting.append(num_of_votes_for_candidate)

    return result_of_voting, {}


def add_commission_key(public_key1, public_key2):
    try:
        P1 = P(public_key1)
        P2 = P(public_key2)
        k1 = hash_points([P1, P2])
        k2 = hash_points([P2, P1])
        result = k1 * P1 + k2 * P2
        return True, result
    except:
        return False, 'decrypt or commission key is not valid'


def point_validate(point):
    try:
        P(point)
        return True
    except:
        return False


def validate_private_key(public_key, private_key):
    try:
        if private_key * base == P(public_key):
            return True, ''
        return False, 'Public key is not valid'
    except:
        return False, 'Private key is not valid'
