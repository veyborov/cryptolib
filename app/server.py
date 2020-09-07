from flask import Flask, jsonify, request

from app.blindsig_rsa import blind_signature_verify_rsa, dummy_blind_signature_generate_rsa
from app.crypto import generate_pair, gen_random_from_scalar_field, pedersen_commit, generate_polynomial_coefficients, \
    unblind_public_keys, calculate_polynomial_coefficients_exponents, calculate_encrypted_shadows, \
    restore_common_secret, decrypt_and_check_shadows, verify_encrypted_bulletin, make_encrypted_bulletin, \
    partially_decrypt_sum_a, get_base_point, calculate_main_key, create_point, \
    calculate_voting_result, verify_encrypted_bulletins, add_encrypted_bulletins_to_sum, \
    subtract_encrypted_bulletins_from_sum, add_commission_key, verify_encrypted_bulletins_v2, point_validate, \
    generate_key_pair, verify_equality_of_dl_wrapped, calculate_voting_result_rtk, validate_private_key
from app.helper import int_to_str, str_to_int, get_post_data, dec_to_hexstr, str_to_hex
from app.config import a, b, p, q, x_base, y_base, hash_length, pedersen_seed
from time import time

from app.blindsig_ec import dummy_blind_signature_generate, gost_point_validate, blind_signature_verify
from flask_cors import CORS

from app.rsa_keys import public_exp, modulo

app = Flask(__name__)
CORS(app)


@app.route('/health', methods=['GET'])
def health_checker():
    return jsonify({
        "ok": True
    })


@app.route('/livenessProbe', methods=['GET'])
def liveness_probe():
    return jsonify({
        "time": int(time() * 1000)
    })


@app.route('/readinessProbe', methods=['GET'])
def readiness_probe():
    return jsonify({
        "time": int(time() * 1000)
    })


@app.route('/v1/getBasePoint', methods=['GET'])
def get_base_point_handler():
    return jsonify(int_to_str(get_base_point()))


@app.route('/v1/generateKeys', methods=['GET'])
def generate_keys_handler():
    privateKey, publicKey = generate_pair()
    secretKeyOfCommit = gen_random_from_scalar_field()
    publicKeyCommit = pedersen_commit(privateKey, secretKeyOfCommit)
    return jsonify({
        "privateKey": int_to_str(privateKey),
        "publicKey": int_to_str([publicKey.x, publicKey.y]),
        "secretKeyOfCommit": int_to_str(secretKeyOfCommit),  # r (steps 1,2)
        "publicKeyCommit": int_to_str([publicKeyCommit.x, publicKeyCommit.y]),  # C (step 1)
    })


@app.route('/v1/getParamSet', methods=['GET'])
def get_paramset_handler():
    pedersenBase = create_point(pedersen_seed)

    return jsonify({
        "a": int_to_str(a),
        "b": int_to_str(b),
        "p": int_to_str(p),
        "q": int_to_str(q),
        "base_point": int_to_str([x_base, y_base]),
        "pedersen_base": int_to_str([pedersenBase.x, pedersenBase.y]),
        "hash_length": int_to_str(hash_length)
    })


@app.route('/v1/unblindPublicKeys', methods=['POST'])
def unblind_public_keys_hanlder():
    data = get_post_data(request)
    publicKeysCommits = list(map(lambda publicKeyCommit: str_to_int(publicKeyCommit), data.get('publicKeysCommits')))
    secretKeysOfCommits = str_to_int(data.get('secretKeysOfCommits'))
    unblindedPublicKeys = unblind_public_keys(publicKeysCommits, secretKeysOfCommits)
    return jsonify({
        "unblindedPublicKeys": list(map(lambda publicKey: int_to_str([publicKey.x, publicKey.y]), unblindedPublicKeys))
    })


@app.route('/v1/calculateMainKey', methods=['POST'])
def calculate_main_key_hanlder():
    data = get_post_data(request)
    publicKeysCommits = list(map(lambda publicKeyCommit: str_to_int(publicKeyCommit), data.get('publicKeysCommits')))
    secretKeysOfCommits = str_to_int(data.get('secretKeysOfCommits'))
    mainKey = calculate_main_key(publicKeysCommits, secretKeysOfCommits)
    return jsonify({
        "mainKey": int_to_str(mainKey)
    })


@app.route('/v1/generatePolynomialCoefficients', methods=['POST'])
def generate_polynomial_coefficients_handler():
    data = get_post_data(request)
    privateKey = str_to_int(data.get('privateKey'))
    k = str_to_int(data.get('k'))
    coefficients = generate_polynomial_coefficients(privateKey, k)
    return jsonify({
        "polynomialCoefficients": int_to_str(coefficients)
    })


# exponents
@app.route('/v1/calculatePolynomialCoefficientsExponents', methods=['POST'])
def calculate_polynomial_coefficients_exponents_handler():
    data = get_post_data(request)
    coefficients = str_to_int(data.get('polynomialCoefficients'))
    polynomialCoefficientsExponents = calculate_polynomial_coefficients_exponents(coefficients)
    return jsonify({
        "polynomialCoefficientsExponents": list(map(lambda exponent: int_to_str([exponent.x, exponent.y]),
                                                    polynomialCoefficientsExponents))
    })


# shadows for each server
@app.route('/v1/calculateEncryptedShadows', methods=['POST'])
def calculate_encrypted_shadows_handler():
    data = get_post_data(request)
    coefficients = str_to_int(data.get('polynomialCoefficients'))
    unblindedPublicKeys = list(map(lambda publicKey: str_to_int(publicKey), data.get('unblindedPublicKeys')))
    encryptedShadows = calculate_encrypted_shadows(coefficients, unblindedPublicKeys)
    return jsonify({
        "encryptedShadows": list(map(
            lambda encryptedShadow: {"privateKey": int_to_str(encryptedShadow[0]), "publicKey": int_to_str(
                [encryptedShadow[1].x, encryptedShadow[1].y])}, encryptedShadows))
    })


@app.route('/v1/decryptAndCheckShadows', methods=['POST'])
def decrypt_and_check_shadows_handler():
    data = get_post_data(request)
    privateKey = str_to_int(data.get('privateKey'))
    idx = str_to_int(data.get('idx'))
    polynomialCoefficientsExponents = list(str_to_int(data.get('polynomialCoefficientsExponents')))
    encrypted_shadows = list(map(
        lambda shadow: [str_to_int(shadow['privateKey']), str_to_int([shadow['publicKey'][0], shadow['publicKey'][1]])],
        data.get('encryptedShadows')))

    unblindedPublicKeys = list(map(lambda publicKey: str_to_int(publicKey), data.get('unblindedPublicKeys')))

    result = decrypt_and_check_shadows(privateKey, idx, encrypted_shadows, polynomialCoefficientsExponents,
                                       unblindedPublicKeys)
    return result


@app.route('/v1/restoreCommonSecret', methods=['POST'])
def restore_common_secret_handler():
    data = get_post_data(request)
    indexes = str_to_int(data.get('indexes'))
    decryptedShadowsSums = str_to_int(data.get('decryptedShadowsSums'))
    commonSecret = restore_common_secret(indexes, decryptedShadowsSums)
    return jsonify({
        "commonSecret": int_to_str(commonSecret)
    })


@app.route('/v1/verifyEncryptedBulletin', methods=['POST'])
def verify_encrypted_bulletin_handler():
    data = get_post_data(request)
    encryptedBulletin = str_to_int(data.get('encryptedBulletin')[0])
    sumRangeProof = str_to_int(data.get('encryptedBulletin')[1])
    mainKey = str_to_int(data.get('mainKey'))
    verified = verify_encrypted_bulletin(encryptedBulletin, sumRangeProof, mainKey)
    return jsonify({
        "verified": verified
    })


@app.route('/v1/verifyEncryptedBulletins', methods=['POST'])
def verify_encrypted_bulletins_handler():
    data = get_post_data(request)
    encryptedBulletins = str_to_int(data.get('encryptedBulletins'))
    mainKey = str_to_int(data.get('mainKey'))
    verified = verify_encrypted_bulletins(encryptedBulletins, mainKey)
    return jsonify({
        "verified": int_to_str(verified)
    })


@app.route('/v1/makeEncryptedBulletin', methods=['POST'])
def make_encrypted_bulletin_handler():
    data = get_post_data(request)
    bulletin = str_to_int(data.get('bulletin'))
    mainKey = str_to_int(data.get('mainKey'))
    encrypted_bulletin, proof = make_encrypted_bulletin(bulletin, mainKey)
    return jsonify([
        list(int_to_str(encrypted_bulletin)),
        int_to_str(proof)
    ])


@app.route('/v1/calculateEncryptedBulletinsSum', methods=['POST'])
@app.route('/v1/addEncryptedBulletins', methods=['POST'])
def add_encrypted_bulletins_to_sum_handler():
    data = get_post_data(request)
    encryptedBulletins = list(str_to_int(data.get('encryptedBulletins')))
    mainKey = str_to_int(data.get('mainKey'))
    prevSums = data.get('prevSums')

    sum_A, sum_B = add_encrypted_bulletins_to_sum(encryptedBulletins, mainKey, prevSums)

    return jsonify({
        "sum_A": int_to_str(sum_A),
        "sum_B": int_to_str(sum_B)
    })


@app.route('/v1/subtractEncryptedBulletins', methods=['POST'])
def subtract_encrypted_bulletins_from_sum_handler():
    data = get_post_data(request)
    encryptedBulletins = list(map(lambda v: [str_to_int(v[0]), str_to_int(v[1])],
                                  data.get('encryptedBulletins')))
    mainKey = str_to_int(data.get('mainKey'))
    prevSums = data.get('prevSums')

    sum_A, sum_B = subtract_encrypted_bulletins_from_sum(encryptedBulletins, mainKey, prevSums)

    return jsonify({
        "sum_A": int_to_str(sum_A),
        "sum_B": int_to_str(sum_B)
    })


@app.route('/v1/partiallyDecryptSumA', methods=['POST'])
def partially_decrypt_sum_a_handler():
    data = get_post_data(request)
    sum_A = str_to_int(data.get('sum_A'))
    decryptedShadowsSum = str_to_int(data.get('decryptedShadowsSum'))
    partiallyDecrypted = partially_decrypt_sum_a(sum_A, decryptedShadowsSum)
    return jsonify({
        "partiallyDecrypted": int_to_str(partiallyDecrypted)
    })


@app.route('/v1/verifyEqualityOfDl', methods=['POST'])
def verify_equality_of_dl_handler():
    data = get_post_data(request)
    decrypted = str_to_int(data.get('decrypted'))
    publicKey = str_to_hex(data.get('publicKey'))
    sum_A = str_to_int(data.get('sum_A'))

    verified = verify_equality_of_dl_wrapped(decrypted, sum_A, publicKey)

    return jsonify({
        "verified": verified
    })


@app.route('/v2/calculateVotingResult', methods=['POST'])
def calculate_voting_result_v2_handler():
    data = get_post_data(request)

    indexes = str_to_int(data.get('indexes'))

    polynomialCoefficientsExponents = str_to_int(data.get('polynomialCoefficientsExponents'))
    partialDecrypts = str_to_int(data.get('partialDecrypts'))

    mainKey = str_to_int(data.get('mainKey'))

    sum_A = str_to_int(data.get('sum_A'))
    sum_B = str_to_int(data.get('sum_B'))

    votersNum = str_to_int(data.get('votersNum'))
    optionsNum = str_to_int(data.get('optionsNum'))

    result, error = calculate_voting_result(indexes, votersNum, optionsNum,
                                            polynomialCoefficientsExponents, partialDecrypts, sum_A,
                                            sum_B, mainKey)

    if not result:
        return jsonify(error), 400
    else:
        return jsonify({
            "result": result
        })


@app.route('/v2/calculateVotingResultRTK', methods=['POST'])
def calculate_voting_result_rtk_handler():
    data = get_post_data(request)

    indexes = str_to_int(data.get('indexes'))

    polynomialCoefficientsExponents = str_to_int(data.get('polynomialCoefficientsExponents'))
    partialDecrypts = str_to_int(data.get('partialDecrypts'))

    sum_A = str_to_int(data.get('sum_A'))
    sum_B = str_to_int(data.get('sum_B'))

    votersNum = str_to_int(data.get('votersNum'))
    optionsNum = str_to_int(data.get('optionsNum'))

    commissionPubKey = str_to_hex(data.get('commissionPubKey'))
    decryptKey = str_to_int(data.get('decryptKey'))
    commissionDecrypt = str_to_int(data.get('commissionDecrypt'))

    result, error = calculate_voting_result_rtk(indexes, votersNum, optionsNum,
                                                polynomialCoefficientsExponents, partialDecrypts, sum_A,
                                                sum_B, decryptKey, commissionPubKey, commissionDecrypt)

    if not result:
        return jsonify(error), 400
    else:
        return jsonify({
            "result": result
        })


@app.route('/v1/blindSignatureVerify', methods=['POST'])
def blind_signature_verify_handler():
    data = get_post_data(request)

    rho = int(data.get('rho'), 16)
    omega = int(data.get('omega'), 16)
    delta = int(data.get('delta'), 16)
    sigma = int(data.get('sigma'), 16)
    message = data.get('message')
    Z = data.get('Z')
    Z = [int(Z[0], 16), int(Z[1], 16)]

    public_key = data.get('publicKey')
    public_key = [int(public_key[0], 16), int(public_key[1], 16)]

    return jsonify({
        "verified": blind_signature_verify(rho, omega, sigma, delta, Z, message, public_key)
    })


@app.route('/v1/blindSignatureGenerate', methods=['POST'])
def blind_signature_generate_handler():
    data = get_post_data(request)

    message = data.get('message')
    rho, omega, sigma, delta, Z, public_key = dummy_blind_signature_generate(message)

    return jsonify({
        "rho": dec_to_hexstr(rho),
        "omega": dec_to_hexstr(omega),
        "sigma": dec_to_hexstr(sigma),
        "delta": dec_to_hexstr(delta),
        "Z": dec_to_hexstr([Z.x, Z.y]),
        "message": message,
        "publicKey": dec_to_hexstr([public_key.x, public_key.y]),
    })


@app.route('/v1/pointValidate', methods=["POST"])
def point_validate_handler():
    data = get_post_data(request)
    point = str_to_hex(data.get('point'))
    if data.get('curve') == 'gost':
        valid = gost_point_validate(point)
    elif data.get('curve') == 'bitcoin':
        point = [str(point[0]), str(point[1])]
        valid = point_validate(point)
    else:
        return jsonify({
            "valid": False,
            "error": "Unknown curve"
        }), 400

    return jsonify({
        "valid": valid
    })


@app.route('/v1/addCommissionPubKey', methods=["POST"])
def add_commission_key_handler():
    data = get_post_data(request)
    decryptKey = str_to_int(data.get('decryptKey'))
    commissionPubKey = str_to_hex(data.get('commissionPubKey'))
    result, data = add_commission_key(decryptKey, commissionPubKey)
    if not result:
        return jsonify(data), 400
    else:
        return jsonify({
            "mainKey": int_to_str(data)
        })


@app.route('/v2/verifyEncryptedBulletins', methods=['POST'])
def verify_encrypted_bulletins_handler_v2():
    data = get_post_data(request)
    encryptedBulletins = str_to_int(data.get('encryptedBulletins'))
    mainKey = str_to_int(data.get('mainKey'))
    verified = verify_encrypted_bulletins_v2(encryptedBulletins, mainKey)
    return jsonify({
        "verified": verified
    })


@app.route('/v1/generateKeyPair', methods=['POST'])
def generate_key_pair_handler():
    data = get_post_data(request)
    privateKey, publicKey = generate_key_pair()
    if data.get('format') == 'hex':
        publicKey = [format(publicKey.x, 'x'), format(publicKey.y, 'x')]
    else:
        publicKey = int_to_str([publicKey.x, publicKey.y])

    return jsonify({
        "privateKey": int_to_str(privateKey),
        "publicKey": publicKey
    })


@app.route('/v1/validatePrivateKey', methods=["POST"])
def verify_private_key_handler():
    data = get_post_data(request)
    publicKey = str_to_hex(data.get('publicKey'))
    privateKey = int(data.get('privateKey'))
    valid, error = validate_private_key([str(publicKey[0]), str(publicKey[1])], privateKey)

    return jsonify({
        "valid": valid,
        "error": error
    })


@app.route('/v1/blindSignatureVerifyRSA', methods=['POST'])
def blind_signature_verify_rsa_handler():
    data = get_post_data(request)

    signature = int(data.get('signature'), 16)
    modulo = int(data.get('modulo'), 16)
    publicExp = int(data.get('publicExp'), 16)
    message = bytes(data.get('message'), encoding='utf-8')

    return jsonify({
        "verified": blind_signature_verify_rsa(signature, message, publicExp, modulo)
    })


@app.route('/v1/blindSignatureGenerateRSA', methods=['POST'])
def blind_signature_generate_rsa_handler():
    data = get_post_data(request)

    message = bytes(data.get('message'), encoding='utf-8')
    signature = dummy_blind_signature_generate_rsa(message)

    return jsonify({
        "message": data.get('message'),
        "signature": dec_to_hexstr(signature),
        "publicExp": dec_to_hexstr(public_exp),
        "modulo": dec_to_hexstr(modulo)
    })


@app.route('/v1/blindSignatureKeysRSA')
def blind_signature_keys_rsa_handler():
    return jsonify({
        "public_exp": dec_to_hexstr(public_exp),
        "modulo": dec_to_hexstr(modulo)
    })