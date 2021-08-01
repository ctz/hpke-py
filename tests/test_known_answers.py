import json
import pytest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

import hpke


@pytest.fixture
def known_answers():
    return json.load(open('tests/known_answers.json'))


def find_suite(kem_id, kdf_id, aead_id):
    all = [
        hpke.Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__AES_128_GCM,
        hpke.Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA512__AES_128_GCM,
        hpke.Suite__DHKEM_P521_HKDF_SHA512__HKDF_SHA512__AES_256_GCM,
    ]
    for suite in all:
        if suite.KEM.ID == kem_id and suite.KDF.ID == kdf_id and suite.AEAD.ID == aead_id:
            return suite
    return None


def test_aeads(known_answers):
    for kat in known_answers:
        suite = find_suite(kat['kem_id'], kat['kdf_id'], kat['aead_id'])
        if suite is None:
            continue

        for enc in kat['encryptions']:
            c = suite.AEAD(bytes.fromhex(kat['key']),
                           bytes.fromhex(enc['nonce']))
            assert(c.seal(bytes.fromhex(enc['aad']),
                          bytes.fromhex(enc['pt']))
                   == bytes.fromhex(enc['ct']))

        print('tested', suite.AEAD, 'OK')

def test_receive_known_answer(known_answers):
    for kat in known_answers:
        suite = find_suite(kat['kem_id'], kat['kdf_id'], kat['aead_id'])
        if kat['mode'] != 0 or suite is None:
            continue

        print('testing', suite)
        private_key = suite.KEM.decode_private_key(
            bytes.fromhex(kat['skRm']),
            bytes.fromhex(kat['pkRm']))

        # TODO: support multiple encryptions
        enc = kat['encryptions'][0]
        message = suite.open(
            bytes.fromhex(kat['pkEm']),
            private_key,
            info=bytes.fromhex(kat['info']),
            aad=bytes.fromhex(enc['aad']),
            ciphertext=bytes.fromhex(enc['ct']))
        assert message == bytes.fromhex(enc['pt'])

        print('tested', suite, 'OK')
