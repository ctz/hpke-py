import json
import pytest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

import hpke

known_answers = tuple(json.load(open("tests/known_answers.json")))


def is_for_suite(suite, mode, kat):
    return (
        mode.value == kat["mode"]
        and suite.KEM.ID == kat["kem_id"]
        and suite.KDF.ID == kat["kdf_id"]
        and suite.AEAD.ID == kat["aead_id"]
    )


@pytest.mark.parametrize(
    "suite",
    (
        hpke.Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__AES_128_GCM,
        hpke.Suite__DHKEM_P521_HKDF_SHA512__HKDF_SHA512__AES_256_GCM,
        hpke.Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__ChaCha20Poly1305,
    ),
)
def test_aead(suite):
    for kat in known_answers:
        if not is_for_suite(suite, hpke.Mode.BASE, kat):
            continue

        for enc in kat["encryptions"]:
            c = suite.AEAD(bytes.fromhex(kat["key"]), bytes.fromhex(enc["nonce"]))
            assert c.seal(
                bytes.fromhex(enc["aad"]), bytes.fromhex(enc["pt"])
            ) == bytes.fromhex(enc["ct"])

        print("tested", suite.AEAD, "OK")


@pytest.mark.parametrize(
    "suite",
    (
        hpke.Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__AES_128_GCM,
        hpke.Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA512__AES_128_GCM,
        hpke.Suite__DHKEM_P521_HKDF_SHA512__HKDF_SHA512__AES_256_GCM,
        hpke.Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__ChaCha20Poly1305,
        hpke.Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__ExportOnly,
        hpke.Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA512__ExportOnly,
    ),
)
def test_receive_base_known_answer(suite):
    count = 0

    for kat in known_answers:
        mode = hpke.Mode(kat["mode"])
        if not is_for_suite(suite, hpke.Mode.BASE, kat):
            continue

        print("testing", suite)
        count += 1
        private_key = suite.KEM.decode_private_key(
            bytes.fromhex(kat["skRm"]), bytes.fromhex(kat["pkRm"])
        )

        context = suite.setup_recv(
            encap=bytes.fromhex(kat["pkEm"]),
            our_privatekey=private_key,
            info=bytes.fromhex(kat["info"]),
        )

        for i, enc in enumerate(kat["encryptions"]):
            if i == 0:
                # test one-shot API
                message = suite.open(
                    bytes.fromhex(kat["pkEm"]),
                    private_key,
                    info=bytes.fromhex(kat["info"]),
                    aad=bytes.fromhex(enc["aad"]),
                    ciphertext=bytes.fromhex(enc["ct"]),
                )
                assert message == bytes.fromhex(enc["pt"])
                print("  ", "single-shot OK")

            message = context.aead.open(
                aad=bytes.fromhex(enc["aad"]), ciphertext=bytes.fromhex(enc["ct"])
            )
            assert message == bytes.fromhex(enc["pt"])
            print("  ", "ciphertext", i, "OK")

        for i, ex in enumerate(kat["exports"]):
            got = context.export(
                exporter_context=bytes.fromhex(ex["exporter_context"]), length=ex["L"]
            )
            assert got == bytes.fromhex(ex["exported_value"])
            print("  ", "exporter value", i, "OK")

        print("tested", suite, "OK")

    assert count > 0, "this suite is untested"


@pytest.mark.parametrize(
    "suite",
    (
        hpke.Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__AES_128_GCM,
        hpke.Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA512__AES_128_GCM,
        hpke.Suite__DHKEM_P521_HKDF_SHA512__HKDF_SHA512__AES_256_GCM,
        hpke.Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__ChaCha20Poly1305,
        hpke.Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__ExportOnly,
        hpke.Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA512__ExportOnly,
    ),
)
def test_receive_auth_known_answer(suite):
    count = 0

    for kat in known_answers:
        if not is_for_suite(suite, hpke.Mode.AUTH, kat):
            continue

        print("testing", suite)
        count += 1
        private_key = suite.KEM.decode_private_key(
            bytes.fromhex(kat["skRm"]), bytes.fromhex(kat["pkRm"])
        )
        sender_pubkey = suite.KEM.decode_public_key(bytes.fromhex(kat["pkSm"]))

        context = suite.setup_auth_recv(
            encap=bytes.fromhex(kat["pkEm"]),
            our_privatekey=private_key,
            info=bytes.fromhex(kat["info"]),
            peer_pubkey=sender_pubkey,
        )

        for i, enc in enumerate(kat["encryptions"]):
            if i == 0:
                # test one-shot API
                message = suite.open_auth(
                    bytes.fromhex(kat["pkEm"]),
                    private_key,
                    sender_pubkey,
                    info=bytes.fromhex(kat["info"]),
                    aad=bytes.fromhex(enc["aad"]),
                    ciphertext=bytes.fromhex(enc["ct"]),
                )
                assert message == bytes.fromhex(enc["pt"])
                print("  ", "single-shot OK")

            message = context.aead.open(
                aad=bytes.fromhex(enc["aad"]), ciphertext=bytes.fromhex(enc["ct"])
            )
            assert message == bytes.fromhex(enc["pt"])
            print("  ", "ciphertext", i, "OK")

        for i, ex in enumerate(kat["exports"]):
            got = context.export(
                exporter_context=bytes.fromhex(ex["exporter_context"]), length=ex["L"]
            )
            assert got == bytes.fromhex(ex["exported_value"])
            print("  ", "exporter value", i, "OK")

        print("tested", suite, "OK")
    assert count > 0, "this suite is untested"
