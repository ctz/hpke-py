import os

import pytest
import cryptography.exceptions

import pyhpke as hpke


aead_suites = [
    hpke.Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__AES_128_GCM,
    hpke.Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA512__AES_128_GCM,
    hpke.Suite__DHKEM_P521_HKDF_SHA512__HKDF_SHA512__AES_256_GCM,
    hpke.Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__ChaCha20Poly1305,
]


export_suites = [
    hpke.Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__ExportOnly,
    hpke.Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA512__ExportOnly,
]


@pytest.mark.parametrize("suite", aead_suites)
def test_base_oneshot_pairwise(suite):
    receiver = suite.KEM.generate_private_key()
    encap, ct = suite.seal(
        receiver.public_key(), info=b"info", aad=b"aad", message=b"message"
    )
    message = suite.open(encap, receiver, info=b"info", aad=b"aad", ciphertext=ct)
    assert message == b"message"

    with pytest.raises(cryptography.exceptions.InvalidTag):
        suite.open(encap, receiver, info=b"info", aad=b"aad", ciphertext=ct + b"eh")

    print(suite, "OK")


@pytest.mark.parametrize("suite", aead_suites)
def test_auth_oneshot_pairwise(suite):
    receiver = suite.KEM.generate_private_key()
    sender = suite.KEM.generate_private_key()

    encap, ct = suite.seal_auth(
        receiver.public_key(), sender, info=b"info", aad=b"aad", message=b"message"
    )
    message = suite.open_auth(
        encap,
        receiver,
        sender.public_key(),
        info=b"info",
        aad=b"aad",
        ciphertext=ct,
    )
    assert message == b"message"

    with pytest.raises(cryptography.exceptions.InvalidTag):
        suite.open_auth(
            encap,
            receiver,
            sender.public_key(),
            info=b"info",
            aad=b"aad",
            ciphertext=ct + b"eh",
        )

    with pytest.raises(cryptography.exceptions.InvalidTag):
        suite.open_auth(
            encap,
            receiver,
            receiver.public_key(),  # wrong
            info=b"info",
            aad=b"aad",
            ciphertext=ct,
        )

    print(suite, "OK")


@pytest.mark.parametrize("suite", aead_suites)
def test_base_pairwise(suite):
    receiver = suite.KEM.generate_private_key()
    encap, send_ctx = suite.setup_send(receiver.public_key(), info=b"info")

    recv_ctx = suite.setup_recv(encap, receiver, info=b"info")

    assert send_ctx.export(b"context", 512) == recv_ctx.export(b"context", 512)

    for x in range(128):
        aad = os.urandom(32)
        msg = os.urandom(128)
        ct = send_ctx.aead.seal(aad=aad, message=msg)
        assert msg == recv_ctx.aead.open(aad=aad, ciphertext=ct)

    print(suite, "OK")


@pytest.mark.parametrize("suite", aead_suites)
def test_auth_pairwise(suite):
    sender = suite.KEM.generate_private_key()
    receiver = suite.KEM.generate_private_key()

    encap, send_ctx = suite.setup_auth_send(receiver.public_key(), b"info", sender)

    recv_ctx = suite.setup_auth_recv(encap, receiver, b"info", sender.public_key())

    assert send_ctx.export(b"context", 512) == recv_ctx.export(b"context", 512)

    for x in range(128):
        aad = os.urandom(32)
        msg = os.urandom(128)
        ct = send_ctx.aead.seal(aad=aad, message=msg)
        assert msg == recv_ctx.aead.open(aad=aad, ciphertext=ct)

    print(suite, "OK")


@pytest.mark.parametrize("suite", export_suites)
def test_base_pairwise_export(suite):
    receiver = suite.KEM.generate_private_key()
    encap, send_ctx = suite.setup_send(receiver.public_key(), info=b"info")

    recv_ctx = suite.setup_recv(encap, receiver, info=b"info")

    assert send_ctx.export(b"context", 512) == recv_ctx.export(b"context", 512)

    with pytest.raises(NotImplementedError):
        send_ctx.aead.seal(aad=b"", message=b"")

    with pytest.raises(NotImplementedError):
        recv_ctx.aead.open(aad=b"", ciphertext=b"")


@pytest.mark.parametrize("suite", export_suites)
def test_auth_pairwise_export(suite):
    sender = suite.KEM.generate_private_key()
    receiver = suite.KEM.generate_private_key()

    encap, send_ctx = suite.setup_auth_send(receiver.public_key(), b"info", sender)

    recv_ctx = suite.setup_auth_recv(encap, receiver, b"info", sender.public_key())

    assert send_ctx.export(b"context", 512) == recv_ctx.export(b"context", 512)

    with pytest.raises(NotImplementedError):
        send_ctx.aead.seal(aad=b"", message=b"")

    with pytest.raises(NotImplementedError):
        recv_ctx.aead.open(aad=b"", ciphertext=b"")
