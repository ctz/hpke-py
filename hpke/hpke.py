"""
Implementation of draft-irtf-cfrg-hpke using cryptography.io.

Author: Joseph Birr-Pixton
License: Apache License 2.0
https://github.com/ctz/hpke-py
"""

import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding


def xor_bytes(b1, b2):
    return bytes([a1 ^ a2 for (a1, a2) in zip(b1, b2)])


class _HKDF:
    ID = None
    HASH = None

    @classmethod
    def _hkdf_extract(cls, salt, ikm):
        hctx = hmac.HMAC(salt, cls.HASH, backend=default_backend())
        hctx.update(ikm)
        return hctx.finalize()

    @classmethod
    def _hkdf_expand(cls, prk, info, length):
        t_n_minus_1= b''
        n = 1
        data = b''

        assert length <= 255 * cls.HASH.digest_size

        while len(data) < length:
            hctx = hmac.HMAC(prk, cls.HASH, backend=default_backend())
            hctx.update(t_n_minus_1 + info + n.to_bytes(1, byteorder='big'))
            t_n_minus_1 = hctx.finalize()
            data += t_n_minus_1
            n += 1

        return data[:length]



    @classmethod
    def labeled_extract(cls, salt, label, ikm, suite_id):
        labeled_ikm = b"HPKE-v1" + suite_id + label + ikm
        return cls._hkdf_extract(salt, labeled_ikm)

    @classmethod
    def labeled_expand(cls, prk, label, info, length, suite_id):
        if length == 0:
            return b''

        labeled_info = struct.pack('>H', length) + b"HPKE-v1" + suite_id + label + info
        return cls._hkdf_expand(prk, labeled_info, length)


class HKDF_SHA256(_HKDF):
    ID = 0x0001
    HASH = hashes.SHA256()


class HKDF_SHA384(_HKDF):
    ID = 0x0002
    HASH = hashes.SHA384()


class HKDF_SHA512(_HKDF):
    ID = 0x0003
    HASH = hashes.SHA512()


class _DHKEMWeierstrass:
    ID = None
    KDF = None
    CURVE = None
    NSECRET = None

    @classmethod
    def _extract_and_expand(cls, dh, kem_context, N):
        suite_id = b'KEM' + struct.pack('>H', cls.ID)
        eae_prk = cls.KDF.labeled_extract(b'', b'eae_prk', dh, suite_id=suite_id)
        shared_secret = cls.KDF.labeled_expand(eae_prk, b'shared_secret',
                kem_context, N, suite_id=suite_id)
        return shared_secret

    @classmethod
    def encap(cls, peer_pubkey):
        our_priv = ec.generate_private_key(cls.CURVE, backend=default_backend())
        shared_key = our_priv.exchange(ec.ECDH(), peer_pubkey)

        enc = our_priv.public_key().public_bytes(
            encoding=Encoding.X962,
            format=PublicFormat.UncompressedPoint)

        kem_context = enc
        kem_context += peer_pubkey.public_bytes(
            encoding=Encoding.X962,
            format=PublicFormat.UncompressedPoint)

        shared_secret = cls._extract_and_expand(shared_key, kem_context, cls.NSECRET)

        return shared_secret, enc

    @classmethod
    def decap(cls, enc, our_privatekey):
        peer_pubkey = ec.EllipticCurvePublicKey.from_encoded_point(
            cls.CURVE,
            enc
        )

        shared_key = our_privatekey.exchange(ec.ECDH(), peer_pubkey)
        kem_context = enc
        kem_context += our_privatekey.public_key().public_bytes(
            encoding=Encoding.X962,
            format=PublicFormat.UncompressedPoint)

        shared_secret = cls._extract_and_expand(shared_key, kem_context, cls.NSECRET)
        return shared_secret

    @classmethod
    def decode_private_key(cls, scalar, public_key):
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(cls.CURVE, public_key)
        private_key = ec.EllipticCurvePrivateNumbers(
            int.from_bytes(scalar, 'big'),
            public_key.public_numbers()
        ).private_key(backend=default_backend())
        return private_key

    @classmethod
    def generate_private_key(cls):
        return ec.generate_private_key(cls.CURVE, backend=default_backend())


class DHKEM_P256_HKDF_SHA256(_DHKEMWeierstrass):
    CURVE = ec.SECP256R1()
    KDF = HKDF_SHA256
    NSECRET = 32
    ID = 0x0010


class DHKEM_P521_HKDF_SHA512(_DHKEMWeierstrass):
    CURVE = ec.SECP521R1()
    KDF = HKDF_SHA512
    NSECRET = 64
    ID = 0x0012


class _AES_GCM:
    NK = None
    NN = None

    def __init__(self, key, nonce):
        self.key = key
        self.nonce = nonce
        self.seq = 0
        assert len(self.key) == self.NK
        assert len(self.nonce) == self.NN

    def seal(self, aad, message):
        nonce = xor_bytes(self.nonce, self.seq.to_bytes(self.NN, byteorder='big'))
        self.seq += 1

        ctx = aead.AESGCM(self.key)
        return ctx.encrypt(nonce, message, aad)

    def open(self, aad, ciphertext):
        nonce = xor_bytes(self.nonce, self.seq.to_bytes(self.NN, byteorder='big'))
        self.seq += 1

        ctx = aead.AESGCM(self.key)
        return ctx.decrypt(nonce, ciphertext, aad)


class AES_128_GCM(_AES_GCM):
    NK = 16
    NN = 12
    ID = 0x0001


class AES_256_GCM(_AES_GCM):
    NK = 32
    NN = 12
    ID = 0x0002


class ExportOnlyAEAD:
    """
    The export-only AEAD.

    This has the same interface as (eg) AES_128_GCM but refuses
    to seal() or open().
    """
    NK = 0
    NN = 0
    ID = 0xffff

    def __init__(self, _key, _nonce):
        pass

    def seal(self, aad, message):
        raise NotImplementedError()

    def open(self, aad, ciphertext):
        raise NotImplementedError()


class Context:
    def __init__(self, aead, export):
        self.aead = aead
        self.export = export


class _Suite:
    KEM = None
    KDF = None
    AEAD = None

    @classmethod
    def _key_schedule(cls, shared_secret, info):
        suite_id = b'HPKE' + struct.pack('>HHH', cls.KEM.ID, cls.KDF.ID, cls.AEAD.ID)

        psk_id_hash = cls.KDF.labeled_extract(b'', b'psk_id_hash', b'', suite_id)
        info_hash = cls.KDF.labeled_extract(b'', b'info_hash', info, suite_id)
        key_schedule_context = b'\x00' + psk_id_hash + info_hash

        secret = cls.KDF.labeled_extract(shared_secret, b'secret', b'', suite_id)

        key = cls.KDF.labeled_expand(secret, b'key', key_schedule_context, cls.AEAD.NK, suite_id)
        base_nonce = cls.KDF.labeled_expand(secret, b'base_nonce', key_schedule_context,
                cls.AEAD.NN, suite_id)

        exporter_secret = cls.KDF.labeled_expand(secret, b'exp', key_schedule_context,
                cls.KDF.HASH.digest_size, suite_id)

        def exporter(exporter_context, length):
            return cls.KDF.labeled_expand(exporter_secret, b'sec',
                    exporter_context, length, suite_id)

        return Context(aead=cls.AEAD(key, base_nonce),
                export=exporter)

    @classmethod
    def _setup_base_send(cls, peer_pubkey, info):
        shared_secret, encap = cls.KEM.encap(peer_pubkey)
        return encap, cls._key_schedule(shared_secret, info)

    @classmethod
    def _setup_base_recv(cls, encap, our_privatekey, info):
        shared_secret = cls.KEM.decap(encap, our_privatekey)
        return cls._key_schedule(shared_secret, info)

    @classmethod
    def setup_send(cls, peer_pubkey, info):
        return cls._setup_base_send(peer_pubkey, info)

    @classmethod
    def setup_recv(cls, encap, our_privatekey, info):
        return cls._setup_base_recv(encap, our_privatekey, info)

    @classmethod
    def seal(cls, peer_pubkey, info, aad, message):
        """
        Single-shot encryption API.

        `peer_pubkey` is the peer's public key, of type
          `ec.EllipticCurvePublicKey'.
        `info` is any identity information for the receiver.
        `aad` is any additional authenticated data for the AEAD.
        `message` is the message plaintext.

        `info`, `aad`, and `message` arguments are of type `bytes`.

        Returns `(encap, ciphertext)`, both of type `bytes`.
        """
        encap, ctx = cls._setup_base_send(peer_pubkey, info)
        ciphertext = ctx.aead.seal(aad, message)
        return encap, ciphertext

    @classmethod
    def open(cls, encap, our_privatekey, info, aad, ciphertext):
        """
        Single-shot decryption API.

        `encap` is the encapsulated key from the sender.
        `our_privatekey` is the receiver's private key, of type
          `ec.EllipticCurvePrivateKey`.
        `info` is any identity information for the receiver.
        `aad` is any additional authenticated data for the AEAD.
        `ciphertext` is the message ciphertext.

        `encap`, `info`, `aad`, and `ciphertext` arguments are of
        type `bytes`.

        Returns `plaintext` of type `bytes`.

        Raises `cryptography.exceptions.InvalidTag` if any of the
        arguments are corrupt.
        """
        ctx = cls._setup_base_recv(encap, our_privatekey, info)
        return ctx.aead.open(aad, ciphertext)


class Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__AES_128_GCM(_Suite):
    """
    This is DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
    """
    KEM = DHKEM_P256_HKDF_SHA256
    KDF = HKDF_SHA256
    AEAD = AES_128_GCM


class Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA512__AES_128_GCM(_Suite):
    """
    This is DHKEM(P-256, HKDF-SHA256), HKDF-SHA512, AES-128-GCM
    """
    KEM = DHKEM_P256_HKDF_SHA256
    KDF = HKDF_SHA512
    AEAD = AES_128_GCM


class Suite__DHKEM_P521_HKDF_SHA512__HKDF_SHA512__AES_256_GCM(_Suite):
    """
    This is DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM
    """
    KEM = DHKEM_P521_HKDF_SHA512
    KDF = HKDF_SHA512
    AEAD = AES_256_GCM

class Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__ExportOnly(_Suite):
    """
    This is DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ExportOnly
    """
    KEM = DHKEM_P256_HKDF_SHA256
    KDF = HKDF_SHA256
    AEAD = ExportOnlyAEAD


class Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA512__ExportOnly(_Suite):
    """
    This is DHKEM(P-256, HKDF-SHA256), HKDF-SHA512, ExportOnly
    """
    KEM = DHKEM_P256_HKDF_SHA256
    KDF = HKDF_SHA512
    AEAD = ExportOnlyAEAD
