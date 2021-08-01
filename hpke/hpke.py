"""
Implementation of draft-irtf-cfrg-hpke using cryptography.io.

Supported parameters:
    mode_base only
    Single-shot API only
"""

import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding


class _HKDF:
    @classmethod
    def _HKDF_Extract(cls, salt, ikm):
        h = hmac.HMAC(salt, cls.HASH, backend=default_backend())
        h.update(ikm)
        return h.finalize()

    @classmethod
    def _HKDF_Expand32(cls, prk, info):
        h = hmac.HMAC(prk, cls.HASH, backend=default_backend())
        h.update(b'' + info + b'\x01')
        return h.finalize()

    @classmethod
    def LabeledExtract(cls, salt, label, ikm, suite_id):
        labeled_ikm = b"HPKE-v1" + suite_id + label + ikm
        return cls._HKDF_Extract(salt, labeled_ikm)

    @classmethod
    def LabeledExpand(cls, prk, label, info, N, suite_id):
        assert N <= cls.HASH.digest_size
        labeled_info = struct.pack('>H', N) + b"HPKE-v1" + suite_id + label + info
        return cls._HKDF_Expand32(prk, labeled_info)[:N]


class HKDF_SHA256(_HKDF):
    ID = 0x0001
    HASH = hashes.SHA256()


class HKDF_SHA384(_HKDF):
    ID = 0x0002
    HASH = hashes.SHA384()


class HKDF_SHA512(_HKDF):
    ID = 0x0003
    HASH = hashes.SHA512()


class _DHKEM_WEIERSTRASS:
    @classmethod
    def _ExtractAndExpand(cls, dh, kem_context, N):
        id = b'KEM' + struct.pack('>H', cls.ID)
        eae_prk = cls.KDF.LabeledExtract(b'', b'eae_prk', dh, suite_id=id)
        shared_secret = cls.KDF.LabeledExpand(eae_prk, b'shared_secret', kem_context, N, suite_id=id)
        return shared_secret

    @classmethod
    def Encap(cls, peer_pubkey):
        our_priv = ec.generate_private_key(cls.CURVE, backend=default_backend())
        shared_key = our_priv.exchange(ec.ECDH(), peer_pubkey)

        enc = our_priv.public_key().public_bytes(
            encoding=Encoding.X962,
            format=PublicFormat.UncompressedPoint)

        kem_context = enc
        kem_context += peer_pubkey.public_bytes(
            encoding=Encoding.X962,
            format=PublicFormat.UncompressedPoint)

        shared_secret = cls._ExtractAndExpand(shared_key, kem_context, cls.NSECRET)

        return shared_secret, enc

    @classmethod
    def Decap(cls, enc, our_privatekey):
        peer_pubkey = ec.EllipticCurvePublicKey.from_encoded_point(
            cls.CURVE,
            enc
        )

        shared_key = our_privatekey.exchange(ec.ECDH(), peer_pubkey)
        kem_context = enc
        kem_context += our_privatekey.public_key().public_bytes(
            encoding=Encoding.X962,
            format=PublicFormat.UncompressedPoint)

        shared_secret = cls._ExtractAndExpand(shared_key, kem_context, cls.NSECRET)
        return shared_secret

    @classmethod
    def decode_private_key(cls, scalar, public_key):
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(cls.CURVE, public_key)
        private_key = ec.EllipticCurvePrivateNumbers(
            int.from_bytes(scalar, 'big'),
            public_key.public_numbers()
        ).private_key(backend=default_backend())
        return private_key


class DHKEM_P256_HKDF_SHA256(_DHKEM_WEIERSTRASS):
    CURVE = ec.SECP256R1()
    KDF = HKDF_SHA256
    NSECRET = 32
    ID = 0x0010


class DHKEM_P521_HKDF_SHA512(_DHKEM_WEIERSTRASS):
    CURVE = ec.SECP521R1()
    KDF = HKDF_SHA512
    NSECRET = 64
    ID = 0x0012


class _AES_GCM:
    def __init__(self, key, nonce):
        self.key = key
        self.nonce = nonce
        assert len(self.key) == self.NK
        assert len(self.nonce) == self.NN

    def seal(self, aad, message):
        nonce = self.nonce
        self.nonce = None

        ctx = aead.AESGCM(self.key)
        return ctx.encrypt(nonce, message, aad)

    def open(self, aad, ct):
        nonce = self.nonce
        self.nonce = None

        ctx = aead.AESGCM(self.key)
        return ctx.decrypt(nonce, ct, aad)


class AES_128_GCM(_AES_GCM):
    NK = 16
    NN = 12
    ID = 0x0001


class AES_256_GCM(_AES_GCM):
    NK = 32
    NN = 12
    ID = 0x0002


class _Suite:
    @classmethod
    def _KeySchedule(cls, shared_secret, info):
        suite_id = b'HPKE' + struct.pack('>HHH', cls.KEM.ID, cls.KDF.ID, cls.AEAD.ID)

        psk_id_hash = cls.KDF.LabeledExtract(b'', b'psk_id_hash', b'', suite_id)
        info_hash = cls.KDF.LabeledExtract(b'', b'info_hash', info, suite_id)
        key_schedule_context = b'\x00' + psk_id_hash + info_hash

        secret = cls.KDF.LabeledExtract(shared_secret, b'secret', b'', suite_id)

        key = cls.KDF.LabeledExpand(secret, b'key', key_schedule_context, cls.AEAD.NK, suite_id)
        base_nonce = cls.KDF.LabeledExpand(secret, b'base_nonce', key_schedule_context, cls.AEAD.NN, suite_id)
        return cls.AEAD(key, base_nonce)

    @classmethod
    def _SetupBaseS(cls, peer_pubkey, info):
        shared_secret, enc = cls.KEM.Encap(peer_pubkey)
        return enc, cls._KeySchedule(shared_secret, info)

    @classmethod
    def _SetupBaseR(cls, encap, our_privatekey, info):
        shared_secret = cls.KEM.Decap(encap, our_privatekey)
        return cls._KeySchedule(shared_secret, info)

    @classmethod
    def seal(cls, peer_pubkey, info, aad, message):
        enc, ctx = cls._SetupBaseS(peer_pubkey, info)
        ct = ctx.seal(aad, message)
        return enc, ct

    @classmethod
    def open(cls, encap, our_privatekey, info, aad, ciphertext):
        ctx = cls._SetupBaseR(encap, our_privatekey, info)
        return ctx.open(aad, ciphertext)


class Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__AES_128_GCM(_Suite):
    KEM = DHKEM_P256_HKDF_SHA256
    KDF = HKDF_SHA256
    AEAD = AES_128_GCM


class Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA512__AES_128_GCM(_Suite):
    KEM = DHKEM_P256_HKDF_SHA256
    KDF = HKDF_SHA512
    AEAD = AES_128_GCM


class Suite__DHKEM_P521_HKDF_SHA512__HKDF_SHA512__AES_256_GCM(_Suite):
    KEM = DHKEM_P521_HKDF_SHA512
    KDF = HKDF_SHA512
    AEAD = AES_256_GCM

