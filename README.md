Forked from [ctz/hpke-py](https://github.com/ctz/hpke-py).

**This package is only for an experimental [COSE-HPKE](https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke-02) implementation on [dajiaji/python-cwt](https://github.com/dajiaji/python-cwt). DO NOT INSTALL IT.**

# pyhpke

This is an implementation of [RFC9180](https://datatracker.ietf.org/doc/rfc9180/) in python3, using
[cryptography.io](https://cryptography.io) for the underlying cryptography.

## Features

 - Modes
   - [x] mode_base
   - [ ] mode_psk
   - [x] mode_auth
   - [ ] mode_auth_psk
 - AEADs
   - [x] AES-128-GCM
   - [x] AES-256-GCM
   - [x] ChaCha20Poly1305
   - [x] Export only
 - KEMs
   - [x] DHKEM(P-256, HKDF-SHA256)
   - [ ] DHKEM(P-384, HKDF-SHA384)
   - [x] DHKEM(P-521, HKDF-SHA512)
   - [ ] DHKEM(X25519, HKDF-SHA256)
   - [ ] DHKEM(X448, HKDF-SHA512)
 - KDFs
   - [x] HKDF-SHA256
   - [x] HKDF-SHA384
   - [x] HKDF-SHA512

## Original Author
Joseph Birr-Pixton <jpixton@gmail.com>

## License
pyhpke is licensed under the Apache License, Version 2.0. See
[LICENSE](LICENSE) for the full license text.
