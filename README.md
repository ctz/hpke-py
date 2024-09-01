# hpke.py

![CI status](https://github.com/ctz/hpke-py/actions/workflows/ci.yaml/badge.svg)
![PyPI version](https://shields.io/pypi/v/hpke)

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
   - [x] DHKEM(P-384, HKDF-SHA384)
   - [x] DHKEM(P-521, HKDF-SHA512)
   - [ ] DHKEM(X25519, HKDF-SHA256)
   - [ ] DHKEM(X448, HKDF-SHA512)
 - KDFs
   - [x] HKDF-SHA256
   - [x] HKDF-SHA384
   - [x] HKDF-SHA512

## Author
Joseph Birr-Pixton <jpixton@gmail.com>

## License
hpke.py is licensed under the Apache License, Version 2.0. See
[LICENSE](LICENSE) for the full license text.
