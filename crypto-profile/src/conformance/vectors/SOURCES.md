# Conformance vector sources

Every file in this directory is byte-for-byte as retrieved, except `ed25519_rfc8032.json`, which transcribes RFC text. Retrieved 2026-10-28.

## Wycheproof

Repository `https://github.com/C2SP/wycheproof`, commit `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9`, directory `testvectors_v1/`. Licence: Apache-2.0.

Each file was fetched from `https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/<file>`.

| File | SHA-256 |
|---|---|
| `ecdsa_secp256r1_sha256_test.json` | `182db4f3e230f6f9fa9f800d2a614dede30284b8e8438bbfe1171905402e9332` |
| `ecdsa_secp384r1_sha384_test.json` | `8a5b3ae1760975143414811f13588c24d951d9d8c904195087ba327591dfe9cc` |
| `ecdsa_secp521r1_sha512_test.json` | `0fa3bb09a2319242253028b53d555fb8ec2081d891271321205cdaeabb3eef3e` |
| `ed25519_test.json` | `ea80ffebac085e21cb9d3e903e7fa2b448d96702da5b31f061d0b83b430b74b3` |
| `rsa_signature_2048_sha384_test.json` | `c571c105d261c0ff588a2888a529f152563fb3b77894b7620d4e4f8f934f2c1d` |
| `aes_gcm_test.json` | `985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7` |

## RFC 8032

`ed25519_rfc8032.json` holds TEST 1, TEST 2 and TEST 3 of RFC 8032 §7.1 (public key, message, signature), copied from `https://www.rfc-editor.org/rfc/rfc8032.txt` (SHA-256 of the text as retrieved: `ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3`). Licence: IETF Trust; the test vectors are code components under the Revised BSD licence (BCP 78).

| File | SHA-256 |
|---|---|
| `ed25519_rfc8032.json` | `203979671b0827a9a60dd792edd7f86b32f91ee7b9a46d191e6737f54de489c9` |

## NIST CAVP

The SHA byte-oriented test vectors, `https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip` (linked from `https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing`; zip SHA-256 `929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8`), extracted from `shabytetestvectors/`. Licence: public domain (US Government work). The files keep their CRLF line endings.

| File | SHA-256 |
|---|---|
| `SHA256ShortMsg.rsp` | `75e1cb83994638481808e225b9eb0c1ebd0c232d952ac42b61abce6363be283c` |
| `SHA384ShortMsg.rsp` | `7ea7bcf00fadc20949fae63703e40681ddf288fea808471cb3cbc95f3ec16811` |
| `SHA512ShortMsg.rsp` | `e53a36c03609e5a3e3cc4b6e117a499db7864c23ec825c6cec99503a45f40764` |

## Sealed box

The known answers in `conformance/mod.rs` (`vectors::sealbox`) are Maknae's sealed-box v1 vectors, produced by an independent implementation.

## Reference policies

The two reference policies the conformance macro builds are named for their shape. Their origins:

- `reference_pq_first`: Maknae's TLS configuration: TLS 1.3 only, key-exchange groups MLKEM1024, X25519MLKEM768, SECP256R1MLKEM768, secp384r1, secp256r1.
- `reference_cnsa1`: Microkosmos's CNSA 1.0 filter: TLS 1.3 AES-256-GCM-SHA384, plus TLS 1.2 ECDHE with ECDSA or RSA and AES-256-GCM-SHA384, over secp384r1.
