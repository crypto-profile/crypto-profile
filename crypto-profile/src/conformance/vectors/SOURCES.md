# Conformance vector sources

Every file in this directory is byte-for-byte as retrieved, except `ed25519_rfc8032.json` and `hkdf_rfc5869.json`, which transcribe RFC text, and `kda_onestep_acvp.json`, which transcribes NIST ACVP samples. Retrieved 2026-10-28; the three `hmac_*` files 2026-10-31, the three `hkdf_sha*` files 2026-11-01, and the three `ecdh_*` files and `x25519_test.json` 2026-11-02, from the same commit.

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
| `rsa_signature_3072_sha384_test.json` | `73499ee649d8fb703b3f0f455fa36f7682fde677c590a736958ebce05ab27dae` |
| `rsa_signature_4096_sha384_test.json` | `bc26f16b9fc9a90628864d3d1111ef48a4bd00b9d4870bfab88ff326e309e073` |
| `mldsa_87_verify_test.json` | `54adffe10f6dad7941ffd97f77ad4e5c85cb3a54d44cf5ce1c95cb1757b9ba14` |
| `hmac_sha256_test.json` | `2d201cfa61d1bf95e6f5d07d96634b4a348b31e8eaa277ad7c8d09677b7a743f` |
| `hmac_sha384_test.json` | `28b9776e979dd755d852ca471043ea6cedce8b15f7a28abdf6ea9efd982b43c0` |
| `hmac_sha512_test.json` | `b6c90477bdb4a6fc8ee3d1f7b2c0b69a8dfffab34718abaa6cabd71cc2ba1207` |
| `hkdf_sha256_test.json` | `bb2b462a38b251cb52a2aede706d6d4b62b26864f4e80c95497507ddb07c5f1e` |
| `hkdf_sha384_test.json` | `69ff6ea3657bb9c1b8cdffbbb4e7832353d08fd15c0d9997b03f7a6b180e3678` |
| `hkdf_sha512_test.json` | `bb9a21f4e86041caf5d7792b030349f8ff289087f195b2fbc0fc0afc39deca6f` |
| `ecdh_secp256r1_ecpoint_test.json` | `648f16d077caf2400d02331ca51f44744c72c799830c8d0595d0b18b6dd9f886` |
| `ecdh_secp384r1_ecpoint_test.json` | `ffa7835fe1de359dff762c8f1272b98acebd5578e2f855d969051ff956c6dca3` |
| `ecdh_secp521r1_ecpoint_test.json` | `87aba8739c96de2bde8c75b60ffea09d0493192c4d9543d1d969e5e998931f35` |
| `x25519_test.json` | `35c3f5231cf25cc640b524d403461deee9e49441d5d915a3a25b2c8ff5adbe7d` |

The ECDH files are the raw-point (`ecpoint`) forms. The SubjectPublicKeyInfo forms (`ecdh_secp*_test.json`) are not used: `ecdh` refuses a public key in that form before the module sees it.

## RFC 8032

`ed25519_rfc8032.json` holds TEST 1, TEST 2 and TEST 3 of RFC 8032 §7.1 (public key, message, signature), copied from `https://www.rfc-editor.org/rfc/rfc8032.txt` (SHA-256 of the text as retrieved: `ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3`). Licence: IETF Trust; the test vectors are code components under the Revised BSD licence (BCP 78).

| File | SHA-256 |
|---|---|
| `ed25519_rfc8032.json` | `203979671b0827a9a60dd792edd7f86b32f91ee7b9a46d191e6737f54de489c9` |

## RFC 5869

`hkdf_rfc5869.json` holds Test Cases 1, 2 and 3 of RFC 5869 Appendix A (SHA-256: IKM, salt, info, L and OKM; the PRK is not used, because the crate exposes no extract), copied from `https://www.rfc-editor.org/rfc/rfc5869.txt` (SHA-256 of the text as retrieved: `7a40eb3835b35fc947eb12a2ed614db079d43b26e50dbc537c31fba16397089c`). Test Cases 4 to 7 use SHA-1, which no profile offers. Licence: IETF Trust; the test vectors are code components under the Revised BSD licence (BCP 78).

| File | SHA-256 |
|---|---|
| `hkdf_rfc5869.json` | `1121ba5b84fefa7956a1ebdcbcb91b14af108b5482d328a0daed46011fa4a511` |

## NIST ACVP

`kda_onestep_acvp.json` holds the passing one-step KDF cases with SHA2-256, SHA2-384 and SHA2-512 from two sample vector sets of `https://github.com/usnistgov/ACVP-Server`, commit `975de31eb83d87039ec88934fdc47d8c312b892d`, directory `gen-val/json-files/`, retrieved 2026-11-02. Licence: public domain (US Government work).

| Source file | SHA-256 | Cases taken |
|---|---|---|
| `KDA-OneStep-Sp800-56Cr2/internalProjection.json` | `0b4a11017ba5e181c3c3dcc2e4f5a5c0080beb4ab8ef59c06179327ebd50e6ce` | the SHA2-512 groups (the sample has no SHA2-256 or SHA2-384 one-step group); `fixedInfo` = `t` ‖ `uPartyInfo` ‖ `vPartyInfo` ‖ `l` as 32 bits, each party's `partyId` then its `ephemeralData` if present |
| `KAS-IFC-Sp800-56Br2/internalProjection.json` | `38d1cad1a883e4e5571751eba12655962f67622d4b234eb8d4cb070756cc41ce` | the one-step KDF of the `KAS1-basic` initiator groups with SHA2-256 and SHA2-384; `fixedInfo` = `algorithmId` ‖ `l` as 32 bits ‖ `iutId` ‖ `iutC` ‖ `serverId` ‖ `serverNonce` |

Each case keeps its `source`, `tgId`, `tcId`, `hash`, `z`, assembled `fixedInfo`, `l` and `dkm`; cases whose `testPassed` is false are left out. Every case's `dkm` was recomputed from `z` and `fixedInfo` with SP 800-56C Rev. 2 §4.1 option 1 before it was kept: 23 SHA2-256, 10 SHA2-384 and 45 SHA2-512 cases.

| File | SHA-256 |
|---|---|
| `kda_onestep_acvp.json` | `e5f4a3efe026cd2e010f107ac81017b33686d26c60fb648f4742e7d62c75b77c` |

## RFC 7518

The constants in `conformance/mod.rs` `vectors::rfc7518` transcribe RFC 7518 Appendix C (ECDH-ES on P-256 with the Concat KDF; the JWK coordinates and private keys decoded from base64url), from `https://www.rfc-editor.org/rfc/rfc7518.txt` (SHA-256 of the text as retrieved: `9a9ae524b09ea700ad3f189bac115df95ba69af84b26ffdbe3cdfb8d2152b1fc`). Licence: IETF Trust; the test vectors are code components under the Revised BSD licence (BCP 78).

## RFC 9180

The constants in `conformance/mod.rs` `vectors::rfc9180` transcribe the base-mode `kem_id`, `skEm`, `enc`, `skRm`, `pkRm` and `shared_secret` of RFC 9180 Appendix A.1.1, A.3.1 and A.6.1, every DHKEM the appendix carries (it has no DHKEM(P-384, HKDF-SHA384) case), from `https://www.rfc-editor.org/rfc/rfc9180.txt` (SHA-256 `f45a8b7c30231b26d668b1e8168074e5ab514b174d656b67e859895117f1f8f6`). Licence: IETF Trust; the test vectors are code components under the Revised BSD licence (BCP 78).

## NIST CAVP

The SHA byte-oriented test vectors, `https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip` (linked from `https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing`; zip SHA-256 `929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8`), extracted from `shabytetestvectors/`. Licence: public domain (US Government work). The files keep their CRLF line endings.

| File | SHA-256 |
|---|---|
| `SHA256ShortMsg.rsp` | `75e1cb83994638481808e225b9eb0c1ebd0c232d952ac42b61abce6363be283c` |
| `SHA384ShortMsg.rsp` | `7ea7bcf00fadc20949fae63703e40681ddf288fea808471cb3cbc95f3ec16811` |
| `SHA512ShortMsg.rsp` | `e53a36c03609e5a3e3cc4b6e117a499db7864c23ec825c6cec99503a45f40764` |

## Sealed box

The known answers in `conformance/mod.rs` (`vectors::sealbox`) are Maknae's sealed-box v1 vectors, produced by an independent implementation. `vectors::sealbox::release_0_9_0` is a blob sealed, with its key, by crypto-profile 0.9.0 (`crypto-profile-awslc4`, tag `v0.9.0`, commit `6a1615a4708a2d6e79d0a1882e094251002a0f28`) on 2026-11-02, so that every later release is checked to open what 0.9.0 sealed.

## Reference policies

The two reference policies the conformance macro builds are named for their shape. Their origins:

- `reference_pq_first`: Maknae's TLS configuration: TLS 1.3 only, key-exchange groups MLKEM1024, X25519MLKEM768, SECP256R1MLKEM768, secp384r1, secp256r1.
- `reference_cnsa1`: a CNSA 1.0 TLS filter used by another consumer: TLS 1.3 AES-256-GCM-SHA384, plus TLS 1.2 ECDHE with ECDSA or RSA and AES-256-GCM-SHA384, over secp384r1.
