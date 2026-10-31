# Sources

This page lists every document a profile, citation or capability cell depends on, with the edition the crate follows, the issuer's link, and the SHA-256 of the exact copy the maintainers read, so a reader can confirm they hold the same text: issuers revise documents at the same URL. A profile follows the edition listed here, and changes only through a reviewed change when the issuer publishes a new one ([`docs/profiles.md`](profiles.md) section 8).

¹ A web page with no fixed edition, read but not stored, so there is no hash.

Jurisdictions: [Australia](#australia) · [Canada](#canada) · [European Union](#european-union) · [Germany](#germany) · [United Kingdom](#united-kingdom) · [United States](#united-states)

Standards and evidence: [NIST and CMVP](#nist-and-cmvp) · [IETF](#ietf) · [Interoperability](#interoperability) · [CAVP certificates](#cavp-certificates) · [3.x backend provenance](#3x-backend-provenance)

## Australia

| Document | Issuer | Edition | Link | Used by | SHA-256 |
|---|---|---|---|---|---|
| Information security manual, Guidelines for cryptography | ASD / ACSC | September 2026 (first published 7 September 2026) | Edition: <https://www.cyber.gov.au/ism/2026-09><br>Guideline: <https://www.cyber.gov.au/ism/2026-09/guidelines-for-cryptography> | `preferred` (ISM-cited cells; HMAC, ISM-1772, ISM-0998, ISM-1375); `docs/profiles.md` sections 3, 4, 7 and 10 | `de582a6a541f9221dce77e36bd13418694bd6514de9ba2f54c75eed9aa550ac2` |

## Canada

| Document | Issuer | Edition | Link | Used by | SHA-256 |
|---|---|---|---|---|---|
| Roadmap for the migration to post-quantum cryptography for the Government of Canada (ITSM.40.001) | CCCS | June 2025 | <https://www.cyber.gc.ca/en/guidance/roadmap-migration-post-quantum-cryptography-government-canada-itsm40001> | `docs/profiles.md` section 7 (Canada) | —¹ |
| Cryptographic algorithms for UNCLASSIFIED, PROTECTED A, PROTECTED B information (ITSP.40.111) | CCCS | Version 5, 29 May 2026 | <https://www.cyber.gc.ca/en/guidance/cryptographic-algorithms-unclassified-protected-protected-b-information-itsp40111> | `docs/profiles.md` section 7 (Canada) | —¹ |

## European Union

| Document | Issuer | Edition | Link | Used by | SHA-256 |
|---|---|---|---|---|---|
| A Coordinated Implementation Roadmap for the Transition to Post-Quantum Cryptography | EU NIS Cooperation Group / European Commission | v1.1, 11 June 2025 | <https://ec.europa.eu/newsroom/dae/redirection/document/117507> | `docs/profiles.md` section 7 (EU) | `e76b0ea3abe5606e71d49c154a2fe1422413b5c31d0cc8dbf87a74263ead00ea` |

## Germany

| Document | Issuer | Edition | Link | Used by | SHA-256 |
|---|---|---|---|---|---|
| TR-02102-1, Cryptographic Mechanisms: Recommendations and Key Lengths | BSI | Version 2026-01 (23 January 2026) | <https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf?__blob=publicationFile> | `bsi` (HMAC: §5.2, Tables 4.1 and 5.2) | `f601cdf25c000b431573a307a3c125f3c51d301897089e7e63dde0449367a62a` |
| TR-02102-2, Use of Transport Layer Security (TLS) | BSI | Version 2026-01 (27 January 2026) | <https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-2.pdf?__blob=publicationFile> | `bsi` | `a7f55c3403d45719287415d2698bf51e629aafe841e2e9867e8afe8749d238e5` |

## United Kingdom

| Document | Issuer | Edition | Link | Used by | SHA-256 |
|---|---|---|---|---|---|
| Timelines for migration to post-quantum cryptography | NCSC (UK) | v1.0, 2025; PDF of August 2026 | <https://www.ncsc.gov.uk/guidance/pqc-migration-timelines> | `docs/profiles.md` section 7 (UK) | —¹ |
| Using Transport Layer Security to protect data | NCSC (UK) | v1.2, 15 October 2026 | <https://www.ncsc.gov.uk/guidance/using-tls-to-protect-data> | `docs/profiles.md` section 7 (UK) | —¹ |

## United States

| Document | Issuer | Edition | Link | Used by | SHA-256 |
|---|---|---|---|---|---|
| CNSSP 15, Use of Public Standards for Secure Information Sharing (CNSA 2.0 edition) | CNSS | December 2024 (signed 2025-02-28) | <https://www.cnss.gov/CNSS/issuances/Policies.cfm> | `cnsa2` (Annex B, pp. B-1 to B-2); `cnsa1` dates (para. 18, p. 8); `docs/profiles.md` section 7; HMAC (Annex B p. B-1; ¶8a and fn. 1, p. 5) | `0faf4a9336a1b310987b3b57bd7fed37aa3232ff68ded3cae556bf67aa314c1c` |
| CNSSP 15, Use of Public Standards for Secure Information Sharing (CNSA 1.0 edition) | CNSS | 20 October 2016 | <https://www.cnss.gov/CNSS/issuances/Policies.cfm> | `cnsa1` (Annex B algorithms; HMAC p. B-1; the ¶2b option, p. B-2) | `862a6c5e9e4d3ee669b8a388b83d7f9c0b661d06af6e8cbabc5222ce51839dc0` |

## NIST and CMVP

| Document | Issuer | Edition | Link | Used by | SHA-256 |
|---|---|---|---|---|---|
| FIPS 204, Module-Lattice-Based Digital Signature Standard | NIST | August 2024 | <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf> | `fips1403`, `preferred` (ML-DSA-87 cells) | `57239b9f84c03227eda3ca0991204dc7764c79af9ce2e6824eda774918d46b6b` |
| FIPS 186-5, Digital Signature Standard | NIST | 3 February 2023 | <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf> | `fips1403`; `AlgorithmTested` cells | `fbb9c7c2ba442f03c57b63b43c888311903c9d0f29f89b06efdebd9b619140c5` |
| FIPS 186-4, Digital Signature Standard (withdrawn) | NIST | July 2013 | <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf> | `fips1402` | `081dcccbcd8a1ffe4b5cca7b30dcedb739910e65b39e6182a3cdbae3e5f61689` |
| FIPS 198-1, The Keyed-Hash Message Authentication Code (HMAC) | NIST | July 2008 | <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf> | HMAC (every profile); `fips1403`, `fips1402` | `67661ba1407b391c799ff407471de18f36697af51d78a777e817c067ac30da23` |
| SP 800-186, Recommendations for Discrete Logarithm-Based Cryptography: Elliptic Curve Domain Parameters | NIST | February 2023 | <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf> | `fips1403` (Ed25519, curves) | `53c7cf3340528aaa0a7bbeaef947f2099568192367d4341a7d4abceb55f78432` |
| SP 800-131A Rev. 2, Transitioning the Use of Cryptographic Algorithms and Key Lengths | NIST | March 2019 | <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf> | `fips1403`, `fips1402`; the 112-bit HMAC key floor (Table 9) | `5c81a1095e0eee35ce0e627b8cc672c1c2239367b0de9bb53d7271c9ab9d7d27` |
| SP 800-131A Rev. 3, initial public draft | NIST | October 2024 (draft, not authoritative) | <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar3.ipd.pdf> | Context only; IR 8547 final now governs the dates | `5ffdb907e0e2375901151579422a370b655e131223a2588ea418c5df1dea6e7f` |
| SP 800-107 Rev. 1, Recommendation for Applications Using Approved Hash Algorithms | NIST | August 2012 | <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-107r1.pdf> | HMAC key strength (§5.3.2) and truncation (§5.3.3) | `2b691bd8895cbc6793e442b1e5a45398f5ca777edc2a79072469ad05405b093b` |
| SP 800-224, Keyed-Hash Message Authentication Code (HMAC): Specification of HMAC and Recommendations for Message Authentication, initial public draft | NIST | June 2024 (draft, not authoritative) | <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-224.ipd.pdf> | Context only; FIPS 198-1 governs | `be111e9c06be0ca2b1a8402ab7a7aecc1e779af71101226fba5a619bc176880c` |
| NIST IR 8547, Transition to Post-Quantum Cryptography Standards | NIST | Final, October 2026 | <https://doi.org/10.6028/NIST.IR.8547> | Certificate transition dates and dual-signature context; SHA-1 (Table 8, footnote 4) | `cf1c5b3eeb3bdd8bf1c30e16bb6f1a77b46f75eb619619e14d05f0821f4272c4` |
| NIST IR 8547, initial public draft | NIST | November 2024 (draft, context only) | <https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf> | Historical comparison; non-authoritative | `bed27fff9520b6e02e0919d43bbe0942eb567644dd933100fda0b07f6a18a2dc` |
| SP 800-52 Rev. 2, Guidelines for the Selection, Configuration, and Use of Transport Layer Security (TLS) Implementations | NIST | August 2019 | <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf> | `fips1402` (versions and suites); `peer_certificates_match_profile` | `f9a4dbb9cc6ac6778bb9f4e6be9272c2f14d113f3ad241a295684ac6bd71f257` |
| SP 800-56A Rev. 3, Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography | NIST | April 2018 | <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf> | `fips1403` (ECDH groups); decision 0004 (KAS-ECC-SSC) | `6b315e3a91012981f9a88ad62c97ea7d4b170a7746e713f34dd29538ee46f403` |
| SP 800-56C Rev. 2, Recommendation for Key-Derivation Methods in Key-Establishment Schemes | NIST | August 2020 | <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf> | `fips1403` (HKDF, hybrid) | `668a8ad181a299afe1d8becc0062b1e00e8f9db402ecb291456f6fa3aa4cf85e` |
| SP 800-135 Rev. 1, Recommendation for Existing Application-Specific Key Derivation Functions | NIST | December 2011 | <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-135r1.pdf> | `fips1403` (TLS 1.2 KDF) | `97c9094086ac0602e50ccc03087b50fb6f497ac65ab7e17708011c12593ed5ed` |
| SP 800-227, Recommendations for Key-Encapsulation Mechanisms | NIST | Final, September 2025 | <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-227.pdf> | `fips1403` (ML-KEM, hybrid) | `41e427a461c1ae0ceed2a68dc29507400983d1d495c35631306d0f4803ca4614` |
| SP 800-140C Rev. 2, CMVP Approved Security Functions | NIST | July 2023 | <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-140Cr2.pdf> | `fips1403` | `76e32694d67dfb7e8199365f120e78563d659d0ca8df17d85c6116b0ab70465d` |
| CMVP SP 800-140C list page (the operative list) | NIST CMVP | Updated 21 August 2026; fetched 2026-10-28 | <https://csrc.nist.gov/projects/cmvp/sp800-140c> | `fips1403` | `4e3c76c93f6254e78ad812711bb4e6c39a07d8d479748958d70f0f3838eea078` |
| SP 800-140D Rev. 2, CMVP Approved Sensitive Security Parameter Generation and Establishment Methods | NIST | July 2023 | <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-140Dr2.pdf> | `fips1403` | `df039c5d1c2aed36a7e54912ecc8e864e57f71d456247986547283313635c56a` |
| CMVP SP 800-140D list page (the operative list) | NIST CMVP | Updated 21 August 2026; fetched 2026-10-28 | <https://csrc.nist.gov/projects/cmvp/sp800-140d> | `fips1403` | `2c895cc5060f7054da71211a4bf205858805327607753d992602c899c087ab98` |
| CMVP SP 800-140 series supplemental information | NIST CMVP | Fetched 2026-10-28 | <https://csrc.nist.gov/projects/cmvp/sp800-140-series-info> | `fips1403` (context) | `0edebcdfe8bd18527d2f98aeaee1f7573f0eae2fa0f2db64a1cda0d2ccf088fe` |
| Implementation Guidance for FIPS 140-3 and the CMVP (IG A.x, C.A, C.F, C.K, D.Q, D.S and others) | NIST CMVP | Last update 19 August 2026 | <https://csrc.nist.gov/CSRC/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf> | `fips1403`; `preferred` (hybrid groups) | `15ebdd396a31129f9d75137ace99be56b1085feb25a95c990f8b6558440aeb02` |
| FIPS 140-2 Annex A, Approved Security Functions | NIST | 12 October 2021 | <https://csrc.nist.gov/files/pubs/fips/140-2/upd2/final/docs/fips1402annexa.pdf> | `fips1402` (HMAC, p. 3) | `e395949cc907fb93c03cdab76545c2728f98152c3eb28e36463478ac91987abf` |
| FIPS 140-2 Annex D, Approved Key Establishment Techniques | NIST | 12 October 2021 | <https://csrc.nist.gov/files/pubs/fips/140-2/upd2/final/docs/fips1402annexd.pdf> | `fips1402` | `b1eba11d8ab0474b440caf1e704973f656623d57816f5280bd756292fd2980d5` |
| Implementation Guidance for FIPS 140-2 and the CMVP (IG A.14) | NIST CMVP | Last update 30 October 2023 | <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Module-Validation-Program/documents/fips140-2/FIPS1402IG.pdf> | `fips1402` (RSA 4096) | `67ad1e159fdc16a77bed29ae136dc29d85b066ab2f53dc2195429dd3cacc8857` |
| FIPS 140-3 Transition Effort page (FIPS 140-2 sunset 22 September 2026) | NIST CMVP | Updated 13 April 2026 | <https://csrc.nist.gov/projects/fips-140-3-transition-effort> | `fips1402` status text | `d074ba57c99b2a4e551757cb26e14b24d4680842c54a8668e871fcf3afed13e5` |
| CMVP FIPS 140-2 Related References page | NIST CMVP | Fetched 2026-10-28 | <https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-2> | `fips1402` (Annex editions) | `d7c25ac67368dd22b9025b7b721765436f0a20ade458d9cba4c0a2850a2a81b2` |
| CMVP programmatic transitions page | NIST CMVP | Fetched 2026-10-28 | <https://csrc.nist.gov/projects/cryptographic-module-validation-program/programmatic-transitions> | `fips1402` status text | `d015376549c3cf86b135baec43ce33dca1c73027325414ae206732fe0d7f21d4` |
| CMVP news page | NIST CMVP | Fetched 2026-10-28 | <https://csrc.nist.gov/projects/cryptographic-module-validation-program/news> | `fips1402` status text | `c08cd53a40a8e6d6257e72aa68fffe6fcfb0fc16f600ec49383227a35465a62e` |
| CMVP certificate #4282 (FIPS 140-2, historical) | NIST CMVP | Fetched 2026-10-28 | <https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4282> | `fips1402` sunset evidence | `d9063d075521fdefc41ad6d3091d797dee493c78431afbc0ac5b5b41e4fdae85` |
| CMVP certificate #4407 (FIPS 140-2, historical) | NIST CMVP | Fetched 2026-10-28 | <https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4407> | `fips1402` sunset evidence | `26576e21da66586903f9f04b232fe85cd6b6343d689f36fdb5002734a1e56e21` |
| CMVP certificate #4566 (FIPS 140-2, historical) | NIST CMVP | Fetched 2026-10-28 | <https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4566> | `fips1402` sunset evidence | `9c8b50de09963abcfa5c42c9c72a4735828011ba68a8bb87e7aa8fd21f88b6a4` |

## IETF

| Document | Issuer | Edition | Link | Used by | SHA-256 |
|---|---|---|---|---|---|
| RFC 8603, Commercial National Security Algorithm Suite Certificate and CRL Profile | IETF | May 2019 | <https://www.rfc-editor.org/rfc/rfc8603> | `cnsa1` peer certificate rule (§4.1) | `382589199c5a940c3f3956ac655942af865746ac25c54ca79b4bba092a9baf2f` |
| RFC 9151, Commercial National Security Algorithm (CNSA) Suite Profile for TLS and DTLS 1.2 and 1.3 | IETF (Independent Submission) | April 2022 | <https://www.rfc-editor.org/rfc/rfc9151.txt> | `cnsa1`, `cnsa2` (protocol guidance; `cnsa1` HMAC, §4) | txt `3be03b8dc9d664adcf94d5fb2c2b96d274b5320b6b518b489364f030a20336be`<br>pdf `b88774c477b83814482bd9dfcf056c22dc07b28f45345598c138a0b05aafad24` |
| RFC 10024, Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS | IETF | August 2026 | <https://www.rfc-editor.org/rfc/rfc10024> | `unrestricted`, `preferred`, `fips1403` (SecP384r1MLKEM1024: §4.1-4.3 share layout and secret, §7.3 codepoint); `bsi` (hybrid groups residual); hybrid group cells | txt `5efcfacef53549ec4ff57450dfec28085b34cf3f34d829c541c0ddbe19230dfe`<br>pdf `56e0f58c3f68f12c51010f4964a94f3b0deab2e519f07125e228bb5fbcd266d0`<br>html `844c9bcb3bb43926ef408d3747fe614f9bf3a720d9e4c81a5e07d97cc5fbfd73` |
| RFC 9001, Using TLS to Secure QUIC | IETF | May 2021 | <https://www.rfc-editor.org/rfc/rfc9001.txt> | The provider's QUIC algorithms (§5 packet and header protection, §6.6 limits; Appendix A test vectors) | `3bbaecdf5afd278052a2c48348ce118c4ff8d0cf6b9915549858171b3f98a591` |
| RFC 8446, The Transport Layer Security (TLS) Protocol Version 1.3 | IETF | August 2018 | <https://www.rfc-editor.org/rfc/rfc8446> | All profiles (section 4.2.3 signature schemes, section 7.1 key schedule) | `47871bc8820a2c3b6ea89f061055577058862cf543686b82d10131239702b3bd` |
| RFC 8422, Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS) Versions 1.2 and Earlier | IETF | August 2018 | <https://www.rfc-editor.org/rfc/rfc8422> | `cnsa1`, `fips1402` (TLS 1.2 key exchange) | `cac45754399e5115342cf1d773a51ac5a77ad221e9336e43ceadd8f294712350` |
| RFC 7919, Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS) | IETF | August 2016 | <https://www.rfc-editor.org/rfc/rfc7919> | `cnsa1`, `fips1402` (TLS 1.2 key exchange) | `e7ffd3d8109670aa48d218964ceccf82cc6d2fd36132403c89589434bf8a4d72` |
| RFC 7627, Transport Layer Security (TLS) Session Hash and Extended Master Secret Extension | IETF | September 2015 | <https://www.rfc-editor.org/rfc/rfc7627> | `fips1403` (IG D.Q) | `3e908b1a511f5894b64b2c7867c5e0e8db43896add4d99a340fe67a07ee11a59` |
| RFC 9206, Commercial National Security Algorithm (CNSA) Suite Cryptography for Internet Protocol Security (IPsec) | IETF | 2022 | <https://www.rfc-editor.org/rfc/rfc9206> | `cnsa2` (cited by CNSSP 15 p. 5 footnote 1; HMAC, §4 and §8) | `605d1c5c9945439c6e171f3e21fca9195d7bad5d8c8280e2af627b6bfb6a2dbe` |

## Interoperability

| Document | Issuer | Edition | Link | Used by | SHA-256 |
|---|---|---|---|---|---|
| OpenSSL 3.5.9, source release | OpenSSL Project | 29 September 2026 | <https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz> (release page <https://github.com/openssl/openssl/releases/tag/openssl-3.5.9>) | SecP384r1MLKEM1024 interop test (`ci/openssl-interop.sh`) | `603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a` |

## CAVP certificates

| Document | Issuer | Edition | Link | Used by | SHA-256 |
|---|---|---|---|---|---|
| CAVP certificate A7855 (SHA_AVX2 processor variant) | NIST CAVP | FIPS 4.0.0 module line, dynamic build; page captured 2026-10-31 | <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?product=20657&displayMode=Aggregated> | ML-DSA-87, Ed25519 (key and scheme), ML-KEM-1024, SHA-256, SHA-384 and SHA-512, and HMAC-SHA256, HMAC-SHA384 and HMAC-SHA512 cells | `f8ceaede9dac95fc116222aad792914ebb964c6903c9c69a78144a2e539d4bcb` |
| CAVP certificate A7856 (SHA_AVX processor variant) | NIST CAVP | FIPS 4.0.0 module line, dynamic build | <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?product=20658&displayMode=Aggregated> | ECDSA SigVer P-256, P-384 and P-521; RSA-PSS and PKCS#1 v1.5 SigVer cells | `f77c1fc681222a62cfd92ca4c9eb009d5624cf952424401ad1087db434c96ede` |
| CAVP certificate A7864 (GENERIC_C processor variant) | NIST CAVP | FIPS 4.0.0 module line, dynamic build | <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?product=20666&displayMode=Aggregated> | Key exchange secp384r1 and secp256r1 (KAS-ECC-SSC and ECDSA KeyGen) | `5f17cbff14d8abe72ffd0dda51f983dd10ae2d3ba86ee92e3bba133a7c3dc2ed` |
| CAVP certificate A7873 (NARROW_MULTIPLIER processor variant) | NIST CAVP | FIPS 4.0.0 module line, dynamic build | <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?product=20675&displayMode=Aggregated> | RSA 2048, 3072 and 4096 keys with SHA2-384 | `eb8fdc4693ba6adcee24ca0e4c5c114547cf15b229bedc7b5207ae6e09a07f1d` |
| CAVP certificate A7839 (AESNI processor variant) | NIST CAVP | FIPS 4.0.0 module line, dynamic build | <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?product=20641&displayMode=Aggregated> | Lower end of the range A7839-A7876 named in the capability table and decision 0004 | `ed886dee89bb04c0c9d32e9d6bf912a34732736b74892ba84d5bb506ea35bee9` |
| CAVP certificate A7876 (SHA3_ASM_N1 processor variant) | NIST CAVP | FIPS 4.0.0 module line, dynamic build | <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?product=20678&displayMode=Aggregated> | Upper end of the range A7839-A7876 named in the capability table and decision 0004 | `e77f9061128ee3cc69fe898455834b160537abba03b45099cc3e984b9c553952` |

## 3.x backend provenance

The 3.x backend pins aws-lc-rs 1.17.4 and rcgen 0.14.9; its lockfile selects aws-lc-fips-sys 0.13.17, which bundles AWS-LC 3.6.0, a later revision of the AWS-LC FIPS 3.x line. The certificates below cover that line; their certified release is 3.1.0.

| Document | Issuer | Edition | Link | Used by | SHA-256 |
|---|---|---|---|---|---|
| AWS-LC FIPS 3.1.0 security policy, static (CMVP #5314) | NIST CMVP | Document version 1.2, 2026-05-20 | <https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5314.pdf> | 3.x static capability cells (Table 5; HMAC p. 9, key range 112-524288); `certificate(MODULE)` | `9e0c9f57f5d319c0c86492e6196aa5625a1b97867843e0e0d9bb423937e6f34e` |
| AWS-LC FIPS 3.1.0 security policy, dynamic (CMVP #5298) | NIST CMVP | Document version 1.3, 2026-05-14 | <https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5298.pdf> | 3.x dynamic capability cells (Table 5; HMAC p. 9, key range 112-524288); `certificate(MODULE)` | `4e285b543fe4f333ef2ea85f6942753bb9d08403bf3a4933818462f43caf96a0` |

| Crate | Version | Link |
|---|---|---|
| aws-lc-rs | 1.17.4 | <https://crates.io/crates/aws-lc-rs/1.17.4> |
| aws-lc-fips-sys | 0.13.17 | <https://crates.io/crates/aws-lc-fips-sys/0.13.17> |
| rcgen | 0.14.9 | <https://crates.io/crates/rcgen/0.14.9> |
