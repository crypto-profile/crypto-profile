The `rsa8192.pkcs8.der` file is a test-only, unencrypted RSA private key.
It was generated independently for the peer certificate conformance matrix
on 2026-10-30 using the following command:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:8192 -outform DER -out rsa8192.rsa.der
openssl pkcs8 -topk8 -nocrypt -inform DER -in rsa8192.rsa.der -outform DER -out rsa8192.pkcs8.der
```

The key is public test material and must never protect real data. Its 8192-bit
modulus exercises peer admission without extending the local key-generation
inventory. Certificates are generated in memory from this fixture.
