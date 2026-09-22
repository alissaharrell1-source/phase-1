# Intent Contract signing profile

Intent signatures use HMAC-SHA256 over the Intent Contract with the `signature` field excluded. The signed message is produced by the MADVA canonical JSON profile:

- object keys are sorted lexicographically;
- insignificant whitespace is omitted;
- strings are encoded as UTF-8 rather than ASCII-escaped;
- non-standard `NaN` and `Infinity` values are rejected;
- the resulting UTF-8 bytes are hashed with HMAC-SHA256;
- the signature is lowercase hexadecimal.

Implementations in another language must reproduce these rules before sending a signed contract. The profile test vector is:

```text
Input object: {"z":true,"a":"café","n":2}
Canonical UTF-8 JSON: {"a":"café","n":2,"z":true}
```

The canonicalizer is shared by the signer and its interoperability test at `vie_gateway/src/vie_gateway/canonical.py`. Unsupported JSON values fail closed as `invalid_intent_signature`.
