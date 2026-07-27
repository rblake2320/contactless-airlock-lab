# Canonical binding encoding

Canonical bindings are UTF-8 JSON with protocol-defined property order and no
insignificant whitespace. The versioned fixtures in
`vectors/canonical-bindings-v1.json` are the normative interoperability
evidence for the current profile.

## Opaque identifiers are never Unicode-normalized

Identifiers and merchant strings are encoded exactly as supplied after
validation as Unicode scalar values. The canonicalizer does **not** apply NFC,
NFD, case folding, trimming, locale processing, or other semantic rewriting.
Consequently, visually similar NFC and NFD identifiers produce different bytes,
different hashes, and different signatures. This is intentional: silently
normalizing an issuer-owned opaque identifier could cause one signed identity
to be interpreted as another.

Systems that own an identifier may normalize it before constructing the
binding, but every signer and verifier must then use that exact resulting value.
The vector pair `opaque-id-nfc` and `opaque-id-nfd` proves the distinction.

## JSON numeric wire forms

The TypeScript implementation receives JSON numbers through `JSON.parse`, so
`1e3`, `1000.0`, and `1000` become the same finite integer-valued JavaScript
Number and canonicalize as `1000`. The independent Python canonicalization
verifier mirrors that behavior while still rejecting booleans, non-finite
values, fractions, zero, negatives, and values above JavaScript's maximum safe
integer.

## Scope of the Python verifier

`python_reference_verifier.py` independently verifies validation decisions,
canonical bytes, and SHA-256 fixtures using only the Python standard library.
It is not an approval-signature verifier and makes no claim about ECDSA
interoperability.
