# SPEC_SIGNED_ADMISSION_RECORD_V1

Version: v1
Status: FROZEN

---

## 1. Signed Admission Record v1 (signed object)

Fields:

- intent (object)
  - action_type (string)
  - payload (object)
- decision ("ALLOW" | "DENY")
- policy_version (string)
- authority_id (string)
- image_digest (sha256:<64hex>)
- timestamp_utc (RFC3339, Z)
- seq (integer)
- prev_hash (64 hex lowercase)
- decision_hash (64 hex lowercase)
- record_hash (64 hex lowercase)
- signature (base64)

NOTE: new_hash is NOT part of the signed record.

---

## 2. Canonical JSON v1

- UTF-8
- No whitespace
- Object keys sorted by UTF-8 byte order
- Arrays preserve order
- Strings standard JSON escaping
- Numbers: integers only
- Floats forbidden
- Fractional values must be strings

Function:
CANONICAL_JSON_V1(x) -> UTF-8 bytes

---

## 3. Hashing

decision_hash =
SHA256_HEX(
  CANONICAL_JSON_V1({
    "intent": intent,
    "decision": decision,
    "policy_version": policy_version
  })
)

record_hash =
SHA256_HEX(
  CANONICAL_JSON_V1(record_without_signature_and_record_hash)
)

signature =
BASE64(
  ED25519_SIGN(
    priv,
    HEX_TO_BYTES(record_hash)
  )
)

---

## 4. Ledger Chain

new_hash =
SHA256_HEX(
  HEX_TO_BYTES(prev_hash) || HEX_TO_BYTES(record_hash)
)

---

## 5. Fail-Closed Enforcement

Executor MUST verify:

- decision_hash matches recomputation
- record_hash matches recomputation
- signature valid
- authority_id pinned
- image_digest pinned
- seq strictly increasing
- prev_hash matches expected_prev_hash

On any failure -> DENY.

---

END OF SPEC