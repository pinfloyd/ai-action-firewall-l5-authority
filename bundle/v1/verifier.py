import json, sys, hashlib, base64
from cryptography.hazmat.primitives.asymmetric import ed25519

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def canonical_json_v1(obj):
    # Canonical JSON v1:
    # - UTF-8
    # - no whitespace
    # - keys sorted by UTF-8 byte order
    # - integers only; floats forbidden
    def validate_numbers(x):
        if isinstance(x, bool) or x is None:
            return
        if isinstance(x, int):
            return
        if isinstance(x, float):
            raise ValueError("FLOAT_FORBIDDEN")
        if isinstance(x, str):
            return
        if isinstance(x, list):
            for i in x: validate_numbers(i)
            return
        if isinstance(x, dict):
            for k, v in x.items():
                if not isinstance(k, str):
                    raise ValueError("NON_STRING_KEY")
                validate_numbers(v)
            return
        raise ValueError("UNSUPPORTED_TYPE:" + type(x).__name__)

    validate_numbers(obj)

    def sort_keys(d):
        return sorted(d.keys(), key=lambda k: k.encode("utf-8"))

    def dumps(x):
        if isinstance(x, dict):
            items = []
            for k in sort_keys(x):
                items.append(f"{json.dumps(k, ensure_ascii=False, separators=(',',':'))}:{dumps(x[k])}")
            return "{" + ",".join(items) + "}"
        if isinstance(x, list):
            return "[" + ",".join(dumps(i) for i in x) + "]"
        if isinstance(x, str):
            return json.dumps(x, ensure_ascii=False, separators=(',',':'))
        if isinstance(x, int):
            return str(x)
        if x is True:
            return "true"
        if x is False:
            return "false"
        if x is None:
            return "null"
        raise ValueError("UNSUPPORTED_TYPE:" + type(x).__name__)

    return dumps(obj).encode("utf-8")

def fail(msg):
    print("VERIFY=FAIL")
    print("ERROR=" + msg)
    sys.exit(2)

def ok(msg):
    print(msg)

def main():
    if len(sys.argv) != 3:
        print("usage: verifier.py <response.json> <pubkey_b64>")
        sys.exit(1)

    resp_path = sys.argv[1]
    pub_b64   = sys.argv[2]

    with open(resp_path, "rb") as f:
        resp = json.loads(f.read().decode("utf-8"))

    if "signed_record" not in resp or "ledger_new_hash" not in resp:
        fail("BAD_RESPONSE_SHAPE")

    rec = resp["signed_record"]
    ledger_new = resp["ledger_new_hash"]

    required = ["intent","decision","policy_version","authority_id","image_digest","timestamp_utc","seq","prev_hash","decision_hash","record_hash","signature"]
    for k in required:
        if k not in rec:
            fail("MISSING_FIELD:" + k)

    intent = rec["intent"]
    decision = rec["decision"]
    policy_version = rec["policy_version"]

    # 1) decision_hash recompute
    decision_obj = {"intent": intent, "decision": decision, "policy_version": policy_version}
    decision_hash_calc = sha256_hex(canonical_json_v1(decision_obj))
    if decision_hash_calc != rec["decision_hash"]:
        fail("DECISION_HASH_MISMATCH")

    # 2) record_hash recompute (exclude signature and record_hash)
    unsigned = dict(rec)
    unsigned.pop("signature", None)
    unsigned.pop("record_hash", None)
    record_hash_calc = sha256_hex(canonical_json_v1(unsigned))
    if record_hash_calc != rec["record_hash"]:
        fail("RECORD_HASH_MISMATCH")

    # 3) signature verify: sign over HEX_TO_BYTES(record_hash)
    pub_raw = base64.b64decode(pub_b64.encode("ascii"))
    if len(pub_raw) != 32:
        fail("BAD_PUBKEY_LEN")
    pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_raw)

    sig = base64.b64decode(rec["signature"].encode("ascii"))
    try:
        pub.verify(sig, bytes.fromhex(rec["record_hash"]))
    except Exception:
        fail("SIGNATURE_INVALID")

    # 4) ledger new_hash check: SHA256(prev_bytes || record_hash_bytes)
    new_calc = sha256_hex(bytes.fromhex(rec["prev_hash"]) + bytes.fromhex(rec["record_hash"]))
    if new_calc != ledger_new:
        fail("LEDGER_NEW_HASH_MISMATCH")

    print("VERIFY=OK")
    ok("decision_hash_ok=1")
    ok("record_hash_ok=1")
    ok("signature_ok=1")
    ok("ledger_new_hash_ok=1")
    ok("seq=" + str(rec["seq"]))
    ok("prev_hash=" + rec["prev_hash"])
    ok("record_hash=" + rec["record_hash"])
    ok("new_hash=" + ledger_new)

if __name__ == "__main__":
    main()