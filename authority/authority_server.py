import json, os, hashlib, base64
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timezone
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

    s = dumps(obj)
    return s.encode("utf-8")

def now_rfc3339_z():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")

def load_state(path):
    if not os.path.exists(path):
        st = {"seq": 0, "prev_hash": "0"*64}
        save_state(path, st)
        return st
    with open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"))

def save_state(path, st):
    b = json.dumps(st, ensure_ascii=False, separators=(",",":")).encode("utf-8")
    with open(path, "wb") as f:
        f.write(b)

def load_seed_hex(key_path: str) -> bytes:
    with open(key_path, "rb") as f:
        s = f.read().decode("ascii").strip()
    if len(s) != 64:
        raise ValueError("BAD_KEY_HEX_LEN")
    if any(c not in "0123456789abcdef" for c in s):
        raise ValueError("BAD_KEY_HEX_CHARS")
    return bytes.fromhex(s)

def pubkey_raw_bytes(priv: ed25519.Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes_raw()

class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        b = json.dumps(obj, ensure_ascii=False, separators=(",",":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/pubkey":
            try:
                key_path = os.environ["KEY_PATH"]
                seed = load_seed_hex(key_path)
                priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
                pub = pubkey_raw_bytes(priv)
                pub_b64 = base64.b64encode(pub).decode("ascii")
                pub_sha = sha256_hex(pub)
                self._send(200, {
                    "format": "ed25519-raw-b64",
                    "public_key_b64": pub_b64,
                    "public_key_sha256": pub_sha
                })
            except Exception as e:
                self._send(500, {"error":"PUBKEY_FAILED", "detail": str(e)})
            return
        self._send(404, {"error":"NOT_FOUND"})

    def do_POST(self):
        if self.path != "/admit":
            self._send(404, {"error":"NOT_FOUND"})
            return

        ln = int(self.headers.get("Content-Length","0"))
        raw = self.rfile.read(ln)
        try:
            req = json.loads(raw.decode("utf-8"))
        except Exception:
            self._send(400, {"error":"INVALID_JSON"})
            return
        if not isinstance(req, dict) or "intent" not in req:
            self._send(400, {"error":"MISSING_INTENT"})
            return

        intent = req["intent"]
        if not isinstance(intent, dict) or "action_type" not in intent or "payload" not in intent:
            self._send(400, {"error":"INTENT_SHAPE"})
            return

        authority_id  = os.environ.get("AUTHORITY_ID","ADMIT_AUTHORITY_V1")
        policy_version = os.environ.get("POLICY_VERSION","v1")
        image_digest  = os.environ.get("IMAGE_DIGEST","sha256:" + "0"*64)

        st_path  = os.environ.get("STATE_PATH", "state.json")
        log_path = os.environ.get("LOG_PATH", "admit.log")
        key_path = os.environ["KEY_PATH"]

        # load key
        seed = load_seed_hex(key_path)
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)

        # state
        st = load_state(st_path)
        seq = int(st["seq"]) + 1
        prev_hash = str(st["prev_hash"])

                # v1 policy (deterministic)
        atype = intent.get("action_type")
        decision = "ALLOW" if atype == "EXECUTE_TEST" else "DENY"
# decision_hash per SPEC
        decision_obj = {"intent": intent, "decision": decision, "policy_version": policy_version}
        decision_hash = sha256_hex(canonical_json_v1(decision_obj))

        # unsigned record (no record_hash, no signature)
        record_unsigned = {
            "intent": intent,
            "decision": decision,
            "policy_version": policy_version,
            "authority_id": authority_id,
            "image_digest": image_digest,
            "timestamp_utc": now_rfc3339_z(),
            "seq": seq,
            "prev_hash": prev_hash,
            "decision_hash": decision_hash,
        }

        record_hash = sha256_hex(canonical_json_v1(record_unsigned))

        # signature per SPEC: sign over HEX_TO_BYTES(record_hash)
        sig_bytes = priv.sign(bytes.fromhex(record_hash))
        signature_b64 = base64.b64encode(sig_bytes).decode("ascii")

        signed_record = dict(record_unsigned)
        signed_record["record_hash"] = record_hash
        signed_record["signature"] = signature_b64

        # ledger new_hash: SHA256(prev_bytes || record_hash_bytes)
        new_hash = sha256_hex(bytes.fromhex(prev_hash) + bytes.fromhex(record_hash))

        # append-only log
        line = f'{signed_record["timestamp_utc"]} | {seq} | {authority_id} | {decision} | {decision_hash} | {prev_hash} | {new_hash} | {record_hash} | {signature_b64}\n'
        with open(log_path, "ab") as f:
            f.write(line.encode("utf-8"))

        # persist state
        save_state(st_path, {"seq": seq, "prev_hash": new_hash})

        self._send(200, {"signed_record": signed_record, "ledger_new_hash": new_hash})

def main():
    host = os.environ.get("HOST","127.0.0.1")
    port = int(os.environ.get("PORT","8787"))
    httpd = HTTPServer((host, port), Handler)
    print(f"Authority ED25519 listening on http://{host}:{port}")
    httpd.serve_forever()

if __name__ == "__main__":
    main()