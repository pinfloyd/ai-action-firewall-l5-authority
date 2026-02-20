import json, os, sys, subprocess, urllib.request

def fail(msg, code=2):
    print("GATE=DENY")
    print("ERROR=" + msg)
    sys.exit(code)

def http_json(url, method="GET", body_obj=None):
    data = None
    headers = {}
    if body_obj is not None:
        data = json.dumps(body_obj, ensure_ascii=False, separators=(",",":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=10) as r:
        b = r.read()
        return json.loads(b.decode("utf-8"))

def load_json(path, default_obj):
    if not os.path.exists(path):
        return default_obj
    with open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"))

def save_json(path, obj):
    b = json.dumps(obj, ensure_ascii=False, separators=(",",":")).encode("utf-8")
    with open(path, "wb") as f:
        f.write(b)

def main():
    if len(sys.argv) != 5:
        print("usage: executor_gate.py <config.json> <state.json> <verifier.py> <action_file>")
        sys.exit(1)

    cfg_path, state_path, verifier_path, action_file = sys.argv[1:5]

    cfg = load_json(cfg_path, None)
    if cfg is None:
        fail("MISSING_CONFIG")

    st = load_json(state_path, {"last_seq": 0, "expected_prev_hash": None})

    authority_url = cfg["authority_url"].rstrip("/")
    intent = {"action_type": "EXECUTE_TEST", "payload": {"n": 1}}

    # 1) call Authority
    resp = http_json(authority_url + "/admit", method="POST", body_obj={"intent": intent})

    # Save last response for audit
    out_path = os.path.join(os.path.dirname(state_path), "last_executor_response.json")
    save_json(out_path, resp)

    if "signed_record" not in resp or "ledger_new_hash" not in resp:
        fail("BAD_RESPONSE_SHAPE")

    rec = resp["signed_record"]
    ledger_new = resp["ledger_new_hash"]

    # 2) pinned checks (fail-closed)
    if rec.get("authority_id") != cfg["authority_id"]:
        fail("AUTHORITY_ID_MISMATCH")

    if rec.get("image_digest") != cfg["image_digest"]:
        fail("IMAGE_DIGEST_MISMATCH")

    # 3) chain checks (fail-closed)
    last_seq = int(st.get("last_seq", 0))
    if int(rec.get("seq", 0)) <= last_seq:
        fail("SEQ_NOT_INCREASING")

    expected_prev = st.get("expected_prev_hash", None)
    if expected_prev is not None:
        if rec.get("prev_hash") != expected_prev:
            fail("PREV_HASH_MISMATCH")

    # 4) verifier (independent)
    pub_b64 = cfg["public_key_b64"]
    p = subprocess.run(
        [sys.executable, verifier_path, out_path, pub_b64],
        capture_output=True, text=True
    )
    print(p.stdout, end="")
    if p.returncode != 0 or "VERIFY=OK" not in p.stdout:
        fail("VERIFIER_FAILED")

    # 5) update executor state (track ledger even if DENY)
    st2 = {"last_seq": int(rec["seq"]), "expected_prev_hash": ledger_new}
    save_json(state_path, st2)

    # 6) enforce decision (fail-closed)
    if rec.get("decision") != "ALLOW":
        print("DECISION=" + str(rec.get("decision")))
        print("ACTION=SKIPPED")
        sys.exit(3)

    # 7) perform action ONLY on ALLOW
    with open(action_file, "wb") as f:
        f.write(b"ACTION_PERFORMED\n")
    print("ACTION=PERFORMED")
    sys.exit(0)

if __name__ == "__main__":
    main()