package main

import (
"bytes"
"crypto/ed25519"
"crypto/sha256"
"encoding/base64"
"encoding/hex"
"encoding/json"
"errors"
"fmt"
"io"
"os"
"sort"
"strings"
)

type Resp struct {
SignedRecord    map[string]any `json:"signed_record"`
LedgerNewHash   string         `json:"ledger_new_hash"`
}

func decodeJSON(path string) (any, error) {
f, err := os.Open(path)
if err != nil { return nil, err }
defer f.Close()
dec := json.NewDecoder(f)
dec.UseNumber()
var v any
if err := dec.Decode(&v); err != nil { return nil, err }
return v, nil
}

func mustMap(v any) (map[string]any, error) {
m, ok := v.(map[string]any)
if !ok { return nil, errors.New("expected object") }
return m, nil
}

func jsonStringLiteral(s string) string {
b, _ := json.Marshal(s) // handles escaping
return string(b)
}

func isForbiddenFloat(num json.Number) bool {
s := num.String()
return strings.ContainsAny(s, ".eE")
}

func utf8ByteLess(a, b string) bool {
return bytes.Compare([]byte(a), []byte(b)) < 0
}

func canonicalWrite(w io.Writer, v any) error {
switch t := v.(type) {
case nil:
_, _ = w.Write([]byte("null"))
return nil
case bool:
if t { _, _ = w.Write([]byte("true")) } else { _, _ = w.Write([]byte("false")) }
return nil
case string:
_, _ = w.Write([]byte(jsonStringLiteral(t)))
return nil
case json.Number:
if isForbiddenFloat(t) { return fmt.Errorf("FORBIDDEN_FLOAT:%s", t.String()) }
_, _ = w.Write([]byte(t.String()))
return nil
case float64:
// If decoder didn't UseNumber somewhere, forbid (v1)
return fmt.Errorf("FORBIDDEN_FLOAT64")
case []any:
_, _ = w.Write([]byte("["))
for i := range t {
if i > 0 { _, _ = w.Write([]byte(",")) }
if err := canonicalWrite(w, t[i]); err != nil { return err }
}
_, _ = w.Write([]byte("]"))
return nil
case map[string]any:
keys := make([]string, 0, len(t))
for k := range t { keys = append(keys, k) }
sort.Slice(keys, func(i, j int) bool { return utf8ByteLess(keys[i], keys[j]) })

_, _ = w.Write([]byte("{"))
for i, k := range keys {
if i > 0 { _, _ = w.Write([]byte(",")) }
_, _ = w.Write([]byte(jsonStringLiteral(k)))
_, _ = w.Write([]byte(":"))
if err := canonicalWrite(w, t[k]); err != nil { return err }
}
_, _ = w.Write([]byte("}"))
return nil
default:
// int, int64 can appear if program created objects in-memory; allow via json.Marshal roundtrip
b, err := json.Marshal(t)
if err != nil { return fmt.Errorf("UNSUPPORTED_TYPE:%T", v) }
var vv any
dec := json.NewDecoder(bytes.NewReader(b))
dec.UseNumber()
if err := dec.Decode(&vv); err != nil { return err }
return canonicalWrite(w, vv)
}
}

func canonicalJSON(v any) ([]byte, error) {
var buf bytes.Buffer
if err := canonicalWrite(&buf, v); err != nil { return nil, err }
return buf.Bytes(), nil
}

func sha256Hex(b []byte) string {
h := sha256.Sum256(b)
return hex.EncodeToString(h[:])
}

func hexToBytes32(s string) ([]byte, error) {
b, err := hex.DecodeString(strings.TrimSpace(s))
if err != nil { return nil, err }
if len(b) != 32 { return nil, fmt.Errorf("HEX_LEN_NOT_32:%d", len(b)) }
return b, nil
}

func main() {
if len(os.Args) != 3 {
fmt.Println("usage: verifier_go.exe <last_executor_response.json> <public_key_b64_file>")
os.Exit(1)
}
respPath := os.Args[1]
pubFile  := os.Args[2]

pubB64Raw, err := os.ReadFile(pubFile)
if err != nil { fmt.Println("ERR_READ_PUBKEY_FILE"); os.Exit(2) }
pubB64 := strings.TrimSpace(string(pubB64Raw))
pub, err := base64.StdEncoding.DecodeString(pubB64)
if err != nil { fmt.Println("ERR_PUBKEY_B64"); os.Exit(2) }
if len(pub) != ed25519.PublicKeySize { fmt.Println("ERR_PUBKEY_LEN"); os.Exit(2) }

v, err := decodeJSON(respPath)
if err != nil { fmt.Println("ERR_READ_JSON"); os.Exit(2) }
root, err := mustMap(v)
if err != nil { fmt.Println("ERR_JSON_NOT_OBJECT"); os.Exit(2) }

// Expect fields: signed_record, ledger_new_hash
srAny, ok := root["signed_record"]
if !ok { fmt.Println("ERR_MISSING_signed_record"); os.Exit(2) }
sr, err := mustMap(srAny)
if err != nil { fmt.Println("ERR_signed_record_not_object"); os.Exit(2) }

ledgerNew, ok := root["ledger_new_hash"].(string)
if !ok { fmt.Println("ERR_MISSING_ledger_new_hash"); os.Exit(2) }

// Extract signature + provided hashes
sigB64, ok := sr["signature"].(string)
if !ok { fmt.Println("ERR_MISSING_signature"); os.Exit(2) }
sig, err := base64.StdEncoding.DecodeString(sigB64)
if err != nil { fmt.Println("ERR_SIGNATURE_B64"); os.Exit(2) }
if len(sig) != ed25519.SignatureSize { fmt.Println("ERR_SIGNATURE_LEN"); os.Exit(2) }

providedDecisionHash, _ := sr["decision_hash"].(string)
providedRecordHash, _ := sr["record_hash"].(string)
prevHash, _ := sr["prev_hash"].(string)

// decision_hash = SHA256(canonical_json({intent, decision, policy_version}))
intent := sr["intent"]
decision := sr["decision"]
pv := sr["policy_version"]
decObj := map[string]any{
"intent": intent,
"decision": decision,
"policy_version": pv,
}
decCanon, err := canonicalJSON(decObj)
if err != nil { fmt.Println("ERR_CANON_DECISION"); os.Exit(2) }
computedDecisionHash := sha256Hex(decCanon)

// canonical_record = record WITHOUT signature and record_hash
recNo := make(map[string]any, len(sr))
for k, vv := range sr {
if k == "signature" || k == "record_hash" { continue }
recNo[k] = vv
}
recCanon, err := canonicalJSON(recNo)
if err != nil { fmt.Println("ERR_CANON_RECORD"); os.Exit(2) }
computedRecordHash := sha256Hex(recCanon)

decisionOK := (strings.EqualFold(providedDecisionHash, computedDecisionHash))
recordOK := (strings.EqualFold(providedRecordHash, computedRecordHash))

// signature = Ed25519.Sign(priv, record_hash_bytes)
rhBytes, err := hexToBytes32(computedRecordHash)
if err != nil { fmt.Println("ERR_RECORD_HASH_HEX"); os.Exit(2) }
sigOK := ed25519.Verify(ed25519.PublicKey(pub), rhBytes, sig)

// ledger_new_hash = SHA256(prev_hash_bytes || record_hash_bytes)
prevBytes, err := hexToBytes32(prevHash)
if err != nil { fmt.Println("ERR_PREV_HASH_HEX"); os.Exit(2) }
ln := sha256.Sum256(append(prevBytes, rhBytes...))
computedLedgerNew := hex.EncodeToString(ln[:])
ledgerOK := strings.EqualFold(ledgerNew, computedLedgerNew)

// Output in stable order
fmt.Println("VERIFY_GO=OK")
fmt.Printf("decision_hash_ok=%d\n", b2i(decisionOK))
fmt.Printf("record_hash_ok=%d\n", b2i(recordOK))
fmt.Printf("signature_ok=%d\n", b2i(sigOK))
fmt.Printf("ledger_new_hash_ok=%d\n", b2i(ledgerOK))
fmt.Printf("decision_hash=%s\n", computedDecisionHash)
fmt.Printf("record_hash=%s\n", computedRecordHash)
fmt.Printf("ledger_new_hash=%s\n", computedLedgerNew)

if !(decisionOK && recordOK && sigOK && ledgerOK) {
os.Exit(3)
}
}

func b2i(b bool) int {
if b { return 1 }
return 0
}