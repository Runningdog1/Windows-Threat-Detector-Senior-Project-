# decrypt_audit_log_to_json.py
from pathlib import Path
import base64, json
from Crypto.Cipher import AES

# Edit these if your files are somewhere else
BASE_DIR = Path(r"C:\Users\Chase McCrary\Downloads\EventLogDetector2")
KEY_FILE = BASE_DIR / "audit_key.bin"
ENC_LOG  = BASE_DIR / "detections.log.enc"
OUT_JSON = BASE_DIR / "detections_decrypted.jsonl"   # line-delimited JSON

if not KEY_FILE.exists():
    raise SystemExit(f"[!] Missing key file: {KEY_FILE}")
if not ENC_LOG.exists():
    raise SystemExit(f"[!] Missing encrypted log: {ENC_LOG}")

key = KEY_FILE.read_bytes()
if len(key) != 32:
    raise SystemExit("[!] Key length incorrect (expected 32 bytes for AES-256).")

print(f"[i] Decrypting {ENC_LOG} -> {OUT_JSON} ...")

with ENC_LOG.open("r", encoding="utf-8") as fin, OUT_JSON.open("w", encoding="utf-8") as fout:
    for lineno, line in enumerate(fin, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            data = base64.b64decode(line)
            nonce, tag, ciphertext = data[:12], data[12:28], data[28:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            # `plaintext` is a JSON object per your logger
            obj = json.loads(plaintext.decode("utf-8"))
            # write as single-line JSON (easy to tail)
            fout.write(json.dumps(obj, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"[!] Skipping line {lineno}: {e}")

print(f"[i] Done. Decrypted lines saved to: {OUT_JSON}")
print("[i] Use a text viewer (or PowerShell Get-Content -Tail) to inspect the last entries.")