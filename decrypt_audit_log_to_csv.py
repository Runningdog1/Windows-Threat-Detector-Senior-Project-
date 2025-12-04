# decrypt_audit_log_to_csv.py
from pathlib import Path
import base64, json, csv
from Crypto.Cipher import AES
from datetime import datetime

BASE_DIR = Path(r"C:\Users\Chase McCrary\Downloads\EventLogDetector2")
KEY_FILE = BASE_DIR / "audit_key.bin"
ENC_LOG  = BASE_DIR / "detections.log.enc"
OUT_CSV  = BASE_DIR / "detections_decrypted.csv"

if not KEY_FILE.exists():
    raise SystemExit(f"[!] Missing key file: {KEY_FILE}")
if not ENC_LOG.exists():
    raise SystemExit(f"[!] Missing encrypted log: {ENC_LOG}")

key = KEY_FILE.read_bytes()
if len(key) != 32:
    raise SystemExit("[!] Key length incorrect (expected 32 bytes).")

print(f"[i] Decrypting and sorting CSV...")

rows = []

with ENC_LOG.open("r", encoding="utf-8") as fin:
    for lineno, line in enumerate(fin, start=1):
        line = line.strip()
        if not line:
            continue

        try:
            blob = base64.b64decode(line)
            nonce, tag, ciphertext = blob[:12], blob[12:28], blob[28:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)

            obj = json.loads(plaintext.decode("utf-8"))

            rows.append({
                "Timestamp": obj.get("ts"),
                "Event ID": obj.get("event_id"),   # underscore removed & capitalized
                "Category": obj.get("category").capitalize() if obj.get("category") else "",
                "Description": obj.get("description"),
            })

        except Exception as e:
            print(f"[!] Skipping line {lineno}: {e}")

# SORT NEWEST FIRST
def parse_ts(ts_str):
    try:
        return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except:
        return datetime.min

rows.sort(key=lambda r: parse_ts(r["Timestamp"]), reverse=True)

# WRITE CLEAN CSV
fieldnames = ["Timestamp", "Event ID", "Category", "Description"]

with OUT_CSV.open("w", newline="", encoding="utf-8") as fcsv:
    writer = csv.DictWriter(fcsv, fieldnames=fieldnames)
    writer.writeheader()  # CSV doesn't support styling (bold) but Excel will bold automatically if needed
    for row in rows:
        writer.writerow(row)

print(f"[i] Sorted CSV written to: {OUT_CSV}")
