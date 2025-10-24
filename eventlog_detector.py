# Windows Event Log Threat Detector (single-file)
# Saved-for: C:\Users\Chase McCrary\Downloads\EventLogDetector2\eventlog_detector.py
# Python 3.12+ (Windows) — requires pycryptodome
#
# Functional summary:
# - Failed logins (4625): staged alerts within 5 minutes at 6, then 10, 20, 30, 40, ...
# - Account changes (4720/4726/4728): alert on creation/deletion/membership changes (no repeat for same RecordId)
# - Process whitelist (4688): alert on non-whitelisted process creation (no repeat for same RecordId)
# - Privilege escalation (4672): alert on special privileges assigned (no repeat for same RecordId; ignores SYSTEM/SERVICE by SID or name)
# - Mass file activity (4663): optional burst detection (requires Object Access auditing)
#
# Security: Admin check, AES-256-GCM encrypted audit log in same folder

import ctypes
import datetime as dt
import json
import re
import subprocess
import sys
import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, List

# -------- USER-SPECIFIC PATH --------
BASE_DIR = Path(r"C:\Users\Chase McCrary\Downloads\EventLogDetector2")
BASE_DIR.mkdir(parents=True, exist_ok=True)

AUDIT_KEY_FILE = BASE_DIR / "audit_key.bin"
AUDIT_LOG_FILE = BASE_DIR / "detections.log.enc"
WHITELIST_FILE = BASE_DIR / "whitelist.json"

# -------- Config --------
POLL_INTERVAL_SECONDS = 2               # real-time-ish polling
FAILED_LOGIN_WINDOW_MIN = 5
MASS_FILE_WINDOW_SECONDS = 60
MASS_FILE_THRESHOLD = 100
ALERT_COOLDOWN_SECONDS = 60
PSHELL = "powershell"

# Warm-up: seed seen_record_ids with *existing* events at startup (so no historical spam)
WARMUP_LOOKBACK_MIN = 10  # match your rule ranges

# Default process whitelist (lowercase names)
DEFAULT_WHITELIST = {
    "explorer.exe","chrome.exe","msedge.exe","notepad.exe","wordpad.exe","calc.exe",
    "mspaint.exe","snippingtool.exe","osk.exe","control.exe","cmd.exe","powershell.exe",
    "conhost.exe","regedit.exe","taskmgr.exe","svchost.exe","services.exe","eventlog_detector.py"
}

# Ignore by *both* well-known service account names and SIDs
PRIV_ESC_IGNORE = {
    "NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\LOCAL SERVICE", "NT AUTHORITY\\NETWORK SERVICE",
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
    "S-1-5-18", "S-1-5-19", "S-1-5-20"
}

# -------- Crypto (PyCryptodome) --------
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
except ImportError:
    print("[!] Missing dependency: pycryptodome")
    print("    Install with:  py -m pip install pycryptodome")
    sys.exit(1)

def ensure_admin():
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        is_admin = False
    if not is_admin:
        print("[!] This tool must be run as Administrator. Re-open VS Code (or terminal) as Administrator and run again.")
        sys.exit(1)

def load_or_create_key() -> bytes:
    if AUDIT_KEY_FILE.exists():
        key = AUDIT_KEY_FILE.read_bytes()
        if len(key) == 32:
            return key
        else:
            print("[!] Existing key file invalid length; regenerating.")
    key = get_random_bytes(32)
    AUDIT_KEY_FILE.write_bytes(key)
    try:
        AUDIT_KEY_FILE.chmod(0o600)
    except Exception:
        pass
    print(f"[i] Generated AES-256 key: {AUDIT_KEY_FILE}")
    return key

class EncryptedLogger:
    def __init__(self, key: bytes, path: Path):
        self.key = key
        self.path = path

    def log(self, record: Dict[str, Any]):
        import base64
        plaintext = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
        nonce = get_random_bytes(12)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        line = base64.b64encode(nonce + tag + ciphertext).decode("ascii")
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

# -------- PowerShell helper --------
def _ps_json(script: str):
    try:
        result = subprocess.run(
            [PSHELL, "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=20
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []
        raw = result.stdout.strip()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if isinstance(data, dict):
            return [data]
        return data if isinstance(data, list) else []
    except Exception:
        return []

def _since_iso(minutes_back: int) -> str:
    t = dt.datetime.now() - dt.timedelta(minutes=minutes_back)
    return t.strftime("%Y-%m-%dT%H:%M:%S")

def fetch_security_events_by_id(event_id: int, minutes_back: int = 10) -> List[Dict[str, Any]]:
    start_iso = _since_iso(minutes_back)
    script = (
        f"$Start = [datetime]'{start_iso}'; "
        f"Get-WinEvent -FilterHashtable @{{ LogName = 'Security'; Id = {event_id}; StartTime = $Start }} "
        f"-ErrorAction SilentlyContinue | "
        f"Select-Object RecordId, Id, TimeCreated, ProviderName, Message | ConvertTo-Json -Compress"
    )
    return _ps_json(script)

# -------- Regexes --------
RE_4688_NEWPROC = re.compile(r"New Process Name:\s*([^\r\n]+)", re.IGNORECASE)
RE_4688_PARENT  = re.compile(r"Creator Process Name:\s*([^\r\n]+)", re.IGNORECASE)

# 4672 parsing: grab SID, Account Name, and Account Domain
RE_4672_SECID  = re.compile(r"Subject:\s*.*?\n\s*Security ID:\s*([^\r\n]+)", re.IGNORECASE | re.DOTALL)
RE_4672_ACCT   = re.compile(r"Account Name:\s*([^\r\n]+)", re.IGNORECASE)
RE_4672_DOMAIN = re.compile(r"Account Domain:\s*([^\r\n]+)", re.IGNORECASE)

RE_4663_OBJECT  = re.compile(r"Object Name:\s*([^\r\n]+)", re.IGNORECASE)

def parse_timestamp(s: str) -> dt.datetime:
    try:
        return dt.datetime.fromisoformat(s)
    except Exception:
        return dt.datetime.now()

def basename_lower(path: str) -> str:
    return Path(path.strip('"')).name.lower()

def extract_field(regex: re.Pattern, text: str) -> str:
    m = regex.search(text or "")
    return m.group(1).strip() if m else ""

# -------- Detector --------
class Detector:
    def __init__(self):
        # Sliding windows / state
        self.failed_logins: deque[dt.datetime] = deque()
        self.mass_file_times: deque[dt.datetime] = deque()
        self.failed_last_stage: int = 0  # 0 (none), 6, then 10, 20, 30...
        # Dedupe
        self.seen_record_ids: set[str] = set()  # event RecordId strings we've already alerted on
        # Cooldowns
        self.alert_last_fired: Dict[str, dt.datetime] = {}
        # Config/IO
        self.whitelist = set(x.lower() for x in DEFAULT_WHITELIST)
        self.load_whitelist()
        key = load_or_create_key()
        self.audit = EncryptedLogger(key, AUDIT_LOG_FILE)

    def load_whitelist(self):
        if WHITELIST_FILE.exists():
            try:
                data = json.loads(WHITELIST_FILE.read_text(encoding="utf-8"))
                extra = {x.lower() for x in data.get("process_whitelist", []) if isinstance(x, str)}
                self.whitelist |= extra
                print(f"[i] Loaded {len(extra)} extra whitelist entries from {WHITELIST_FILE}")
            except Exception as e:
                print(f"[!] Failed to read {WHITELIST_FILE}: {e}")

    def _should_cooldown(self, key: str) -> bool:
        now = dt.datetime.now()
        last = self.alert_last_fired.get(key)
        if last and (now - last).total_seconds() < ALERT_COOLDOWN_SECONDS:
            return True
        self.alert_last_fired[key] = now
        return False

    def _emit(self, event_id: int, category: str, description: str, when: dt.datetime, extras: Dict[str, Any] = None):
        stamp = when.strftime("%Y-%m-%d %H:%M:%S")
        msg = f"[ALERT] EventID:{event_id} | Timestamp:{stamp} | Category:{category} | {description}"
        print(msg)
        record = {
            "ts": stamp,
            "event_id": event_id,
            "category": category,
            "description": description,
            "extras": extras or {}
        }
        try:
            self.audit.log(record)
        except Exception as e:
            print(f"[!] Failed to write encrypted audit log: {e}")

    # ---------- Rules ----------
    def rule_failed_logins(self):
        # Build sliding window of 4625 events within FAILED_LOGIN_WINDOW_MIN
        events = fetch_security_events_by_id(4625, minutes_back=FAILED_LOGIN_WINDOW_MIN)
        now = dt.datetime.now()
        window_start = now - dt.timedelta(minutes=FAILED_LOGIN_WINDOW_MIN)

        times = []
        for e in events:
            t = parse_timestamp(e.get("TimeCreated", ""))
            if t >= window_start:
                times.append(t)
        times.sort()
        self.failed_logins = deque(times)

        count = len(self.failed_logins)
        # Stage mapping: <6 => 0; 6-9 => 6; >=10 => multiples of 10 (10,20,30,...)
        if count < 6:
            current_stage = 0
        elif count < 10:
            current_stage = 6
        else:
            current_stage = (count // 10) * 10  # 10, 20, 30, ...

        # Allow stage to drop as the window decays so a new wave can alert later
        if current_stage < self.failed_last_stage:
            self.failed_last_stage = current_stage

        # Fire only when crossing to a higher stage than we've already alerted
        if current_stage > self.failed_last_stage:
            self.failed_last_stage = current_stage
            if current_stage == 6:
                desc = f">5 failures in {FAILED_LOGIN_WINDOW_MIN} minutes (count={count})"
            else:
                desc = f">={current_stage} failures in {FAILED_LOGIN_WINDOW_MIN} minutes (count={count})"
            self._emit(
                4625,
                "Failed Logins",
                desc,
                now,
                {"window_minutes": FAILED_LOGIN_WINDOW_MIN, "count": count, "stage": current_stage}
            )

    def rule_account_changes(self):
        # Added 4726 (account deletion)
        for ev_id in (4720, 4726, 4728):
            events = fetch_security_events_by_id(ev_id, minutes_back=10)
            for e in events:
                rid = str(e.get("RecordId", ""))
                if rid and rid in self.seen_record_ids:
                    continue
                t = parse_timestamp(e.get("TimeCreated", ""))
                msg = e.get("Message", "")

                if ev_id == 4720:
                    self._emit(4720, "Account Change", "User account created", t, {"raw": msg[:400]})
                elif ev_id == 4726:
                    self._emit(4726, "Account Change", "User account deleted", t, {"raw": msg[:400]})
                else:
                    self._emit(4728, "Account Change", "User added to security group", t, {"raw": msg[:400]})


                if rid:
                    self.seen_record_ids.add(rid)

    def rule_process_whitelist(self):
        events = fetch_security_events_by_id(4688, minutes_back=5)
        for e in events:
            rid = str(e.get("RecordId", ""))
            if rid and rid in self.seen_record_ids:
                continue
            t = parse_timestamp(e.get("TimeCreated", ""))
            msg = e.get("Message", "")
            m_new = RE_4688_NEWPROC.search(msg or "")
            m_par = RE_4688_PARENT.search(msg or "")
            newp = basename_lower(m_new.group(1)) if m_new else ""
            parent = basename_lower(m_par.group(1)) if m_par else ""
            if not newp:
                if rid:
                    self.seen_record_ids.add(rid)
                continue
            if newp not in self.whitelist:
                # Optional short cooldown per exe name to avoid bursts
                if not self._should_cooldown(f"4688:{newp}"):
                    self._emit(4688, "Process (Non-Whitelisted)",
                               f"New process: {newp} (parent: {parent or 'unknown'})",
                               t, {"process": newp, "parent": parent})
                if rid:
                    self.seen_record_ids.add(rid)
            else:
                # Even if whitelisted, mark the event as seen so it doesn't repeat (no alert)
                if rid:
                    self.seen_record_ids.add(rid)

    def rule_privilege_escalation(self):
        events = fetch_security_events_by_id(4672, minutes_back=10)
        ignore_upper = {x.upper() for x in PRIV_ESC_IGNORE}

        for e in events:
            rid = str(e.get("RecordId", ""))
            if rid and rid in self.seen_record_ids:
                continue
            t = parse_timestamp(e.get("TimeCreated", ""))
            msg = e.get("Message", "") or ""

            # Extract SID + Account Name + Domain
            sid = extract_field(RE_4672_SECID, msg)
            acct = extract_field(RE_4672_ACCT, msg)
            dom = extract_field(RE_4672_DOMAIN, msg)

            # Build possible identity strings and compare against ignore set (case-insensitive)
            candidates = set()
            if sid:
                candidates.add(sid.upper())
            if acct:
                candidates.add(acct.upper())
            if dom and acct:
                candidates.add(f"{dom}\\{acct}".upper())

            if candidates & ignore_upper:
                if rid:
                    self.seen_record_ids.add(rid)
                continue

            # Optional generic cooldown per subject (prefer SID, then DOMAIN\ACCT, then ACCT)
            subject_key = (sid or (f"{dom}\\{acct}" if dom and acct else acct or "UNKNOWN")).upper()
            if not self._should_cooldown(f"4672:{subject_key}"):
                pretty_subject = sid or (f"{dom}\\{acct}" if dom and acct else acct or "Unknown")
                self._emit(4672, "Privilege Escalation",
                           f"Special privileges assigned to: {pretty_subject}",
                           t, {"sid": sid, "account": acct, "domain": dom})
            if rid:
                self.seen_record_ids.add(rid)

    def rule_mass_file_activity(self):
        events = fetch_security_events_by_id(4663, minutes_back=2)
        now = dt.datetime.now()
        cutoff = now - dt.timedelta(seconds=MASS_FILE_WINDOW_SECONDS)
        for e in events:
            t = parse_timestamp(e.get("TimeCreated", ""))
            if t >= cutoff:
                self.mass_file_times.append(t)
        while self.mass_file_times and self.mass_file_times[0] < cutoff:
            self.mass_file_times.popleft()
        if len(self.mass_file_times) > MASS_FILE_THRESHOLD:
            if not self._should_cooldown("mass_file"):
                self._emit(4663, "Mass File Activity",
                           f">{MASS_FILE_THRESHOLD} file access events in {MASS_FILE_WINDOW_SECONDS}s (count={len(self.mass_file_times)})",
                           now, {"count": len(self.mass_file_times)})

    # ---------- Warm-up ----------
    def warmup_seed_seen_record_ids(self):
        """Seed seen_record_ids with recent events so we don't alert on historical items at startup."""
        ids_and_windows = [
            (4625, max(FAILED_LOGIN_WINDOW_MIN, 5)),
            (4720, 10),
            (4726, 10),  # include account deletions
            (4728, 10),
            (4688, 5),
            (4672, 10),
            (4663, 2),
        ]
        for ev_id, win_min in ids_and_windows:
            events = fetch_security_events_by_id(ev_id, minutes_back=win_min)
            for e in events:
                rid = str(e.get("RecordId", ""))
                if rid:
                    self.seen_record_ids.add(rid)

    def run(self):
        print("[i] Windows Event Log Threat Detector — running (Ctrl+C to stop)")
        print("    - Monitoring: 4625, 4720, 4726, 4728, 4688, 4672, 4663")
        print(f"    - Audit key: {AUDIT_KEY_FILE}")
        print(f"    - Encrypted detections log: {AUDIT_LOG_FILE}")

        # Warm-up: avoid startup spam on existing recent events
        self.warmup_seed_seen_record_ids()

        while True:
            try:
                self.rule_failed_logins()
                self.rule_account_changes()
                self.rule_privilege_escalation()
                self.rule_process_whitelist()
                self.rule_mass_file_activity()
                time.sleep(POLL_INTERVAL_SECONDS)
            except KeyboardInterrupt:
                print("\n[i] Monitoring session ended. All detections saved to encrypted audit log.")
                break
            except Exception as e:
                print(f"[!] Runtime error (continuing): {e}")
                time.sleep(POLL_INTERVAL_SECONDS)

if __name__ == "__main__":
    ensure_admin()
    Detector().run()
