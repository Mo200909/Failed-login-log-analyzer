"""
Failed-Login Log Analyzer

What this does: reads SSH login attempts, groups failed ones by IP,
and flags IPs that failed fast (a brute-force burst) vs. just failed
a lot over a long time.

Two ways to feed it data:
  1. Default — no setup. It generates its own fake log and analyzes that.
  2. Real dataset — download the Kaggle "SSH Brute Force" data:
     https://www.kaggle.com/datasets/lako65/ssh-brute-force-ipuserpassword
     Then run: python analyzer.py kaggle brute_force_data.json
  3. Combined — merges the Kaggle data + a generated practice log into
     ONE .log file on disk, then analyzes that:
     python analyzer.py combined brute_force_data.json
"""

import json
import os
import random
import re
from collections import defaultdict
from datetime import datetime, timedelta

BRUTE_FORCE_THRESHOLD = 5       # this many fails...
BRUTE_FORCE_WINDOW_SECONDS = 60 # ...within this many seconds = flagged
KAGGLE_DATASET_URL = "https://www.kaggle.com/datasets/lako65/ssh-brute-force-ipuserpassword"


# ---------- Step 1: Make a fake log to practice on ----------
def _format_line(t, ip, user, status):
    # Builds one line that looks like a real sshd log entry.
    ts = t.strftime("%b %d %H:%M:%S")
    pid = random.randint(1000, 9999)
    return f"{ts} server sshd[{pid}]: {status} password for {user} from {ip} port {random.randint(2000, 60000)} ssh2"


def generate_sample_log(path="sample_auth.log", num_lines=40):
    # Two batches: normal-looking logins, then one obvious attack burst.
    users = ["root", "admin", "mo", "deploy", "backup"]
    normal_ips = ["10.0.0.5", "10.0.0.12", "192.168.1.20"]
    attacker_ip = "203.0.113.77"

    lines = []
    start_time = datetime(2026, 9, 21, 2, 0, 0)

    # Batch 1: everyday logins, spread 3 minutes apart, mostly successful.
    for i in range(15):
        t = start_time + timedelta(minutes=i * 3)
        ip = random.choice(normal_ips)
        user = random.choice(users)
        status = random.choice(["Accepted", "Accepted", "Failed"])
        lines.append(_format_line(t, ip, user, status))

    # Batch 2: one IP hammering logins 4 seconds apart — this is the burst
    # the analyzer below is supposed to catch.
    burst_start = start_time + timedelta(minutes=50)
    for i in range(12):
        t = burst_start + timedelta(seconds=i * 4)
        user = random.choice(["root", "admin"])
        lines.append(_format_line(t, attacker_ip, user, "Failed"))

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return path


# ---------- Step 2: Read a real log file ----------
# This pattern matches one line of a standard sshd log, e.g.:
#   Sep 21 02:50:00 server sshd[8910]: Failed password for admin from 1.2.3.4 port 39081 ssh2
LOG_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<status>Accepted|Failed)\s+password\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
)

def parse_log(path):
    # Reads the file line by line, keeps only lines that match the pattern
    # above, and turns each into a simple dict: {time, status, user, ip}.
    events = []
    with open(path, "r") as f:
        for line in f:
            match = LOG_PATTERN.match(line.strip())
            if not match:
                continue  # skip anything that doesn't look like a login line
            d = match.groupdict()
            timestamp = datetime.strptime(
                f"2026 {d['month']} {d['day']} {d['time']}", "%Y %b %d %H:%M:%S"
            )
            events.append({"time": timestamp, "status": d["status"], "user": d["user"], "ip": d["ip"]})
    return events


# ---------- Step 2b: Read the Kaggle dataset instead ----------
def parse_kaggle_json(path):
    """
    Same job as parse_log() above, but for the Kaggle dataset format
    instead of a real sshd log. Converts it to the same {time, status,
    user, ip} shape so the rest of the script doesn't care which source
    it came from.

    Two things to know about this data before trusting the numbers:
      1. It logs one entry per SESSION (a list of passwords tried), not
         one timestamp per attempt. Every password in a session gets
         stamped with that session's single timestamp — sub-second
         timing inside a session isn't in the data.
      2. It's attack traffic ONLY. There are no successful logins, so
         the "accepted" count in the summary will always show 0 here.
    """
    with open(path, "r", encoding="utf-8-sig") as f:
        sessions = json.load(f)

    events = []
    skipped = 0
    for s in sessions:
        try:
            t = datetime.strptime(s["timestamp"].strip(), "%a %b %d %H:%M:%S %Y")
        except (ValueError, KeyError):
            skipped += 1  # bad/missing timestamp — drop this session
            continue
        for _ in s.get("passwords", []):
            events.append({"time": t, "status": "Failed", "user": s["username"], "ip": s["foreign_ip"]})

    if skipped:
        print(f"[parse_kaggle_json] skipped {skipped} sessions with unparseable timestamps")
    return events


# ---------- Step 2c: Combine both sources into one log file ----------
def kaggle_sessions_to_log_lines(path):
    # Same read as parse_kaggle_json(), but instead of building event
    # dicts, formats each password attempt as a real-looking log line
    # (reuses _format_line so it matches generate_sample_log()'s style).
    with open(path, "r", encoding="utf-8-sig") as f:
        sessions = json.load(f)

    lines = []
    skipped = 0
    for s in sessions:
        try:
            t = datetime.strptime(s["timestamp"].strip(), "%a %b %d %H:%M:%S %Y")
        except (ValueError, KeyError):
            skipped += 1
            continue
        for _ in s.get("passwords", []):
            lines.append(_format_line(t, s["foreign_ip"], s["username"], "Failed"))

    if skipped:
        print(f"[kaggle_sessions_to_log_lines] skipped {skipped} sessions with unparseable timestamps")
    return lines


def generate_combined_log(kaggle_path, out_path="combined_auth.log"):
    """
    Writes ONE .log file that has:
      - the generated practice traffic (normal logins + one obvious burst)
      - the whole Kaggle dataset's attack traffic, converted to the same
        log-line format

    Point of this: one real file you can open, reuse, or feed to
    parse_log() — same pipeline either way, real attacker data mixed
    with clean traffic instead of two separate runs.
    """
    normal_path = generate_sample_log(path="_tmp_normal.log")
    with open(normal_path) as f:
        normal_lines = f.read().splitlines()
    os.remove(normal_path)  # scratch file, not needed once we've read it

    kaggle_lines = kaggle_sessions_to_log_lines(kaggle_path)

    with open(out_path, "w") as f:
        f.write("\n".join(normal_lines + kaggle_lines) + "\n")
    return out_path


# ---------- Step 3: Find the attackers ----------
def analyze_failed_logins(events):
    # Groups every failed attempt by source IP, then checks each IP
    # for a fast burst of fails (see _has_burst below).
    fails_by_ip = defaultdict(list)
    for event in events:
        if event["status"] == "Failed":
            fails_by_ip[event["ip"]].append(event)

    report = {}
    for ip, fails in fails_by_ip.items():
        fails.sort(key=lambda x: x["time"])
        count = len(fails)
        users = {f["user"] for f in fails}
        span = (fails[-1]["time"] - fails[0]["time"]).total_seconds() if count > 1 else 0
        suspicious, tightest_span = _has_burst(fails, BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW_SECONDS)
        report[ip] = {
            "count": count,
            "users": users,
            "suspicious": suspicious,
            "span_seconds": span,
            "burst_span_seconds": tightest_span,
        }
    return report


def _has_burst(fails, threshold, window_seconds):
    """
    Slides a window across the sorted fail list looking for THRESHOLD
    fails packed into WINDOW_SECONDS or less.

    Why not just count total fails? Because 5 fails in 10 seconds is an
    attack, but 5 fails spread over 3 hours is probably just someone who
    forgot their password. Same count, very different situation — this
    is what actually tells them apart.

    Returns: (found_a_burst: bool, tightest_span_seconds_found)
    """
    if len(fails) < threshold:
        return False, None  # not even enough fails to check

    tightest = None
    for i in range(len(fails) - threshold + 1):
        window_span = (fails[i + threshold - 1]["time"] - fails[i]["time"]).total_seconds()
        if tightest is None or window_span < tightest:
            tightest = window_span
        if window_span <= window_seconds:
            return True, window_span  # found one — stop looking
    return False, tightest


# ---------- Step 4: Print the results ----------
def print_file_summary(events):
    # Quick totals: how much data, what time range, how many unique IPs/users.
    if not events:
        print("No events parsed.")
        return

    total = len(events)
    failed = sum(1 for e in events if e["status"] == "Failed")
    accepted = total - failed
    unique_ips = {e["ip"] for e in events}
    unique_users = {e["user"] for e in events}
    start = min(e["time"] for e in events)
    end = max(e["time"] for e in events)

    print("=== File Summary ===")
    print(f"Events parsed: {total}  ({failed} failed, {accepted} accepted)")
    print(f"Time range: {start.strftime('%b %d %H:%M:%S')} - {end.strftime('%b %d %H:%M:%S')}")
    print(f"Unique source IPs: {len(unique_ips)}")
    print(f"Unique usernames targeted: {len(unique_users)}")
    print()

def print_report(report):
    # One line per IP that had failed logins, worst offender first.
    print("=== Failed Login Report ===")
    if not report:
        print("No failed logins found.")
        return
    for ip, data in sorted(report.items(), key=lambda kv: -kv[1]["count"]):
        if data["suspicious"]:
            flag = f" <-- SUSPICIOUS (burst: {data['count']} fails in {data['burst_span_seconds']:.0f}s)"
        else:
            flag = ""
        print(f"IP {ip}: {data['count']} fails, users tried: {sorted(data['users'])}, "
              f"total span: {data['span_seconds']:.0f}s{flag}")


if __name__ == "__main__":
    import sys

    # Three modes:
    #   (no args)              -> generate + analyze the practice log
    #   kaggle <file>          -> analyze the kaggle dataset directly
    #   combined <file>        -> merge kaggle data + practice log into
    #                              one .log file, then analyze that
    if len(sys.argv) > 1 and sys.argv[1] == "kaggle":
        kaggle_path = sys.argv[2] if len(sys.argv) > 2 else "brute_force_data.json"
        try:
            events = parse_kaggle_json(kaggle_path)
        except FileNotFoundError:
            print(f"[error] '{kaggle_path}' not found.")
            print(f"Download the dataset from: {KAGGLE_DATASET_URL}")
            sys.exit(1)
    elif len(sys.argv) > 1 and sys.argv[1] == "combined":
        kaggle_path = sys.argv[2] if len(sys.argv) > 2 else "brute_force_data.json"
        try:
            combined_path = generate_combined_log(kaggle_path)
        except FileNotFoundError:
            print(f"[error] '{kaggle_path}' not found.")
            print(f"Download the dataset from: {KAGGLE_DATASET_URL}")
            sys.exit(1)
        print(f"[combined] wrote {combined_path}")
        events = parse_log(combined_path)
    else:
        log_path = generate_sample_log()
        events = parse_log(log_path)

    print_file_summary(events)
    report = analyze_failed_logins(events)
    print_report(report)