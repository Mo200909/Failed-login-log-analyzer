# Failed-Login Log Analyzer

Parses SSH auth logs (or a Kaggle brute-force dataset) and flags IPs that failed logins in a tight burst — not just IPs with a lot of fails spread out.

## What it does

1. Reads login events (`Accepted` / `Failed`, user, IP, timestamp).
2. Groups failed attempts by source IP.
3. Slides a window over each IP's failed attempts to check for **5+ fails within 60 seconds**.
4. Prints a file summary + a per-IP report, flagging bursts as `SUSPICIOUS`.

A burst check, not a raw-count check: 5 fails in 10 seconds and 5 fails over 3 hours are treated differently. Only the fast one gets flagged.

## Run it

**No arguments** — generates its own sample log (`sample_auth.log`) and analyzes that:
```bash
python "Failed-Login_Log_Analyzer.py"
```

**Against a real sshd-style log**:
```bash
python "Failed-Login_Log_Analyzer.py" logfile your_auth.log
```

**Against the Kaggle "SSH Brute Force" dataset** ([download here](https://www.kaggle.com/datasets/lako65/ssh-brute-force-ipuserpassword)):
```bash
python "Failed-Login_Log_Analyzer.py" kaggle brute_force_data.json
```
If the file isn't found, the script prints the dataset link and exits instead of crashing.

**Combined** — merges the kaggle attack data + a generated practice log into one real `.log` file on disk, then analyzes that:
```bash
python "Failed-Login_Log_Analyzer.py" combined brute_force_data.json
```
Writes `combined_auth.log` in the current directory. Same missing-file behavior as `kaggle` mode above.

## Log format expected (`parse_log`)

Standard sshd auth log lines:
```
Sep 21 02:50:00 server sshd[8910]: Failed password for admin from 203.0.113.77 port 39081 ssh2
```
Lines that don't match this pattern are silently skipped.

## Kaggle adapter — known limitation

`parse_kaggle_json` converts the dataset into the same event shape as `parse_log`, so the same `analyze_failed_logins`/`print_report` code runs on both. Two things to know before trusting the output on this source:

- The dataset logs **one entry per session** with a list of passwords tried, not one timestamp per attempt. Every password in a session gets stamped with the *same* session timestamp — the sub-second timing inside a session is not in the data, so it's approximated.
- The dataset contains **only attack sessions**, no legitimate logins. `print_file_summary`'s accepted count will always be `0` against this source — that's a property of the data, not a bug.

## Config

```python
BRUTE_FORCE_THRESHOLD = 5       # fails required to flag
BRUTE_FORCE_WINDOW_SECONDS = 60 # time window for those fails
```
Change these two constants to tune sensitivity.

## Files

| File | Purpose |
|---|---|
| `Failed-Login_Log_Analyzer.py` | Main script — generator, parser, analyzer, report |
| `sample_auth.log` | Example output of `generate_sample_log()` |
| `combined_auth.log` | Written by `combined` mode — practice log + kaggle attack traffic merged |
| `brute_force_data.json` | Kaggle dataset (not included — [source](https://www.kaggle.com/datasets/lako65/ssh-brute-force-ipuserpassword)) |

## Status

Built as a learning/portfolio script (Fall 2026 weekly Python practice). Not production hardened — no error handling for malformed real-world log lines beyond regex-skip, no tests.
