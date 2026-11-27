# SessionGuard v2.0 — Cookie & Session Security Analyzer (GUI Edition)

**Final project tool — Web Session Security track**
Student: **Rayyan** · Instructor: **Abdul Mannan** · PNY Trainings, Cyber Security Department

SessionGuard is a cookie and session security analyzer. Give it the address of
your **own lab web application** and it fetches responses, inspects every raw
`Set-Cookie` header, checks the **Secure / HttpOnly / SameSite** flags, measures
session-cookie **length and Shannon entropy**, checks whether the session ID
**rotates on login**, **tests session fixation** with an attacker-supplied ID,
re-tests the **pre-logout session ID after logout**, samples fresh IDs for
**duplicates / collisions / shared prefixes**, and audits **cookie scope and
`__Secure-` / `__Host-` prefix rules** — then prints and saves a severity-rated
session security report.


---

## 1. Quick start (pick one)

### Option A — run the ready-made Windows EXE
Double-click **`SessionGuard.exe`** (Windows 8/10/11 x64, nothing to install).
The GUI opens, the scan runs in a background thread, and the report is
auto-saved to the `reports\` folder next to the EXE.

### Option B — run from source
```
python -m pip install -r requirements.txt
python SessionGuard_GUI.py
```
(Python 3.8+ with Tkinter. The tool also works without `requests` — it falls
back to a built-in stdlib HTTP client.)

### Option C — build your own EXE in one click
Double-click **`Build_EXE.bat`**. It installs `requests` + `PyInstaller` and
produces a fresh `SessionGuard.exe` next to the script.

### Instant demo (no lab needed)
Menu **Help → Load Demo Data** (or `python SessionGuard_GUI.py --demo`): the
tool runs a full offline scan against a fictional vulnerable shop so you can
see every tab populated with High findings.

---

## 2. What it checks (all PDF must-haves + stretch goals)

| # | Check | Type |
|---|-------|------|
| 1 | Fetches target and captures **raw Set-Cookie headers** per hop (before the cookie jar normalizes them) | Must-have |
| 2 | Flags audit: **Secure, HttpOnly, SameSite** on every cookie, incl. **SameSite=None without Secure** | Must-have |
| 3 | **Length + Shannon entropy** (bits/char and estimated total bits) of every session value; flags short, low-entropy and **predictable** values (sequential runs, timestamps, hex/base64-encoded text, UUIDv1, username-derived) | Must-have |
| 4 | **Session rotation on login** — compares pre-login vs post-login session ID | Must-have |
| 5 | **Session fixation** — plants an attacker-supplied SID before login and reports kept vs fresh | Must-have |
| 6 | Severity-rated findings + full **report saved to a text file** (auto + Save As) | Must-have |
| 7 | **Sampling** of N fresh session IDs → duplicates, collisions, shared prefixes, sequential counters | Stretch |
| 8 | **Logout invalidation** — re-uses the pre-logout SID and reports whether the server still accepts it | Stretch |
| 9 | **Scope & prefixes** — Domain too broad / public-suffix / cross-domain, Path advisory, `__Host-` and `__Secure-` prefix rule breaks, long-lived session cookies | Stretch |

Severity model: **HIGH** = accepted fixation, no rotation, session valid after
logout, missing HttpOnly on a session cookie, SameSite=None without Secure,
duplicate/sequential/predictable IDs, plaintext HTTP on a public host.
**MEDIUM** = missing Secure on a session cookie, missing SameSite, short or
low-entropy IDs, prefix violations, shared prefixes. **LOW / INFO** = advisory
scope findings, non-session cookie flag gaps, inconclusive tests.
Risk score = `10×High + 5×Medium + 2×Low` (max 100).

---

## 3. Using the GUI

1. **TARGET** box — your lab URL (e.g. `http://192.168.56.10:5000/`).
2. Left sidebar —
   * **Scan modules**: tick which tests a full scan runs (flags and entropy are
     always available; rotation / fixation / logout need the login block).
   * **Lab login**: login URL, your own lab username/password, POST field
     names (defaults `username` / `password`), extra POST fields
     (one `name=value` per line — e.g. a CSRF token if your lab needs it).
   * **Session test options**: session cookie names (blank = auto-detect),
     attacker SID for fixation (blank = auto), sampling count, logout URL
     (blank = `/logout`), protected URL (blank = the page login redirects to),
     authenticated-page marker for a precise logout verdict.
3. **RUN FULL SCAN** (or Ctrl+Enter). Use **STOP** to abort mid-scan.
4. Tabs: **Dashboard** (risk gauge + counts) · **Cookies** (double-click a row
   for the raw header and full entropy analysis) · **Findings** (evidence, fix,
   OWASP reference for every finding) · **Entropy** · **Session Tests**
   (rotation / fixation / logout / sampling values and verdicts) ·
   **Raw Headers** (every captured Set-Cookie per hop) · **Report**
   (Save As / Copy).
5. The report is auto-saved to `reports\SessionGuard_Report_<host>_<time>.txt`.

Settings persist in `sessionguard_settings.json` (the password is never saved).

---

## 4. Command-line mode (the original spec)

Passing a URL runs the same analyzer from the console:

```
python SessionGuard_GUI.py http://192.168.56.10:5000/ ^
       --login-url /login --username testuser --password TestPass123 ^
       --samples 10 --no-verify --out lab_report.txt
```

All options: `python SessionGuard_GUI.py --help`
(`--login-url --username --password --user-field --pass-field
--extra-fields --cookie-names --attacker-sid --samples --timeout --no-verify
--logout-url --protected-url --auth-marker --modules --out`).

Self-checks: `python SessionGuard_GUI.py --selftest` (19 offline checks).

---

## 5. Testing it on your own lab

`lab_server.py` (included) is a deliberately vulnerable lab app you can run
locally to see every finding fire:

```
python -m pip install flask
python lab_server.py 5057          # login: testuser / TestPass123
```

Vulnerability switches: `SG_BADFLAGS=1` (no cookie flags), `SG_WEAK=1`
(sequential 6-digit IDs), `SG_STATIC=1` (same ID for everyone),
`SG_NO_ROTATE=1`, `SG_FIXABLE=1` (accepts planted SIDs), `SG_NO_LOGOUT=1`.
Example worst-case run:

```
set SG_BADFLAGS=1 && set SG_STATIC=1 && set SG_NO_ROTATE=1 && set SG_FIXABLE=1 && set SG_NO_LOGOUT=1
python lab_server.py 5057
SessionGuard.exe  (target http://127.0.0.1:5057/  login testuser / TestPass123)
```

See `sample_report.txt` — a real scan of exactly that configuration
(100/100 HIGH RISK, 5 High findings).

---

## 6. Files in this package

| File | Purpose |
|------|---------|
| `SessionGuard.exe` | Ready-to-run Windows GUI (x64) |
| `SessionGuard_GUI.py` | Full source — GUI + CLI + demo + selftest |
| `Build_EXE.bat` | One-click EXE builder for Windows |
| `Run_SessionGuard.bat` | Run from source with dependency check |
| `requirements.txt` | Python dependencies (`requests`) |
| `icon.ico`, `version.txt` | EXE icon and version metadata |
| `sample_report.txt` | Real lab scan report (all-high configuration) |
| `lab_server.py` | Vulnerable test lab for your own machine |
| `screenshot.png` | GUI screenshot |

---

## 7. Lab rules — read before scanning

Build and test SessionGuard **only on systems you own or have written
permission to test, inside an isolated lab environment**. Never point it at a
real website you do not own, and never test with anyone else's account or
session. A session test is only a test when you have ownership or written
permission — anything else is unauthorized access. Unauthorized access to
computer systems is a criminal offence under the **Prevention of Electronic
Crimes Act, 2016 (Pakistan)**.

---

## 8. Troubleshooting

* **Login tests say "Login could not be verified"** — check username/password,
  field names (`username`/`password` are defaults; many apps use `email`),
  and add CSRF/extra fields in the sidebar. SessionGuard reports INFO instead
  of guessing.
* **Self-signed lab certificate error** — untick **Verify TLS**.
* **No cookies captured** — try the login page URL as target, or a page that
  sets cookies; SPAs may need the API endpoint that returns Set-Cookie.
* **Logout verdict is "undetermined"** — fill *Protected URL* and
  *Authenticated-page marker* (a string that only appears when logged in).
* **Windows SmartScreen warning** — expected for self-built executables;
  click *More info → Run anyway*.
