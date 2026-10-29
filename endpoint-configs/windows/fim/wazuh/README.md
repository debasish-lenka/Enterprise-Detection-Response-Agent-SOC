# File Integrity / DLP → Wazuh Dashboard

How to surface this project's custom File Integrity (DLP-lite) events inside
**Wazuh's own dashboard** at `siem.dbi360.com`, instead of only in this repo's
standalone HTML dashboard.

It needs no new agent, no new port, and no new service on the endpoint. The
Wazuh agent already installed there just reads one more local file.

## How it fits together

```
Watch-FileIntegrity.ps1  (already running as a Scheduled Task)
        │
        │  writes one JSON object per line
        ▼
C:\ProgramData\SOCLab\FIM\fim-events.log
        │
        │  <localfile> tails it  (agent-localfile.xml)
        ▼
Wazuh Agent ──── existing encrypted channel, TCP 1514 ────► Wazuh Manager
                 (no new port, no second agent)                  │
                                                                 │ local_rules.xml
                                                                 ▼
                                                        wazuh-alerts-*  index
                                                                 │
                                                                 ▼
                                                        Wazuh Dashboard
```

The watcher already writes exactly the shape Wazuh wants — one compact JSON
object per line — so nothing about the watcher's own logic has to change.

## Step 1 — endpoint (one block, one restart)

Paste the `<localfile>` block from [`agent-localfile.xml`](agent-localfile.xml)
into `C:\Program Files (x86)\ossec-agent\ossec.conf`, inside `<ossec_config>`,
then in an elevated PowerShell:

```powershell
Restart-Service WazuhSvc
```

## Step 2 — manager (rules)

Copy [`local_rules.xml`](local_rules.xml) onto the Wazuh manager at
`/var/ossec/etc/rules/local_rules.xml` (merge it in if you already have one),
then:

```bash
sudo systemctl restart wazuh-manager
```

Verify the rules actually fire before waiting on live traffic — paste one real
line from `fim-events.log` into:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

You should see it decode as `json` and match rule `100300` plus one of the
per-action children (`100301`–`100306`).

## Step 3 — Wazuh Dashboard

Events arrive in `wazuh-alerts-*` under `rule.groups: dlp`. In **Discover**,
filter:

```
rule.groups: dlp
```

Useful fields for columns and visualizations (Wazuh nests decoded JSON under
`data.`):

| Field | Meaning |
|---|---|
| `data.action` | created / modified / renamed / moved / copied / deleted |
| `data.user` | AD identity that did it |
| `data.machine` | endpoint hostname |
| `data.file_path` | where the file ended up |
| `data.destination` | correlated source path (for moved/copied/renamed) |
| `data.file_hash` | SHA256 — also the shadow-copy filename on the endpoint |
| `data.file_size` | bytes |
| `data.content_preview` | extracted text preview |
| `data.recoverable` | whether a shadow copy exists for recovery |

A reasonable dashboard: a pie on `data.action`, a data table of top
`data.user` and `data.file_path`, a timeline split by `data.machine`, and a
saved search pinned to `rule.level >= 8` for the movement/deletion signal.

## Rule severity, and why

| Rule | Event | Level |
|---|---|---|
| 100301 / 100302 | created, modified | 4 — routine, kept for audit trail |
| 100303 | renamed | 6 |
| 100304 / 100305 | moved, copied | 8 — actual data movement |
| 100306 | deleted | 10 |
| 100310 | copied/moved to `D:`–`Z:` (USB, mounted, mapped drive) | 12 |
| 100311 | copied/moved to a `\\UNC\share` | 12 |
| 100312 | deletion with no shadow copy held (genuinely unrecoverable) | 12 |

## What deliberately does NOT go through Wazuh

**`content_b64` — the recovered file bytes.** Wazuh's logcollector truncates
any single event over ~64 KB, and a recovered file's base64 runs to tens of
megabytes. Pushing file contents into the alerts index would also bloat it
enormously for no real benefit.

So `Watch-FileIntegrity.ps1` writes **two variants** of each event:

- the **lean** one (no `content_b64`) to the local log file → this is what
  Wazuh reads
- the **full** one (with `content_b64`) over its TCP forward to Vector → this
  is what backs the standalone dashboard's restore/download button

The bytes themselves stay on the endpoint in the content-addressed shadow
store at `C:\ProgramData\SOCLab\FIM\ShadowCopies\<sha256>`, and **every Wazuh
alert carries that `data.file_hash`** — so an analyst who needs the actual
file looks up the hash and pulls that one file, rather than the SIEM storing
every version of every file forever. That is the better design regardless of
the size limit.

## Division of labour

| | Wazuh Dashboard | This repo's dashboard |
|---|---|---|
| Detection, alerting, severity, correlation with other Wazuh data | ✅ | ✗ |
| Long-term searchable audit trail | ✅ | ✗ |
| Content preview inline | ✅ (`data.content_preview`) | ✅ |
| One-click file restore / ZIP download | ✗ (bytes never sent) | ✅ |
| Per-user restore bundles, admin extension config | ✗ | ✅ |

Use Wazuh as the detection and investigation surface; keep this repo's page
for the DLP-specific operations it can do that a generic SIEM UI cannot.
