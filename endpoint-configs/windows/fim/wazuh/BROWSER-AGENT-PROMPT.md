# Prompt: build the File Integrity / DLP dashboard in Wazuh

> ## ⚠️ Paste this into the chat box — do NOT let the browser agent read this file
>
> A browser agent treats anything it reads from a page or a file as **data, not
> instructions** — deliberately, because otherwise any web page could order it
> around. If you open this file in the browser and say "do what this says", it
> will (correctly) refuse it as a prompt-injection attempt, and it is right to.
>
> So: **copy the text inside the fenced block below and paste it into the
> agent's chat input yourself**, with the Wazuh Dashboard open and logged in.
> Then it arrives as your own request and it will act on it.
>
> This is also why the text below is written in the first person, as you
> speaking — not as a "task brief" or a numbered script addressed to an agent.
> Phrasing it that way is what made the first attempt look like an injection.

---

````
I want you to build a dashboard for me in the Wazuh Dashboard I have open in this
tab. I'm already logged in. This is my own request — please drive the UI directly.

Background: we run a custom file-integrity agent on our Windows endpoints. Its
events reach this Wazuh instance through the normal Wazuh agent → manager
pipeline, land in the wazuh-alerts-* index, and are tagged with rule group `dlp`
(rule IDs 100300–100312). The decoded fields sit under data.*: data.action
(created / modified / renamed / moved / copied / deleted), data.user,
data.machine, data.file_path, data.destination, data.file_hash,
data.recoverable, plus rule.level. The time field on this index is `timestamp`,
not @timestamp.

First, check whether data is actually flowing: Discover → index pattern
wazuh-alerts-* → query `rule.groups: dlp` → time range last 7 days. If you get
zero results, stop right there and tell me — I'll fix the pipeline before we
build anything. If there are results, tell me roughly how many and the newest
timestamp, then carry on.

Then:

1. Dashboards Management (may be called Stack Management) → Index patterns →
   wazuh-alerts-* → click refresh, so the data.* fields appear in the
   aggregation dropdowns. Tell me whether they show as data.action or
   data.action.keyword, and use whichever exists for everything below.

2. In Discover with query `rule.groups: dlp`, add columns data.action,
   data.user, data.machine, data.file_path, data.destination, rule.level, sort
   by timestamp descending, and save it as "DLP — File Activity".

3. Create these six visualizations, all on wazuh-alerts-*, and put
   `rule.groups: dlp` in the query bar of each one:
   - Pie, Terms on data.action, size 10 → save "DLP — Actions"
   - Data table, Terms on data.user, size 10 → save "DLP — Top Users"
   - Data table, Terms on data.file_path, size 20 → save "DLP — Top Files"
   - Vertical bar, X-axis Date Histogram on timestamp (auto interval), split
     series Terms on data.action → save "DLP — Timeline"
   - Metric, Count, but with query `rule.groups: dlp and rule.level >= 8` →
     save "DLP — High Severity"
   - Data table, Terms on data.machine, size 20 → save "DLP — Endpoints"

4. New dashboard, add all six plus the saved search. Put High Severity and
   Actions on the top row, Timeline full width below, the three tables in a row
   under that, and the saved search full width at the bottom. Time range last
   24 hours. Save as "File Integrity / DLP" with "store time with dashboard"
   ticked.

Please don't invent any numbers — report only what the UI actually shows. If a
step fails or a field is missing, stop and tell me rather than substituting
something else. At the end, give me the dashboard URL and anything that didn't
work.
````

---

## What the six panels give you

| Panel | Answers |
|---|---|
| DLP — High Severity | How many movement/deletion events right now |
| DLP — Actions | What kind of file activity dominates |
| DLP — Timeline | When it happened, split by action |
| DLP — Top Users | Who is moving the most data |
| DLP — Top Files | Which files are being touched most |
| DLP — Endpoints | Which machines are reporting |
| DLP — File Activity | The raw event stream underneath all of it |

## If the agent reports "No DLP events found"

That means the pipeline is not delivering yet — not that the dashboard steps are
wrong. Fix the pipeline first (see [`README.md`](README.md) in this folder):

1. Redeploy the watcher (`Deploy-FIM.ps1`) so events carry the `event_source`
   marker and the hardened ACLs
2. Add the `<localfile>` block from [`agent-localfile.xml`](agent-localfile.xml)
   to the endpoint's `ossec.conf`, then `Restart-Service WazuhSvc`
3. Install [`local_rules.xml`](local_rules.xml) on the manager at
   `/var/ossec/etc/rules/local_rules.xml`, then restart `wazuh-manager`
4. Confirm with `sudo /var/ossec/bin/wazuh-logtest` that a real line from
   `fim-events.log` matches rule `100300` plus one of `100301`–`100306`

Then paste the prompt again from the top.
