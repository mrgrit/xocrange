# Ledger C — wazuh-threat-hunting, case-09 .. case-15 (web attack cases)

Audit date 2026-11-18. Source: `/home/ccc/xocrange/contents/academy/wazuh-threat-hunting/lessons/case-NN/{lesson,explanation,missions}.json`, read in full. Live checks: demo Core 192.168.16.52 (read-only `rule.sh`, `dql`). Repo config read: `/home/ccc/xocrange/components/security-path/web/modsecurity.conf`, `/home/ccc/xocrange/components/siem/ossec.conf`.

## 0. Findings that apply to all seven lessons

Status words: `same`, `renamed -> X`, `missing`, `unverified`. "Verified" below means I saw it in Core today; everything else is labelled as inferred or unverified.

| # | Item | Where | Status | Note |
|---|------|-------|--------|------|
| G1 | **The attack commands are not text.** Every lesson's "실습 ① 공격 실행" slide (p142, 152, 160, 168, 176, 184, 193) is a PNG of an attacker terminal: title bar `공격자 att@192.168.0.202`, prompt `att@attacker:~$`, old hostnames, old response codes. | slide image | missing (must be redrawn) | Commands were transcribed by viewing the images; they are listed per lesson as `S<page>`. None of the seven explanation.json files has a `command` block except case-14 (C06-04..07). |
| G2 | Hostnames `juice.ccc.com`, `dvwa.ccc.com`, `ccc.com` (slides) and `juice.xocrange.lab`, `dvwa.xocrange.lab` (explanation) | all | renamed -> `juice.xoc.range`, `dvwa.xoc.range`; `ccc.com` (company main site) missing | Two different old naming schemes coexist in the same lesson. |
| G3 | Scheme `http://` on port 80 | all commands/URLs | unverified | Core entry is HTTPS 443 on the host; whether plain HTTP answers was not tested (no traffic sent). Expect `https://` and a certificate-trust step (`curl -k` or CA). |
| G4 | `agent.name: "web"` in every explanation query; `agent.name` as a result column on every slide; result screenshots show `agent.name web` | Q06-01..06, Q07-05..10, slides | renamed -> `agent.name: xoc-manager` (useless as a filter); use `location: *apache-access` | Verified: `agent.name: "web"` = 0 hits over 7 days; all web alerts are agent 000 `xoc-manager`. Location is `xoc-native/<64-hex>/apache-access` (a per-record hash in the middle), so only a trailing-wildcard match works. |
| G5 | Attacker VM `att@192.168.0.202`, host `attacker`, `curl/7.81.0` | slides, slide images | renamed -> external attacker VM (seen as `data.srcip 192.168.16.99` on the demo) | curl, python3, seq, bash present; gobuster not. |
| G6 | `Windows · Discover` as the `where` of every query; Chrome DevTools (Network, Console, Network conditions) | all queries, case-13/15 prose | renamed -> learner's own browser at `https://<core>/siem/` | No Windows endpoint in Core. DevTools steps are browser-side and still work in any Chromium. |
| G7 | Index pattern `wazuh-alerts-*` | all queries | same | Matches `wazuh-alerts-4.x-*`. Whether a Dashboard index pattern with exactly this title exists: unverified. |
| G8 | Index `wazuh-archives-*` | case-10 slides p149/158, Q07-06 syntax, Q06-04, case-12 prose | **missing (empty)** | Verified: `*` on archives = 0 hits over 30 days on the demo Core (ossec.conf has `logall_json yes`, but nothing is indexed). Non-alerting requests (plain 200s) are therefore not searchable anywhere in the Dashboard. |
| G9 | ModSecurity audit record: `location: "/var/log/apache2/modsec_audit.log"`, `data.request.request_line`, request headers/body | Q06-04, Q06-05 result, case-10 slides | renamed/missing | Core file is `modsec_audit.json`, location ends `/modsecurity`, and the records are in the **alerts** index (rules 119670 "ModSecurity JSON audit event", 119672 "…request blocked by WAF"). `SecAuditLogParts AHZ`: no request line, no headers, no body. Verified `_exists_:data.request.request_line` = 0. Present: `data.audit_data.messages` (CRS id/msg/matched data), `data.audit_data.action.intercepted`, `data.audit_data.engine_mode` (always `ENABLED`), `data.transaction.remote_address`, `data.transaction.transaction_id`. The access log line ends with `xoc_id=<id>` in the same format as `transaction_id`; joining the two on that id looks possible but I did not confirm an exact match. |
| G10 | WAF in detection-only mode on Juice Shop ("juice 사이트만 DetectionOnly") | case-09, 10, 11, 12, 13, 15 slides + case-11 prose | **missing** | Core: `SecRuleEngine On` for both targets. Verified: over 30 days there is not one apache-access alert with `data.id: 200` from a non-internal source, and `rule.groups: attack AND data.id: 2*` = 0. |
| G11 | Fields `data.url`, `data.id`, `data.srcip`, `data.protocol`, `full_log`, `rule.id`, `rule.description`, `rule.groups` | all | same | Verified on apache-access alerts. `full_log` ends with the User-Agent and then ` xoc_id=…`. `data.srcip` is the real client address. |
| G12 | Core's own management traffic in the same alert stream | — | new noise | Verified: requests to `/siem/…` from `172.18.0.1` appear under `*/apache-access` (e.g. `POST /siem/internal/search/opensearch` 500 -> 31122; `PUT /siem/api/…` 403 -> 31101). Affects case-12 and case-13 queries. |
| G13 | Slide line "xOC Range 결과 N hits" and three Discover result screenshots per lesson | slides | missing (old data) | Counts, timestamps (Oct 31 2026), agent, srcip all from the old lab. |
| G14 | No vhost in the record | — | new limitation | The access record has no Host field, so DVWA and Juice Shop requests cannot be told apart by a field; only by path. Lessons that say "the juice request / the dvwa request" must distinguish by URL. |
| G15 | missions.json | all | same | Three generic self-record missions per lesson; no environment references. |

All Wazuh rule IDs named in these lessons exist on the Core manager (verified with `rule.sh`): 31100, 31101, 31103, 31104, 31105, 31106, 31108, 31115 (maxsize 7900, level 13), 31120, 31121, 31122, 31123, 31151 (freq 14 / 90 s), 31152, 31153, 31154, 31161, 31162, 31163 (freq 14 / 120 s), 31166, 31167, 31168, 31169, 554. Existence is not the same as reachability: see per lesson.

---

## case-09 — Shellshock (slides p138–148; manuscript 7.4)

**1. Summary.** The learner sends a request to a `/cgi-bin/` path with a Shellshock function definition in User-Agent (and Referer), then finds the alerts 31166/31168 and reads why the same string is "attempt" on 4xx and "detected" on 2xx/3xx.

**2. Environment assumptions**

| Item | Where | Status | Note |
|------|-------|--------|------|
| `http://juice.ccc.com/cgi-bin/test.cgi` -> 200 | S142, slide p138, prose | renamed + behaviour missing | Old 200 came from Juice Shop answering any path while its WAF only detected. In Core the header pattern is expected to be blocked (CRS 932170-class rule), giving 403. Unverified live. |
| `http://dvwa.ccc.com/cgi-bin/status` -> 403 | S142, prose | renamed -> `dvwa.xoc.range` | Today's Core sample `GET /cgi-bin/xoc-probe` returned 403 / rule 31101 — but its User-Agent was a plain tag, not a Shellshock string. |
| `juice.xocrange.lab` | prose (B07-05/06) | renamed | |
| Browser User-Agent override (B07-05) | prose | same | Browser-side. |
| Rule 31166/31167 (level 6, child of 31101/31120) | Q07-05, slide p144/148, table | same (exists) | 0 hits ever on demo; expected to fire on a 403. Unverified. |
| Rule 31168/31169 (level 15, child of 31108 = 2xx/3xx) | Q07-05, slides, both screenshots | exists but **unreachable** | Needs a 2xx/3xx answer to a Shellshock-shaped request; with a blocking WAF this cannot happen. 31108 has 0 hits in 30 days. |
| `full_log` shows the header string | slide p140/141/148 | same | UA is in `full_log`; Referer too (combined format, verified shape). |
| "Apache forwards every path to Juice Shop (ProxyPass, 7.9 C07-09)" | prose | unverified | Cross-reference to another section's command. |
| Cross-refs 7.11 C07-19, 도식 7-2 | prose | n/a | Outside these lessons. |
| `agent.name: "web"` | Q07-05, slide columns | renamed | G4. |

**3. Commands**

| id | where | tool | target | Runs in Core? |
|----|-------|------|--------|---------------|
| S142-a (image) | attacker VM | curl `-A '() { :; }; /bin/bash -c "id"'` | Juice Shop `/cgi-bin/test.cgi` | needs rename; result changes (expected 403, not 200) |
| S142-b (image) | attacker VM | curl `-H 'Referer: () { :; }; /bin/bash -c "cat /etc/passwd"'` | DVWA `/cgi-bin/status` | needs rename; expected 403 as before |
| B07-05/06 (prose) | learner browser | DevTools UA override | Juice Shop `/cgi-bin/test.cgi` | needs rename; same caveat |

No `command` blocks in explanation.json.

**4. Queries**

| id | index | fields / rules | Returns data in Core? |
|----|-------|----------------|-----------------------|
| slide p144 | wazuh-alerts-* | `rule.id:(31166 or 31167 or 31168 or 31169) OR rule.description:*Shellshock*` | Probably yes, but only 31166 rows; today 0 hits (nobody sent the header). |
| Q07-05 | wazuh-alerts-* | `agent.name:"web" AND rule.id:(31166..31169)` | **No** as written (agent filter). Without it: 31166 only. |

**5. Images.** Slides 4 (1 attacker-terminal render, 3 old Discover result screens — all old environment). Explanation 3: 2 `screens`, 1 figure.

**6. Blocking gaps.** (a) No path that answers 2xx to a Shellshock header -> the 31166-vs-31168 contrast, which is the lesson's main point and its table, cannot be reproduced. (b) Slide p148's "31168 = 200" row and both result screenshots.

---

## case-10 — OS command injection (slides p149–158; manuscript 7.5)

**1. Summary.** The learner sends `;id` / `|cat /etc/passwd` to DVWA Command Injection and Juice Shop track-order by GET and by POST, then searches `data.url` for shell metacharacters and learns that a POST body is invisible in the access log.

**2. Environment assumptions**

| Item | Where | Status | Note |
|------|-------|--------|------|
| DVWA, page Command Injection, security level Low, logged-in session | prose steps 1–2 | same (app) / unverified (login, level) | DVWA exists; credentials and the security-level setting are not stated in the lesson. Whether the WAF lets the logged-in `ip=127.0.0.1; id` POST through is the crux — in blocking mode it is expected to be 403, so the "uid=… appears" step fails. Unverified. |
| `/vulnerabilities/exec/?ip=127.0.0.1%7Ccat%20/etc/passwd` -> 403 | S152, prose B07-09, screen 7-6 | renamed host; same result expected | 403 -> 31101 alert with the payload in `data.url`. Comparable Core sample today: `host=127.0.0.1%3bprintf+xoc-lab` -> 403 / 31101. |
| `/rest/track-order/1%3Bid` on Juice Shop -> 200 | S152, prose B07-08 | renamed; result unverified | If the WAF passes it and Juice answers 200, no Wazuh rule fires and (G8) the request is invisible. If the WAF blocks, 403 -> 31101. |
| Unauthenticated `POST /vulnerabilities/exec/` -> 302 | S152, prose | renamed; result unverified | Core's DVWA does answer 302 when unauthenticated, but the body `ip=127.0.0.1;id` reaches the WAF first. |
| "POST body is only in modsec_audit.log; no rule for this JSON -> look in archives, `data.audit_data.messages`" | slides p149, p158 | **changed** | Core is the opposite: audit records are decoded and alert (119670/119672) in the alerts index with `data.audit_data.messages`; archives is empty. But the record has no request line or body (parts AHZ), so the payload itself is still not shown — only the CRS match text ("Matched Data: …"). |
| CRS 932xxx | slide p149 | same (CRS 3.3.8 present) | Seen `OWASP_CRS/3.3.8` in audit messages. |
| Rule 31104 mentioned as the GET match | slide p158 | same (exists) | In Core the observed rule for a blocked command-injection GET was 31101. |
| `data.protocol`, `data.url`, `data.id`, bytes in `full_log` | slides, queries | same | "200 with large byte count = output returned" cannot be observed (no 200 alerts). |
| `agent.name: "web"` | Q07-06, Q07-07 | renamed | G4. |

**3. Commands**

| id | where | tool | target | Runs in Core? |
|----|-------|------|--------|---------------|
| S152-a (image) | attacker VM | curl | Juice Shop `/rest/track-order/1%3Bid` | needs rename; outcome unverified |
| S152-b (image) | attacker VM | curl | DVWA `/vulnerabilities/exec/?ip=…%7Ccat%20/etc/passwd` | needs rename |
| S152-c (image) | attacker VM | curl `-X POST -d "ip=127.0.0.1;id&Submit=Submit"` | DVWA `/vulnerabilities/exec/` | needs rename; expected 403 instead of 302 (unverified) |
| B07-07 (prose) | learner browser, logged in | form submit | DVWA Command Injection | needs rename; likely blocked by WAF |
| B07-08, B07-09 (prose) | learner browser address bar | — | as S152-a/b | needs rename |

No `command` blocks in explanation.json.

**4. Queries**

| id | index | fields / rules | Returns data in Core? |
|----|-------|----------------|-----------------------|
| slide p154 | wazuh-alerts-* | `data.url:(*%3Bid* or *;id* or *%7Cid* or *%7Ccat* or *whoami* or *cat%20* …)` | Yes for blocked GETs (field exists, no agent filter). Note Core logs lower-case hex as sent (`%3b`), and the patterns are case-sensitive wildcards. |
| Q07-06 | wazuh-alerts-* (+ archives per syntax note) | `agent.name:"web" AND data.url:(*vulnerabilities/exec/* OR *track-order*)` | No as written (agent filter). Without it: only 4xx/5xx requests; the "normal POST is in archives" part has no equivalent. |
| Q07-07 | wazuh-alerts-* | `agent.name:"web" AND data.url:(*%3Bid* OR …)` | No as written; fine without the agent filter. |

**5. Images.** Slides 4 (1 terminal, 3 Discover — all old environment). Explanation 2: 1 `screens`, 1 figure.

**6. Blocking gaps.** (a) A successful command execution through the browser (step 2, "uid=… is the stage-4 evidence") needs the WAF not to block the POST. (b) Archives index for the normal POST / ratio comparison. (c) Audit record without request line: the "body is in the WAF audit record" teaching needs rewording to "the CRS match text is, the body is not".

---

## case-11 — Attack request answered 200 (slides p159–166; manuscript 7.6)

**1. Summary.** The learner sends an XSS URL and a UNION SELECT to Juice Shop, which sits behind a detection-only WAF, and finds rule 31106 "A web attack returned code 200" as the top-priority list.

**2. Environment assumptions**

| Item | Where | Status | Note |
|------|-------|--------|------|
| Juice Shop WAF = DetectionOnly, other sites blocking | slide p161, prose first sentence, terminal comment | **missing** | G10. |
| `/?q=%3Cscript%3Ealert(1)%3C/script%3E` -> 200 -> 31105 + 31106 | S160, prose B07-10, screen 7-7 | renamed; result changes | Core sample today: `q=%3cscript%3e…` -> 403 / 31105. No 31106. |
| `/rest/products/search?q=%27))%20UNION%20SELECT%20id,email,password,4,…%20FROM%20Users--` -> 500 | S160, prose B07-11, screen 7-8 | renamed; result changes | Core sample today: UNION SELECT -> 403 / 31103. |
| Rule 31106 (child of 31103/31104/31105 with `id ^200`) | slide p159/162/166, Q07-08 | exists, **unreachable** | 0 hits in 30 days. |
| `rule.groups: attack AND data.id: 2*` | slide p162, Q07-08 | field same, 0 hits | Note: in Core `rule.groups` of 31101 also contains `attack`. |
| Alert dialog check in browser | prose | same | Only if the request reaches the app. |
| Cross-ref 7.8 (server change records) | Q07-08 result | n/a | |
| `agent.name: "web"` | Q07-08 | renamed | G4. |

**3. Commands**

| id | where | tool | target | Runs in Core? |
|----|-------|------|--------|---------------|
| S160-a (image) | attacker VM | curl | Juice Shop `/rest/products/search?q=…UNION…` | needs rename; returns 403, not 500 |
| S160-b (image) | attacker VM | curl | Juice Shop `/?q=<script>…` | needs rename; returns 403, not 200 |
| B07-10, B07-11 (prose) | learner browser | — | same | same |

No `command` blocks in explanation.json.

**4. Queries**

| id | index | fields / rules | Returns data in Core? |
|----|-------|----------------|-----------------------|
| slide p162 | wazuh-alerts-* | `rule.id:31106 OR (rule.groups:attack AND data.id:200)` | **No** — 0 hits, structurally. |
| Q07-08 | wazuh-alerts-* | `agent.name:"web" AND (rule.id:"31106" OR (rule.groups:"attack" AND data.id:2*))` | **No** — agent filter and no 2xx attack alerts. |

**5. Images.** Slides 4 (1 terminal, 3 Discover — old environment). Explanation 3: 2 `screens`, 1 figure.

**6. Blocking gaps.** The whole lesson: without a target (or a path) where the WAF only detects, there is no "attack + 200". Options are outside the scope of this audit (a detection-only vhost, or a payload that Wazuh's 31103–31105 match but CRS at paranoia level 1 does not — not identified, not tested).

---

## case-12 — Server error (5xx) surge (slides p167–174; manuscript 7.7)

**1. Summary.** The learner sends a quote character 20 times to the Juice Shop search API to provoke HTTP 500s, then finds them with `data.id: 5*`, reads the histogram, and checks the repeated-5xx rules.

**2. Environment assumptions**

| Item | Where | Status | Note |
|------|-------|--------|------|
| `/rest/products/search?q=apple` -> 200 (baseline) | prose | renamed | A 200 is not visible in the Dashboard (G8). |
| `/rest/products/search?q=%27N` (N=1..20) -> 500 from Juice Shop | S168, prose B07-12, screen 7-9 | renamed; **result unverified** | Depends on the blocking WAF letting `'1` through. If it does, 500 -> 31122, and the 14th within 120 s -> 31162 (which the old lab could not show because of the next row). If it blocks, 403 and the lesson has no 5xx. |
| "the 500 with UNION is rule 31103, so 20 terminal 500s ≠ alert count" | prose, screen 7-10 | changes | That observation came from detection-only mode. |
| Rules 31120–31123 | slide p167, Q07-10 syntax | same | Slide text says "31120~31122 (500/501/503)"; actual: 31120 = 50x parent, 31121 = 501, 31122 = 500, 31123 = 503. The manuscript has it right. |
| Rules 31152–31154 described as "same-IP 5xx burst" | slide p167/170/174 | exists, **mislabelled** | They are repeated SQLi / common web attack / XSS (verified XML). The manuscript uses 31161–31163, which is correct. Content error independent of the port. |
| Rules 31161/31162/31163 | Q07-10 | same (exist) | 0 hits in 7 days. |
| Archives for the request ratio (numerator/denominator) | prose list item 3 | missing | G8. Raw access log is not reachable by a learner either. |
| Histogram interval control (Auto -> Minute) | prose | unverified | Dashboard UI detail. |
| `agent.name: "web"` | Q07-09, Q07-10 | renamed | G4. |

**3. Commands**

| id | where | tool | target | Runs in Core? |
|----|-------|------|--------|---------------|
| S168 (image) | attacker VM | bash `for`/`seq` + curl | Juice Shop `/rest/products/search?q=%27$i` | needs rename; 500 outcome unverified |
| B07-12 (prose) | learner browser, 20 manual requests | — | same | needs rename |

No `command` blocks in explanation.json.

**4. Queries**

| id | index | fields / rules | Returns data in Core? |
|----|-------|----------------|-----------------------|
| slide p170 | wazuh-alerts-* | `data.id:5* OR rule.id:(31152 or 31153 or 31154)` | Yes, but polluted: all 24 `data.id:5*` hits in the last 7 days are Core's own `/siem/…` requests from 172.18.0.1 (G12); 31152–31154 had 11 hits from SQLi/XSS practice. Zero 5xx from a lab target so far. |
| Q07-09 | wazuh-alerts-* | `agent.name:"web" AND data.id:5*` | No as written; without the agent filter see above — add `AND NOT data.url:/siem*` or a srcip condition. |
| Q07-10 | wazuh-alerts-* | `agent.name:"web" AND rule.id:("31161" OR "31162" OR "31163")` | No as written; rules exist, reachable only if the 500s actually happen. |

**5. Images.** Slides 4 (1 terminal, 3 Discover — old environment). Explanation 2: both `screens`, 0 figures.

**6. Blocking gaps.** (a) A reliable way to get 5xx from a target through the blocking WAF — unverified, decides whether the lesson works at all. (b) Archives for the ratio exercise. (c) Platform noise in `data.id: 5*`.

---

## case-13 — Unusual HTTP methods (slides p175–182; manuscript 6.3 "headers and methods")

**1. Summary.** The learner sends PUT/TRACE/PROPFIND/DELETE (slides, curl) or a forged `sqlmap` User-Agent and a PROPFIND from the browser console (manuscript), then finds them by `data.protocol` / `full_log` and reads the WAF audit record.

**2. Environment assumptions**

| Item | Where | Status | Note |
|------|-------|--------|------|
| `http://juice.ccc.com/x` with PUT/TRACE/PROPFIND/DELETE -> 200/405/200/200 | S176 | renamed; result changes | Old 200s = detection-only Juice. Core sample today: `TRACE /` -> 403 / 31101, `data.protocol: TRACE`. PUT/PROPFIND/DELETE expected 403 by CRS 911100 (unverified). |
| "PUT + 201 = upload succeeded -> compare with FIM (rule 554)" | slides p175, p182 | **missing** | Rule 554 exists, but there is no syscheck data at all (0 `rule.groups: syscheck`, 0 `syscheck.path` in 7 days) and no agent on the web server. |
| `http://dvwa.xocrange.lab/book06-ua` with UA `sqlmap/1.0 book06-ua` -> 403 | prose, Q06-03 | renamed; result unverified | CRS 913100 is in 3.3.8; plausible. |
| `fetch('/book06-method', {method:'PROPFIND'})` from the DVWA `login.php` tab -> 403 | code block, B06-06-method.txt, screen 6-7 | renamed; plausible | Same-origin fetch, works from any browser. |
| File `B06-06-method.txt` (copy source) | prose | unverified | Not looked for. |
| Chrome DevTools: Network conditions, Console | prose | same | G6. |
| `full_log: "sqlmap"` (UA not a separate field) | Q06-03 | same | UA is in `full_log`. |
| `wazuh-archives-*`, `location: "/var/log/apache2/modsec_audit.log"`, `data.request.request_line: *book06-ua*` | Q06-04, Q06-05 result | **missing** | G8 + G9: wrong index, wrong location, field does not exist. |
| `intercepted: true`, `messages` containing 913100 / 949110 / 911100 | Q06-04/05 results, screen 6-6 | renamed -> `data.audit_data.action.intercepted`, `data.audit_data.messages` in alerts (rule 119672) | Verified field names and that messages carry `[id "9xxxxx"]`. No URL to filter on. |
| Cross-ref 5.6 | Q06-04 syntax | n/a | |
| `agent.name: "web"` | Q06-03, 04, 05 | renamed | G4. |

**3. Commands**

| id | where | tool | target | Runs in Core? |
|----|-------|------|--------|---------------|
| S176 (image) | attacker VM | bash `for` + `curl -X $m` | Juice Shop `/x` | needs rename; all four expected 403 |
| prose (UA) | learner browser | DevTools Network conditions | DVWA `/book06-ua` | needs rename |
| code block (PROPFIND) | learner browser Console | `fetch` | DVWA `/book06-method` | yes after opening the renamed site |

No `command` blocks in explanation.json.

**4. Queries**

| id | index | fields / rules | Returns data in Core? |
|----|-------|----------------|-----------------------|
| slide p178 | wazuh-alerts-* | `data.protocol:* AND NOT data.protocol:(GET or POST or HEAD or OPTIONS)` | Yes (49 hits / 7 days), but includes Core's own `PUT /siem/api/…` from 172.18.0.1 (G12). |
| Q06-03 | wazuh-alerts-* | `agent.name:"web" AND data.url:"/book06-ua" AND full_log:"sqlmap"` | No as written (agent filter); fields exist. |
| Q06-04 | wazuh-archives-* | `agent.name`, `location` (file path), `data.request.request_line` | **No** — three independent reasons. |
| Q06-05 | wazuh-alerts-* | `agent.name:"web" AND data.protocol:"PROPFIND" AND data.url:"/book06-method"` | No as written (agent filter); fields exist. |

**5. Images.** Slides 4 (1 terminal, 3 Discover — old environment). Explanation 5: 3 `screens`, 2 figures.

**6. Blocking gaps.** (a) Q06-04 and the audit-record half of Q06-05 need a rewritten query against alerts and a way to tie the audit record to the request (transaction id; unconfirmed). (b) FIM follow-up (slides only). (c) Slide and manuscript teach different exercises (curl to Juice vs browser to DVWA); the slide one loses its 200s.

---

## case-14 — Admin page access from outside (slides p183–191; manuscript 6.2 "path discovery")

**1. Summary.** The learner requests common admin paths (`/admin/`, `/phpmyadmin/`, `/wp-admin/`, `/manager/html`, `/console`), runs a word-list scan with Gobuster, and finds the 404 alerts (31101) and the repeated-4xx alert (31151) from a non-internal source.

**2. Environment assumptions**

| Item | Where | Status | Note |
|------|-------|--------|------|
| `http://ccc.com/` — company main site answering 404 | S184, slide p191 | **missing** | Core has only DVWA and Juice Shop. Slide p191 itself notes Juice answers 200 for unknown paths (no alert), so DVWA is the only substitute. |
| DVWA unknown path -> 404 -> 31101 | prose, Q06-01, screens 6-2/6-3 | renamed; **works** | Verified from today's data: `GET /admin?…` -> 404 / 31101 / srcip 192.168.16.99, and `/xoc-training-admin` -> 404. The four exact paths with trailing slash: unverified. |
| `http://dvwa.xocrange.lab/login.php?book06=known` -> 200, `/book06-missing` -> 404 | prose | renamed | The 200 is not visible in the Dashboard. |
| `/robots.txt`, `/login.php` exist on DVWA | C06-07 result | unverified | Standard DVWA files. |
| `NOT data.srcip:10.20.*`; text "attacker 192.168.0.x, ext 10.20.30.x" | slides p183, p186, p191 | same idea, addresses change | Core ext is still 10.20.30.0/24; `data.srcip` is the real client address, so the exclusion still makes sense. Old attacker address 192.168.0.202 is gone. |
| `GeoLocation.country_name` | slide p183 | **missing** | 0 documents have it (private addresses, no GeoIP enrichment seen). |
| Rule 31151 (freq 14, 90 s, same source) | Q06-02, screen 6-4 | same | Verified XML and 23 hits in 7 days. |
| gobuster (`-m dir -u -w -t 1 -a`) on the attacker VM | C06-07, options table, blind-spot box | **tool missing** | Also `-m dir` is Gobuster v2 syntax; current releases use `gobuster dir`. |
| `~/book06-paths.txt`, 23 lines; copy source `examples/rev01/chapter06/paths.txt` | C06-04..06, prose | unverified | Home directory on the attacker VM is fine; the examples path was not looked for. |
| `nano` on the attacker VM | C06-05 | unverified | Not in the listed tool set. |
| Cross-refs 6.7, 6.8 | prose | n/a | |
| `agent.name: "web"` | Q06-01, Q06-02 | renamed | G4. |

**3. Commands**

| id | where | tool | target | Runs in Core? |
|----|-------|------|--------|---------------|
| S184 (image) | attacker VM | bash `for` + curl | `ccc.com` `/admin/ /phpmyadmin/ /wp-admin/ /manager/html /console` | **app missing** -> retarget to DVWA |
| prose list | learner browser | address bar | DVWA `/login.php?book06=known`, `/book06-missing`, four admin paths | needs rename |
| C06-04 | attacker VM · terminal | `ls` | `~/book06-paths.txt` | yes |
| C06-05 | attacker VM · terminal | `nano` | same file | unverified (nano) |
| C06-06 | attacker VM · terminal | `cat` | same file | yes |
| C06-07 | attacker VM · terminal | `gobuster -m dir -u http://dvwa.xocrange.lab/ -w … -t 1 -a book06-scan` | DVWA `/` | **tool missing** (+ rename); a `while read … curl -A book06-scan` loop over the same list would give the same log pattern |

**4. Queries**

| id | index | fields / rules | Returns data in Core? |
|----|-------|----------------|-----------------------|
| slide p186 | wazuh-alerts-* | `data.url:(*phpmyadmin* or *wp-admin* or *manager/html* or */admin/* or *console*) AND NOT data.srcip:10.20.*` | Yes once the requests go to DVWA. Caveat: `*console*` also matches XSS payloads containing `console.log` (seen today). |
| Q06-01 | wazuh-alerts-* | `agent.name:"web" AND data.url:("/admin/" OR "/phpmyadmin/" OR "/wp-admin/" OR "/manager/html")` | No as written (agent filter); fine without it. |
| Q06-02 | wazuh-alerts-* | `agent.name:"web" AND rule.id:"31151"` | No as written; rule fires in Core (23 hits). |

**5. Images.** Slides 5 (1 terminal, 4 Discover — old environment). Explanation 4: 3 `screens`, 1 figure.

**6. Blocking gaps.** (a) `ccc.com` site (slides) — solvable by retargeting. (b) gobuster. (c) GeoLocation column. This is the most portable lesson of the seven.

---

## case-15 — Abnormally long URL (slides p192–199; manuscript 6.4)

**1. Summary.** The learner sends one request with an 8,000-character query value and finds rule 31115 "URL too long", learning that the rule measures the whole log line (maxsize 7900), not the URL.

**2. Environment assumptions**

| Item | Where | Status | Note |
|------|-------|--------|------|
| `http://juice.ccc.com/?a=<A×8000>` -> 200 | S193 | renamed; **result unverified** | Depends on three things not tested: the ingress and each proxy hop accepting an ~8 KB request line, the WAF not rejecting it, and the collector passing an ~8.2 KB line to the manager untruncated. |
| `location.href = '/?book06-long=' + 'A'.repeat(8000)` from the DVWA `login.php` tab; old result `data.id 200` | code block, B06-11-long.txt, Q06-06 | renamed; result differs | Unauthenticated DVWA `/` answers 302 in Core. 31115 is a child of 31100 regardless of status, so the rule can still fire. |
| Apache `LimitRequestLine` 8,190 default; "request line 8,027 B, log line 8,228 B" | prose, slide p199 | unverified | No `LimitRequestLine` override found in `components/security-path/web/`. Core's log line is ~35 bytes longer (`xoc_id=`), which helps the 7,900 threshold but the margin under 8,190 on the request side is unchanged. |
| Rule 31115, level 13, maxsize 7900 | slides, Q06-06, screen 6-8 | same (exists) | 0 hits ever on the demo — nobody has tried it. |
| python3 on the attacker VM | S193 | same | |
| "200, so it was not stopped at the WAF"; cross-ref 5.9 | prose | unverified | |
| `agent.name: "web"` | Q06-06 | renamed | G4. |

**3. Commands**

| id | where | tool | target | Runs in Core? |
|----|-------|------|--------|---------------|
| S193 (image) | attacker VM | curl + `python3 -c` | Juice Shop `/?a=…` | needs rename; outcome unverified |
| code block | learner browser Console | JavaScript `location.href` | DVWA `/?book06-long=…` | needs rename only |

No `command` blocks in explanation.json.

**4. Queries**

| id | index | fields / rules | Returns data in Core? |
|----|-------|----------------|-----------------------|
| slide p195 | wazuh-alerts-* | `rule.id:31115` | Unverified — rule exists, never fired in Core. |
| Q06-06 | wazuh-alerts-* | `agent.name:"web" AND rule.id:"31115" AND data.url:*book06-long*` | No as written (agent filter); otherwise as above. |

**5. Images.** Slides 4 (1 terminal, 3 Discover — old environment). Explanation 2: 1 `screens`, 1 figure.

**6. Blocking gaps.** None known, one unknown: whether an 8 KB request line survives ingress -> fw -> ips -> web -> collector and still yields 31115. One test request decides it.

---

## Cross-lesson summary (ordered by number of lessons affected)

| Gap | Lessons | Severity |
|-----|---------|----------|
| Attack commands exist only as PNGs of the old attacker terminal (old host, address, hostnames, results) | 7/7 | Rework: every "실습 ①" slide must be redrawn; there is no text to edit. |
| `agent.name: "web"` in every manuscript query -> zero hits; replace with `location: *apache-access` | 7/7 (13 queries) | Mechanical, but every query fails as written. |
| Old hostnames (two schemes) and `http://`; Core is HTTPS at the ingress | 7/7 | Mechanical; HTTP behaviour unverified. |
| Old Discover screenshots and "N hits" lines (22 slide screenshots + 14 manuscript `screens` images) | 7/7 | Recapture. |
| Juice Shop no longer behind a detection-only WAF: no attack ever returns 2xx/5xx from the app | 09, 10, 11, 12, 13, 15 (fatal for 11; removes the main contrast in 09; 12 and 15 depend on an untested pass-through) | Design decision needed. |
| `wazuh-archives-*` empty on the demo Core (0 docs in 30 days) | 10, 12, 13 | Normal 200 requests cannot be shown; ratio exercise and Q06-04 have no source. |
| ModSecurity audit record has no request line/headers/body (`SecAuditLogParts AHZ`), different file name, lives in alerts as 119670/119672 | 10, 13 | Queries must be rewritten; correlation by transaction id unconfirmed. |
| Core's own `/siem/…` traffic (172.18.0.1) in the same alert stream | 12, 13 | Add an exclusion to the queries. |
| No FIM/syscheck data (rule 554 follow-up) | 13 | Slide text only. |
| `ccc.com` main site missing; gobuster missing; `GeoLocation.*` missing | 14 | Retarget to DVWA, replace with a curl loop, drop the column. |
| Content errors unrelated to the port: slides of case-12 label 31152–31154 as 5xx-burst rules and 31120–31122 as 500/501/503 | 12 | Fix while porting. |

Not verified in this audit (no traffic was sent): any response code for the lesson payloads against Core; plain-HTTP access; whether 31166 and 31115 fire on Core's log format; DVWA login/security-level handling; existence of the `B0x-…txt` and `examples/rev01/…` copy files; `nano` on the attacker VM.
