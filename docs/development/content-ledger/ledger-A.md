# Ledger A — environment assumptions, lessons `orientation`, `discover`, `dql`, `infrastructure`, `linux-basics`, `web-basics`

Course: `/home/ccc/xocrange/contents/academy/wazuh-threat-hunting/lessons/<lesson>/`
Audit date: 2026-11-18. Read-only. Both `lesson.json` and `explanation.json` of each lesson were read in full; `missions.json` too.

## How to read this

Status values: `same`, `renamed -> <new>`, `missing` (not in Core), `unverified`.

Evidence levels used in notes:
- **[live]** = checked today on demo Core 192.168.16.52 with `rule.sh` / `dql` (alerts index, 7-day window unless stated).
- **[given]** = from the "Current Core facts" in the task brief, not re-checked by me.
- **[seen]** = I opened the image file and looked at it.
- No tag = read from the lesson text only.

Live-check results that many rows refer to (alerts index, last 7 days, 1,708,906 alerts total):

| Check | Result |
|---|---|
| `agent.name: "xoc-manager"` | 1,708,906 hits = 100 %. `NOT agent.name: "xoc-manager"` = 0 |
| `agent.name` = `bastion` / `web` / `xocrange-host` / `office-pc01` | 0 hits each |
| `_exists_:agent.ip` | 0 hits |
| `location: "/var/log/auth.log"` | 0 hits. Core locations look like `xoc-native/<64-hex>/apache-access`; sshd probe uses `xoc-native-probe` |
| `_exists_:data.srcip` | 1,388 |
| `_exists_:data.url` / `data.protocol` | 803 / 803 |
| `_exists_:data.id` | 1,364 |
| `_exists_:data.srcport` | 585 |
| `_exists_:data.srcuser` | 24 (all from the synthetic sshd probe, see below) |
| `_exists_:data.dstuser` | 0 |
| `_exists_:predecoder.program_name` | 24 (same probe) |
| `_exists_:decoder.name`, `location`, `full_log`, `rule.groups` | ~1.7 M each (present) |
| `_exists_:rule.mitre.id` | 862 |
| `_exists_:syscheck.path`, `syscheck.event` | 0 / 0 |
| `_exists_:data.win.system.eventID` | 0 |
| `_exists_:data.audit.command` | 1,203 (`data.audit.exe` 276 in 24 h) |
| `_exists_:data.osquery.name` | 79,354 |
| `_exists_:data.alert.signature`, `data.src_ip` | 104 / 104; only signature seen: `xOC inline verification marker`, sid 1000001, rule 86601 |
| `_exists_:data.command`, `data.cmd_host` | 0 / 0 |
| `_exists_:GeoLocation.country_name`, `data.ip_reputation`, `data.virustotal.positives` | 0 / 0 / 0 |
| `rule.groups: cmdlog` | 0 |
| `rule.groups: attack` | 655 |
| `rule.id: "5710"` | 24, all `location: xoc-native-probe`, `data.srcip 192.0.2.10`, `data.srcuser xocprobe…`, full_log `… xoc sshd[43210]: Invalid user …` — a synthetic probe, not a real sshd |
| `rule.id: "5715"`, `"31106"` | 0 / 0 |
| `rule.id: "31103"` | 46; sample has `data.srcip 192.168.16.99`, `data.url /rest/products/search?q=1+UNION+SELECT+1--`, `data.id 403`, `data.protocol GET`; log time is `+0000` and the line ends with ` xoc_id=…` |
| `data.url: *union*` | 0 (the Core samples carry uppercase `UNION`; the field is a case-sensitive keyword) |
| `rule.level >= 10` | 79,517 in 7 days, 19,682 in 24 h; sample is rule 111201 "Linux Sysmon process creation" from `/sysmon` |
| `location: *modsecurity` | 1,608; sample rule 119672 "ModSecurity JSON request blocked by WAF" |
| `location: *nftables` | 0 |
| **archives index**, `*` for 60 min / 24 h / 7 d | **0 hits every time** (the helper returned no error). Either archives are empty on the demo Core or the helper does not reach them — not determined |
| **events index**, `*` | helper fails: `indexer 400 … No mapping found for [@timestamp] in order to sort on` (helper problem; index exists) |

Rule existence [live, `rule.sh`]: exist — 5710, 5712, 5715, 5716, 5720, 5760, 5763, 31101, 31103, 31106, 31108 (level 0), 60204. **Missing — 100260, 100261, 119660, 119661, 119662, 119663.**

Caveat on the helper: it is not the Dashboard's DQL parser. `rule.id: (5710 or 5712 or …)` with lowercase `or` returned 0 while `(5710 OR 5712)` returned 24. The slides use lowercase `or` in two places; in real Discover DQL that is accepted, so I did not count this as a gap, but it was not checked in the Dashboard itself.

---

## 1. `orientation` — 학습 흐름과 사건 노트 (slides p1–4; manuscript 2.7 조사 기록 쓰기)

**Summary.** The learner sees the course map (61 examples + 2 osquery, five groups) and learns to write an investigation record separating fact from judgement, using one worked sshd failure on `bastion`. No commands, no queries to run.

### Environment assumptions

| Item | Where | Status | Note |
|---|---|---|---|
| Wazuh **4.10** manager | slide p2 table | renamed -> 4.14 | [given] |
| Path attacker → firewall → IPS → WAF → vulnerable web app | p2 | same | [given] |
| Example group "Windows / Sysmon 31~50" (4625/4624, PtH, LSASS …) | p2 | missing | No Windows endpoint [given]; `data.win.*` 0 hits [live] |
| Example group "통합 모듈 51~63": vulnerability, SCA, Rootcheck, VirusTotal, ClamAV, agents, Active Response, Suricata, MITRE, osquery | p3 | mixed | Active Response missing [given]; agents missing (single `xoc-manager`) [live]; VirusTotal field 0 hits [live]; Suricata/osquery/MITRE fields present [live]; vulnerability/SCA/Rootcheck/ClamAV unverified |
| Linux group 16~30 incl. FIM persistence, auditd | p2 | partly | auditd data present; `syscheck.*` 0 hits [live] |
| "공격자 VM 터미널 화면" as step ③ of every example | p4 | renamed -> external attacker VM (Ubuntu 26.04) | [given]; no in-lab attacker host |
| "합성 로그 90일" advanced part | p4 | unverified | Not in these six lessons |
| Host `bastion`, file `/var/log/auth.log` | manuscript table, code, fact/judgement table | renamed -> `office-pc01` (pending) | [given, not yet verified]; `location: "/var/log/auth.log"` 0 hits today [live] |
| Source `10.20.30.254` "xOC Range VM의 ext망 주소" | manuscript table ×3, code | unverified | ext net 10.20.30.0/24 is the same [given]; whether .254 is the host's address there, and whether SSH to the office PC shows it as source, is not known |
| Account `book03_probe` (non-existent user used for the probe) | manuscript | same | Learner-chosen string; depends on section 2.2, outside my lessons |
| Rule 5710 level 5; follow-ups 5760, 5715 | manuscript | same | All three exist [live]. 5710 fires today only from the synthetic `xoc-native-probe` |
| Index `wazuh-alerts-4.x-2026.11.01`, `_id WfiPlaEBEYWT20nnUNlQ` | manuscript table, code | same (pattern) | Naming `wazuh-alerts-4.x-*` same [given]; the specific document is old-lab evidence and will not exist |
| Time "11월 1일 14:22:35 (KST)" | manuscript | unverified | Core access-log sample is stamped `+0000` [live]; host time zone of the future office PC unknown |
| File `examples/rev01/chapter02/investigation.txt` | manuscript prose | missing | Book-repository path; not present under the course directory |
| Cross-references to sections 1.7, 1.8, 2.1, 2.2, chapter 3 | manuscript prose | unverified | Section numbers of the source book, not lesson names |
| Presenter line "사이버보안과 · Dooyong Jeon", title "해킹과침해대응" | p1 | n/a | Source-deck identity, not environment |

### Command blocks
None.

### Query blocks
None. (The worked record implies `rule.id 5710` on `bastion`; see linux-basics.)

### Images
1 total (manuscript `assets/illustrations/chapter02/evidence.png`, illustration). Screenshots of old environment (`screens`): **0**. Diagrams/illustrations: 1.

### Blocking gaps
- None that stop the lesson: it is reading only. The worked case (bastion, 10.20.30.254, 2026-11-01 document id) is old-lab evidence and must be re-captured on `office-pc01` once that host is verified.
- Course map advertises Windows 31~50 and Active Response/VirusTotal/agent examples that Core cannot serve.

---

## 2. `discover` — Discover에서 기록 찾기 (slides p5–19; manuscript 3.2)

**Summary.** The learner logs in to the Wazuh Dashboard, opens Explore → Discover, picks `wazuh-alerts-*`, sets a time range, types DQL, adds columns, reads Top 5, expands a document (Table/JSON) and saves a search.

### Environment assumptions

| Item | Where | Status | Note |
|---|---|---|---|
| Dashboard URL `https://<xOC Range 호스트>:5601` | slide p6 | renamed -> `https://<core>/siem/` | [given] |
| Self-signed certificate warning | p6 | unverified | Core ingress certificate type not checked |
| Login "계정은 강사가 안내"; screenshot shows user `admin` | p6 + image [seen] | unverified | Core learner credentials not checked |
| Menu ☰ → Explore → Discover | p5, p7, p8, manuscript | unverified | Wazuh 4.14 dashboard menu not opened by me |
| Index pattern `wazuh-alerts-*` | p5, p9, manuscript | same | [given]; data present [live] |
| Index pattern `wazuh-archives-*` | p5, manuscript table | unverified | Index exists [given], but the helper returned 0 documents for every window [live]; whether the Dashboard pattern exists is not checked |
| `wazuh-monitoring-*` "에이전트 연결 상태, 매니저 통계, 취약점 상태" | manuscript table; screenshot also lists `wazuh-states-vulnerabil…`, `wazuh-statistics-*` [seen] | unverified | With no agents, agent-connection data is at best trivial |
| "wazuh-archives-* = 에이전트가 보낸 모든 기록 … xOC Range이 켜 둔다(2.3)" | manuscript | unverified | See archives result above; "에이전트가 보낸" wording does not fit Core (no agents) |
| `xoc-events-*` | not mentioned | missing from lesson | Core-only index the lesson never introduces |
| Field search example `srcip` | p13 | same | `data.srcip` 1,388 hits [live] |
| Top-5 example on `data.srcuser` (admin, nouser6, guest, test, oracle; source 192.168.0.202) | p15 image [seen] | missing (data) | `data.srcuser` exists only on 24 synthetic probe alerts [live] |
| JSON tab example `data.win.eventdata` | p18 | missing | 0 hits [live]; no Windows [given] |
| "커스텀 룰이 있는 환경이면 rule.id 대신 rule.description · rule.groups" | p5 | same | Core does have custom rules (e.g. 119672, 111201) [live] |
| "1.7의 수집기·서비스 상태", "2.3" | manuscript | unverified | Cross-references to other book sections |
| Save search / dashboard panel | p19 | unverified | Needs write permission for the learner account |

### Command blocks
None.

### Query blocks
None. (Slides tell the learner to "type DQL" but give no query here.)

### Images
16 total.
- Manuscript: 2, both under `assets/screens/chapter03/` (`menu.png`, `index-pattern.png`) → **2 old-environment screenshots by the `screens` rule**.
- Slides: 14 images with **no `path`** (only an asset hash and alt "교재 N페이지 예시 화면"). They are slide-deck screen captures of the old Dashboard; by the `screens`-path rule they count as 0, but in substance all 14 are old-environment screenshots (p6 login and p15 Top-5 opened and confirmed [seen]; p15 shows old-lab values `192.168.0.202`, `nouser6`).
- Diagrams/illustrations: 0.

### Blocking gaps
- Dashboard address (`:5601` → `/siem/`).
- `wazuh-archives-*` usability is unconfirmed.
- Every one of the 16 pictures is an old-lab capture; the p15 and p18 examples show data kinds (ssh user names, Windows event data) Core does not produce today.

---

## 3. `dql` — DQL 문법과 검색 필드 (slides p20–33; manuscript 3.4)

**Summary.** The learner learns eight DQL forms, escaping and field-type pitfalls, the ten common fields, creates the `wazuh-archives-*` index pattern in Dashboards Management, and runs a first query filtering by agent name.

### Environment assumptions

| Item | Where | Status | Note |
|---|---|---|---|
| `agent.name: "xocrange-host"` (the VM's own agent) | Q03-01 | renamed -> `xoc-manager` (but then filters nothing) | 0 hits for `xocrange-host`; `xoc-manager` is 100 % of alerts [live] |
| Screenshot of that query literally shows `agent.name: "kt66-host"` | manuscript image `assets/screens/chapter03/query.png` [seen] | missing | Also shows the internal code name on a learner screen |
| `agent.name` / `agent.ip` = "이벤트가 발생한 호스트" | slide p25 | missing (concept) | Single agent; `agent.ip` 0 hits [live]. Source is told apart by `location` suffix in Core [given, confirmed live] |
| `NOT agent.name:test` | p20 | same (syntax example) | Harmless; matches everything |
| `rule.id:5712`, `rule.id:(5710 or 5712 or 5720)`, `"5710"`, `"5760"` | p20, manuscript table | same | Rules exist [live]. Only 5710 has data (synthetic probe) |
| `rule.level >= 10`, `>= 12` | p20, manuscript table | same | Works, but returns ~19.7 k alerts/day, mostly Sysmon rule 111201 [live] |
| `data.url:*union*` | p20 | same (field) | Field exists; this exact lowercase pattern returned 0 because Core samples have `UNION` [live] |
| `rule.description:"authentication failed"` | p21 | same | Rules 5716/5760 exist; 0 hits today (no real sshd source) [live] |
| `data.srcip:*` | p21, manuscript table | same | 1,388 hits [live] |
| `*CurrentVersion\\\\Run*`, `C:\\Windows\\Temp`, double-backslash rule | p21, p22 | missing | Windows only |
| "원본 61개 중 6개(01·02·03·07·08·45)" | p22 | unverified | Statement about the old verification run |
| keyword fields `rule.id, rule.description, data.url, data.id, data.srcip, data.win.*, syscheck.path` | p23 | partly | `data.win.*`, `syscheck.path` 0 hits [live]; mapping types not checked |
| numeric `data.ip_reputation`; keyword `logonType`, `virustotal.positives` | p23 | missing | 0 hits [live] |
| Dev Tools `GET wazuh-alerts-*/_mapping/field/rule.description` via "Indexer management → Dev Tools" | p24 | unverified | Learner-role access to Dev Tools in Core not checked |
| `data.srcuser`, `data.dstuser` (SSH, sudo, PAM) | p25 | unverified -> pending `office-pc01` | `data.dstuser` 0 hits; `data.srcuser` probe-only [live] |
| `data.protocol`, `data.url`, `data.id` (Apache/Nginx) | p25 | same | 803 / 803 / 1,364 hits [live] |
| `full_log` | p25 | same | present [live] |
| `rule.mitre.id`, `rule.groups` | p25 | same | present [live] |
| `syscheck.path`, `syscheck.event` (FIM) | p26 | missing | 0 hits [live] |
| `data.win.system.eventID`, `.channel`, `data.win.eventdata.*` | p26 | missing | 0 hits [live] |
| `data.audit.*` | p26 | same | present [live] |
| `GeoLocation.country_name` | p26 | missing | 0 hits [live]; lab sources are private addresses |
| Archive index pattern creation: ☰ → Dashboards Management → Index patterns → Create → `wazuh-archives-` → time field `timestamp` | p27–32 | unverified | Needs learner permission to create patterns; may already exist in Core; archives returned 0 docs via helper [live] |
| "4648 · 4104 · Sysmon 10/13 처럼 기본 룰이 없는 이벤트" as the reason for archives | p27 | missing | Windows only |
| "취약 웹앱 7종 + Wazuh 4.10" | p33 | renamed -> 2 apps (dvwa, juiceshop), 4.14 | [given] |
| "공격자 VM 192.168.0.202 + xOC Range 내부 공격 컨테이너" | p33 | 192.168.0.202 renamed -> external attacker VM; internal attack container missing | [given] |
| "61개 전부 xOC Range 에서 실행·검증 (2026-10-31)" | p33 | missing (claim) | True for the old lab only |
| `github.com/mrgrit/xOC Range` | p33 | missing | Broken by a blind name replacement; not a valid URL |
| rsyslog "message repeated 5 times" lines lack `data.srcip` | manuscript box | unverified -> pending `office-pc01` | Needs a real rsyslog auth.log source |
| "1.7에서 확인한 xOC Range VM의 수집기 이름" | Q03-01 syntax text | renamed | Collector name is `xoc-manager` |
| "hits는 세 조건을 만족한 기록의 건수" | Q03-01 result text | n/a | Refers to conditions from the preceding book section (index, time range) |

### Command blocks
None.

### Query blocks

| Id | Where | Index | Fields / rules | Returns data in Core? |
|---|---|---|---|---|
| Q03-01 | "Windows · Discover 검색창" | wazuh-alerts-* | `agent.name: "xocrange-host"` | **No — 0 hits** [live]. Must become `agent.name: "xoc-manager"` (returns everything, so it no longer teaches filtering) or be rewritten on `location`. Its screenshot must be redone |

Slide-only example queries (not `query` blocks): `rule.id:5712` (rule exists, no data), `rule.level >= 10 AND NOT agent.name:test` (data, very noisy), `rule.id:(5710 or 5712 or 5720)` (5710 probe data), `data.url:*union*` (field ok), `rule.level >= 12`, `rule.description:"authentication failed"` (no data yet), `data.srcip:*` (data), `*CurrentVersion\\\\Run*` (Windows, no data).

### Images
7 total.
- Manuscript: 1 under `assets/screens/chapter03/query.png` → **1 old-environment screenshot** (shows `kt66-host` [seen]).
- Slides: 6 pathless slide captures (p27–32, index-pattern creation) — old Dashboard screenshots in substance.
- Diagrams/illustrations: 0.

### Blocking gaps
- The only query block, Q03-01, returns nothing: the per-device agent model it teaches does not exist.
- Windows-specific material (double backslash, `data.win.*`, 4648/4104) has no data source.
- FIM (`syscheck.*`), GeoLocation, VirusTotal, ip_reputation fields have no data.
- Archive index pattern steps are unconfirmed (permission, pre-existence, and whether archives hold data).

---

## 4. `infrastructure` — 실습 인프라와 수집 경로 (slides p34–46; manuscript 4.1)

**Summary.** The learner studies the lab map: components, addresses, who ships logs how, time synchronisation, what was fixed during verification, five lab-specific searches, and (manuscript) the path bastion auth.log → Agent → Manager → Filebeat → Indexer → Discover. Reading plus five searches; no command blocks.

### Environment assumptions

| Item | Where | Status | Note |
|---|---|---|---|
| Attacker VM `192.168.0.202`, `ssh att@192.168.0.202` | p34, p36 | renamed -> external attacker VM | [given]; Core sample shows client 192.168.16.99 [live] |
| Attacker tools nmap · hydra · sqlmap · nikto · gobuster | p34 | partly missing | nmap present; hydra, sqlmap, nikto, gobuster missing [given] |
| `fw` 10.20.30.1, nftables router/DNAT, drops to kernel log | p34 | same | [given]; `location: *nftables` 0 alerts in 7 days [live] |
| `ips` 10.20.31.2, Suricata inline | p34 | same | [given] |
| Suricata local rules "sid 1000001~5" | p34 | unverified | Only sid 1000001 seen [live] |
| `web` 10.20.32.80, Apache + ModSecurity CRS | p34 | same | [given] |
| "웹앱 7종" juice · dvwa · neobank · govportal · mediforum · adminconsole · aicompanion | p34, p35 | 5 missing | Only dvwa and juiceshop [given] |
| Names `*.ccc.com` | p35, p36 | renamed -> `dvwa.xoc.range`, `juice.xoc.range` (+ `dvwa.<domain>`) | [given] |
| `siem` 10.20.32.100 · `:5601`, Wazuh 4.10 | p35 | address unverified; port renamed -> `https://<core>/siem/`; version -> 4.14 | [given] |
| bastion SSH on `:2204` | p36, p38 | renamed -> `ssh -p 2222 student@<core>` to `office-pc01` | [given, not yet verified] |
| Six agents: web · ips · fw · bastion · xocrange-host · windows-user | p36 | missing | Single `xoc-manager` (id 000) [live]; `office-pc01` agent pending |
| `attacker` container, rsyslog 514 shell-command log, rules 100260/100261 | p36, p39, p40, p45 | missing | Rules absent [live]; no in-lab attacker [given]; `data.command`, `data.cmd_host` 0 hits; `rule.groups: cmdlog` 0 [live] |
| Windows RDP lab `ssh -p 2202 ccc@192.168.0.189` | p36 | missing | No Windows [given] |
| "외부에서 온 공격은 data.srcip 가 192.168.0.202" | p36 | renamed -> real client address | `data.srcip 192.168.16.99` in sample [live] |
| web agent 4.10.1: per-site `*_access.log`, `*_error.log`, `modsec_audit.log`(JSON), real-time FIM, ClamAV log | p37 | renamed -> `location` suffixes `/apache-access`, `/apache-error`, `/modsecurity` | [given + live]; FIM and ClamAV: no data / unverified |
| Search fields `agent.name:web`, `data.srcip`, `data.url`, `data.id`, `syscheck.path` | p37 | `agent.name:web` missing; web fields same; `syscheck.path` missing | [live] |
| ips agent: eve.json, syslog, FIM, command log; `agent.name:ips`, `data.alert.signature`, `data.src_ip` | p37 | `agent.name:ips` missing -> `location` ends `/suricata`; fields same | 104 hits [live] |
| fw agent: syslog, FIM, command log; host `xocrange-perimeter` writes DROP log; `agent.name:fw`, `data.command` | p38 | missing / renamed -> `location` ends `/nftables` | 0 nftables alerts, `data.command` 0 [live] |
| bastion: agent 4.10.1, auth.log (sshd·sudo) + FIM + Active Response; `agent.name:bastion`, `data.srcip/srcuser/dstuser` | p38 | renamed -> `office-pc01` (pending); Active Response missing | [given] |
| `xocrange-host` Linux endpoint: agent + auditd + Sysmon for Linux + osquery, kern.log | p39 | renamed -> `xoc-manager` with `location` `/auditd`, `/sysmon`, `/osquery` | Data present for all three [live] |
| `data.audit.*`, `data.osquery.*` | p39 | same | 1,203 / 79,354 hits [live] |
| Windows 11 `10.20.70.10`, agent `windows-user`, Sysmon, osquery, Defender off | p40 | missing | No Windows [given]. **Address clash: 10.20.70.0/24 is now the planned office network (`office-pc01` = 10.20.70.21)** |
| Manager-only rules 100260, 100261, 119660~119663 ("시설 이벤트") | p40, p45 | missing | None exist [live]. Core uses nearby custom ids for other things (119672 ModSecurity, 111201 Sysmon) [live] |
| `xocrange-ntp` container, chrony, 10.20.32.123; attacker VM → 192.168.0.189:123; Windows w32time | p41, p42 | missing | No NTP container [given] |
| "모든 장비 시간대 Asia/Seoul(KST)" | p42 | unverified, likely different | Core Apache access log sample is stamped `+0000` [live] |
| Check commands `timedatectl timesync-status`, `sudo docker exec xocrange-ntp chronyc sources`, `w32tm /query /source` | p42 (slide text, not command blocks) | host missing | No NTP container, no Windows; learners have no Core host shell |
| "bastion SSH: sshd 가 stderr 로만 … → auth.log + 에이전트(4.10)" and other fix history | p43 | missing (history) | Describes the old lab's repair log |
| ClamAV · VirusTotal · Active Response added | p43 | Active Response missing; VirusTotal no data; ClamAV unverified | [given]/[live] |
| "에이전트 끊김 판정 60초" | p44 | missing | No agents |
| "원본 61개 중 22개를 고침 … xOC Range 주소 대역 4" | p44 | missing (claim) | Old-lab verification statistics |
| ModSecurity audit log "기본 룰이 없어 알림이 안 뜸 → wazuh-archives-* 에서 검색" | p46 item 1 | **changed** | In Core, `/modsecurity` produces alerts (1,608 hits, rule 119672) [live]; the "go to archives" instruction is no longer true, and archives returned 0 docs via helper |
| FIM on /etc/shadow, /etc/sudoers, /var/spool/cron, /usr/bin, /var/log | p46 item 2 | missing | `syscheck.*` 0 hits [live] |
| Active Response 5712 · 5763 → `firewall-drop` 180 s | p46 item 4 | missing | Rules exist [live]; no Active Response [given] |
| Windows auto-install script | p46 item 5 | missing | — |
| Manager runs in `xocrange-siem` container | manuscript | renamed -> `xoc-core-security-path-siem-1` | [given] |
| Filebeat ships `alerts.json` / `archives.json` to Indexer, inside the Manager container | manuscript | unverified | Core's shipping mechanism not inspected |
| bastion `/var/log/auth.log`, bastion agent `ossec.conf` | manuscript table | renamed -> `office-pc01` (pending) | Agent `ossec.conf` on the office PC unverified |
| "Ruleset Test", Manager decoder/rule files | manuscript table | unverified | Dashboard Ruleset Test availability for learners not checked |
| Sections 4.2–4.11 | manuscript | unverified | Book cross-references |

### Command blocks
None (`command` type). The three p42 lines above are slide text: none can run in Core.

### Query blocks
None (`query` type). Slide p45 "전용 검색 5개":

| Slide query | Index | Fields / rules | Returns data in Core? |
|---|---|---|---|
| `rule.groups:cmdlog AND data.cmd_host:attacker` | alerts | group cmdlog, `data.cmd_host` | No — group and field absent [live] |
| `rule.id:100261` | alerts | 100261 | No — rule missing [live] |
| `rule.id:100261 OR rule.groups:attack OR data.alert.signature:xOC Range*` | alerts | 100261, group attack, `data.alert.signature` | Partly — only `rule.groups:attack` (655). The signature term is a damaged replacement (unquoted space; Core signature is `xOC inline verification marker`) |
| `agent.name:ips AND data.alert.signature:xOC Range*` | alerts | `agent.name`, `data.alert.signature` | No — `agent.name:ips` 0 hits; needs `location` ending `/suricata` and a real signature prefix |
| `rule.id:(119660 or 119661 or 119662 or 119663)` | alerts | 119660–119663 | No — rules missing [live] |

### Images
2 total, both manuscript figures (`assets/figures/chapter04/collection-path.png`, `storage.png`). Screenshots (`screens`): **0**. Diagrams: 2. `collection-path.png` names `bastion /var/log/auth.log → Agent → Manager → Filebeat → Indexer → Discover` [seen] and must be redrawn; `storage.png` is environment-neutral [seen].

### Blocking gaps
- The whole "six agents" collection model (p36–40) is absent; every `agent.name:<device>` search field is wrong.
- All five lab-specific searches on p45 fail or degrade (missing rules 100260/100261/119660–3, no attacker command log).
- Five of seven web apps, Windows 11, NTP container, attacker container, Active Response, FIM: not in Core.
- Time-zone claim (all KST) contradicts the observed `+0000` log stamps.
- p46 item 1 teaches the opposite of Core behaviour for ModSecurity.
- Slides p41–44, p46 are a change log of the old lab, not a description of Core.

---

## 5. `linux-basics` — 리눅스 인증·권한·로그 기초 (slides p200–203; manuscript 8.1 준비와 정상 접속)

**Summary.** The learner opens two terminals (lab host and attacker VM), inspects the `bastion` container (sshd settings, root lock, agent status, auth.log), prepares Hydra on the attacker VM, makes one normal SSH login to bastion, reads the `Accepted password` line and finds the matching alert (rule 5715) in Discover.

### Environment assumptions

| Item | Where | Status | Note |
|---|---|---|---|
| Learner workstation is Windows with terminal + browser | table, all `where` values | unverified | Not a Core property; the wording is baked into every block |
| Dashboard `https://192.168.0.107:5601` | manuscript table, prose | renamed -> `https://<core>/siem/` | [given] |
| Dashboard login `admin / (이전 환경 비밀번호)` | manuscript prose | unverified | A credential written in course text; Core credentials not checked |
| Lab host `192.168.0.107:22`, account `ccc / 1` (host shell with docker) | table, C08-01..03 | missing for learners | Core host shell is not a learner surface; address differs. Password printed in content |
| Attacker VM `192.168.0.108:22`, account `att / 1` | table, C08-06 | renamed -> external attacker VM | [given]; account name on the new VM unverified. Note slides elsewhere say 192.168.0.202 — the course is internally inconsistent |
| `xocrange-bastion` container, published `192.168.0.107:2204` → 22, account `ccc / ccc` | table, C08-02, C08-03, C08-11, figure | renamed -> `office-pc01`, `ssh -p 2222 student@<core address>` | [given, not yet verified]; container name would follow `xoc-core-security-path-<service>-1` (exact service name unverified) |
| `xocrange-siem` container | table, C08-02 | renamed -> `xoc-core-security-path-siem-1` | [given] |
| "xOC Range 내부 attacker 컨테이너와 별개" | prose | missing | No in-lab attacker [given] |
| "Docker는 2204번 포트로 온 연결을 bastion의 22번으로 전달" | prose, figure | renamed | New path is via ingress/fw/IPS to the office network on port 2222 [given, unverified] |
| rsyslog writes `/var/log/auth.log` on the target | prose, C08-05, C08-14 | same (pending) | Planned for `office-pc01` [given, unverified] |
| Wazuh agent on the target reading auth.log via `localfile` | prose | same (pending) | Agent `office-pc01` planned [given]; 0 alerts from it today [live] |
| `agent.name` = `bastion` | table, Q08-01 | renamed -> `office-pc01` | 0 hits for both today [live] |
| `agent.ip` = `10.20.30.201` | table | renamed -> 10.20.70.21 (expected) | `agent.ip` has 0 hits today [live]; value unverified |
| `data.srcip` = `192.168.0.108` (attacker VM) | table, code, C08-14 | unverified | Whether the office PC sees the real client or a NAT address through fw/IPS is not known |
| `location` = `/var/log/auth.log` | table, Q08-01 | unverified | Will be true only if a real agent ships the file; Core-native sources use `xoc-native/<hash>/<kind>` [live] |
| Host-key check: `/etc/ssh/ssh_host_ed25519_key.pub` on each VM via "VMware 콘솔" | prose | missing | VMware console is not part of Core |
| `/var/lib/bastion/ssh-host-keys/ssh_host_ed25519_key.pub` | C08-12 | missing | bastion-specific path; office PC key path unverified |
| sshd settings `port 22, permitrootlogin no, passwordauthentication yes, maxauthtries 6` | C08-04 | unverified | office PC sshd config not checked |
| root password state `L`, `/etc/shadow` permissions | C08-05 | unverified | Needs root on the target |
| `/var/ossec/bin/wazuh-control status` on the target | C08-05 | unverified | Needs root on the target and an installed agent |
| Root shell on the target via `docker exec` | C08-03, -04, -05, -12, -14 | missing for learners | Learner has `student` + sudo (per brief) but no `docker exec` from the Core host |
| Hydra on attacker VM; `sudo apt-get install -y hydra`; "Hydra 9.2" | C08-07, C08-08, slide p203 | missing | Not installed [given]; install needs internet + sudo on the attacker VM (unverified) |
| `~/book08`, `/home/att/book08` | C08-09, C08-10 | renamed | Home directory depends on the attacker VM account |
| `ssh -p 2204 -o HostKeyAlgorithms=ssh-ed25519 ccc@192.168.0.107` | C08-11 | renamed -> `ssh -p 2222 student@<core address>` | Ed25519 host key on office PC unverified |
| Expected identity `bastion`, `ccc`, `uid=1000(ccc)`, sudo·docker groups | C08-13 | renamed -> `office-pc01`, `student` | uid/groups unverified |
| Log line `Nov  2 20:28:12 bastion sshd[2445]: Accepted password for ccc from 192.168.0.108 port 51380 ssh2` | code block | renamed | Host/user/address change |
| Slide log line `Oct 31 16:03:31 bastion sshd[947]: Failed password for invalid user nouser6 from 192.168.0.202 …` | slide p202 | renamed | Note 192.168.0.202 here vs .108 in the manuscript |
| Rules 5710, 5712, 5763, 5715, 60204 | slides p201–203, Q08-01 result, table | same (60204 has no data source) | All exist [live]; 5715 0 hits today; 60204 is Windows |
| Decoder `sshd`, `predecoder.program_name`, `decoder.name`, `data.dstuser`, `data.srcip`, `data.srcport`, `data.srcuser`, `full_log` | slides, manuscript table | same (decoder); data pending | Fields populated only by the synthetic probe today; `data.dstuser` 0 [live] |
| FIM `syscheck.*`, auditd `data.audit.*` | slide p200 | syscheck missing; audit same | [live] |
| Active Response / fail2ban as defence | slide p203 | missing | [given] |
| Index `wazuh-alerts-*`, Absolute time range, Refresh | prose | same | — |
| Reference window "KST 2026-11-02 20:25~21:00", JSON `11:38:05+0000` = screen `20:38:05` | prose | unverified | Depends on browser time zone and office PC time zone |
| Sections 1.9, 2.4, 8.5, 8.10 | prose | unverified | Book cross-references |

### Command blocks (14)

| Id | Where | Tool | Runs as-is in Core? |
|---|---|---|---|
| C08-01 | Windows · 터미널 | ssh (`ccc@192.168.0.107`) | **host missing** — learners do not get the Core host shell; address/account differ |
| C08-02 | xOC Range VM · ccc 호스트 셸 | docker ps, docker port `xocrange-bastion` | **host missing** + needs rename (container `xoc-core-security-path-…`) |
| C08-03 | xOC Range VM · ccc 호스트 셸 | docker exec -it `xocrange-bastion` | **host missing** + needs rename |
| C08-04 | xocrange-bastion · root 셸 | hostname, `sshd -T`, grep | **needs rename** (office-pc01); needs root via `sudo` — unverified |
| C08-05 | xocrange-bastion · root 셸 | passwd -S, ls, `wazuh-control status`, tail auth.log | **needs rename**; root needed — unverified |
| C08-06 | Windows · 별도 터미널 | ssh (`att@192.168.0.108`) | **needs rename** (external attacker VM address/account) |
| C08-07 | 공격자 VM · att 셸 | command -v ssh / hydra | yes for ssh; **tool missing** for hydra (prints nothing) |
| C08-08 | 공격자 VM · att 셸 | apt-get install hydra, hydra -h | **tool missing** — would install it; needs sudo + internet on the attacker VM (unverified) |
| C08-09 | 공격자 VM · att 셸 | ls -ld ~/book08 | yes |
| C08-10 | 공격자 VM · att 셸 | mkdir, cd, pwd | yes (expected output path changes with the account) |
| C08-11 | 공격자 VM · att 셸 | ssh -p 2204 … `ccc@192.168.0.107` | **needs rename** -> `ssh -p 2222 student@<core address>` (pending verification) |
| C08-12 | xocrange-bastion · root 셸 | ssh-keygen -lf `/var/lib/bastion/ssh-host-keys/…` | **host missing / path missing** — needs an out-of-band shell on the target and the office PC's key path |
| C08-13 | xocrange-bastion · SSH로 접속한 ccc 셸 | hostname, whoami, id, exit | **needs rename** (expected output: office-pc01 / student) |
| C08-14 | xocrange-bastion · root 셸 | tail -n 20 /var/log/auth.log | **needs rename**; reading auth.log needs sudo/adm — unverified |

Structural note: the old lesson keeps a second, privileged "management" shell (docker exec root) open beside the attacker session. Core gives the learner one SSH account on the target; C08-04/05/12/14 need either `sudo` inside that session or a second `ssh` session.

### Query blocks (1)

| Id | Where | Index | Fields / rules | Returns data in Core? |
|---|---|---|---|---|
| Q08-01 | Windows · Discover · wazuh-alerts-* | wazuh-alerts-* | `agent.name: "bastion" AND location: "/var/log/auth.log"`; expects rule 5715, then columns `rule.id`, `data.srcip`, `data.dstuser`, and `full_log`, `decoder.name`, `location` | **No today — 0 hits** for each term [live]. Rule 5715 exists. `agent.name` must change to `office-pc01`; works only once that agent ships auth.log (unverified). `data.dstuser` has no data at all yet |

### Images
1 total: manuscript figure `assets/figures/chapter08/collection.png`. Screenshots (`screens`): **0**. Diagrams: 1 — and it is environment-specific: it reads "공격자 VM .108 · SSH → **kt66 VM** .107:2204 → bastion:22 → auth.log 에이전트 수집 → Wazuh → Windows Discover" [seen]. Must be redrawn; it also shows the internal code name.

### Blocking gaps
- No SSH target with a real sshd + auth.log + agent exists in verified Core today (`office-pc01` pending). Without it nothing in 8.1 produces data.
- No learner access to the Core host shell / `docker exec`: C08-01..03 and the root-shell commands need redesign.
- Hydra is not on the attacker VM.
- Q08-01 filter (`agent.name: "bastion"`) returns nothing.
- Host-key verification procedure depends on VMware console and a bastion-only file path.

---

## 6. `web-basics` — 웹 요청·로그·WAF 기초 (slides p47–51; manuscript 5.1 웹 요청이 지나가는 길)

**Summary.** The learner reads how an HTTP request becomes an Apache access-log line and Wazuh fields, what the WAF (ModSecurity + CRS) does in blocking versus detection-only mode, and which log holds what. Reading only.

### Environment assumptions

| Item | Where | Status | Note |
|---|---|---|---|
| Decoder `web-accesslog` → `data.srcip`, `data.protocol`, `data.url`, `data.id` | p47, p49 | same | All four present on `/apache-access` alerts [live] |
| User-Agent only in `full_log` | p47 | same | Sample full_log contains `"curl/8.18.0"` [live] |
| Rule 31108 level 0 ("정상 200 은 alerts 에 없다") | p49 | same | Exists, level 0 [live] |
| Wazuh web rules 311xx | p51 | same | 31101, 31103, 31106 exist [live] |
| Sample line `192.168.0.202 … [31/Oct/2026:16:57:17 +0900] "GET /vulnerabilities/xss_r/?name=%3Cscript%3E HTTP/1.1" 403 457 "-" "curl/7.81.0"` | p49 | renamed | Core line has real client address, `+0000` time zone, and a trailing ` xoc_id=<id>` field after the User-Agent [live]. The "⑧ fields" annotation needs a ninth item |
| WAF = Apache + ModSecurity + OWASP CRS, anomaly threshold 5, rule 949110, families 942/941/930/932/913 | p50 | same (stack); details unverified | Stack [given]; threshold and CRS version not checked |
| `SecRuleEngine On` for "dvwa·neobank 등" | p50 | dvwa same; neobank missing | [given] |
| `SecRuleEngine DetectionOnly` for juice — "공격이 성공하는 모습" | p50, p51 | **missing** | Both targets are in blocking mode [given]; live sample: Juice Shop path `/rest/products/search?q=1+UNION+SELECT+1--` → 403 [live] |
| `juice.ccc.com → HTTP 200 → 11번 실습 31106` | p51 | missing | `rule.id: "31106"` 0 hits in 7 days [live]; rule exists |
| `dvwa.ccc.com → 403` | p51 | renamed -> `dvwa.xoc.range` | [given] |
| Per-site `*_access.log`, `dvwa_access.log`, `error.log`, `modsec_audit.log` (JSON) | p51, manuscript, figure | renamed -> `location` `/apache-access`, `/apache-error`, `/modsecurity` | File names inside the Core web container not checked |
| "감사 로그 … 기본 룰셋엔 룰이 없어 wazuh-archives 에서 본다" | p51 | **changed** | Core alerts on it: rule 119672 "ModSecurity JSON request blocked by WAF", 1,608 hits; apache-error ModSecurity lines alert as 30411 [live] |
| `xocrange-dvwa` container | manuscript | renamed -> `xoc-core-security-path-dvwa-1` | [given] |
| `xocrange-web` container | manuscript ×3 | renamed -> `xoc-core-security-path-web-1` | [given] |
| "xocrange-web의 Wazuh 에이전트(이름 web)" | manuscript, figure | missing | No per-device agent; `agent.name: "web"` 0 hits [live] |
| CRS in blocking mode in front of DVWA | manuscript | same | [given] |
| Client "Windows PC 브라우저" | figure | unverified | Learner workstation assumption |
| HTTP methods, status codes, URL-encoding table | p48 | same | Environment-neutral |

### Command blocks
None.

### Query blocks
None.

### Images
2 total, both manuscript figures (`assets/figures/chapter05/request-log-path.png`, `rev01-reach.png`). Screenshots (`screens`): **0**. Diagrams: 2. `request-log-path.png` reads "Windows PC → **kt66 진입** fw · ips → web Apache · WAF → DVWA; web의 Agent → Wazuh Manager" [seen] — wrong collection model and shows the internal code name. `rev01-reach.png` names `dvwa_access.log` and `modsec_audit.log` [seen].

### Blocking gaps
- The blocking-versus-detection contrast (dvwa 403 vs juice 200, rule 31106) cannot be shown: no detection-only target.
- "ModSecurity audit log is only in archives" is false in Core.
- "web agent" collection model and one diagram must be replaced.

---

## Cross-lesson summary of gaps (ordered by number of lessons affected)

| # | Gap | Lessons affected | Evidence |
|---|---|---|---|
| 1 | **Per-device Wazuh agents do not exist.** Everything is `agent.name: xoc-manager`; `agent.ip` is empty. Every `agent.name:<device>` filter, the "six agents" table and three diagrams are wrong. Both `query` blocks in these lessons (Q03-01, Q08-01) return 0 | 5: orientation (course map), dql, infrastructure, linux-basics, web-basics | [live] |
| 2 | **`bastion` SSH host is gone**; replacement `office-pc01` (port 2222, `student`) is not yet verified. All sshd/sudo fields (`data.dstuser`, `data.srcuser`, `location: /var/log/auth.log`, rules 5715/5760/5712/5763) have no real data today — only a synthetic 5710 probe | 4: orientation, dql, infrastructure, linux-basics | [live] + [given] |
| 3 | **Old addresses, names and versions**: `192.168.0.107/.108/.202/.189`, `:5601`, `:2204`, `*.ccc.com`, `xocrange-<svc>` containers, Wazuh 4.10, accounts `ccc/1`, `att/1`, `ccc/ccc`, `admin/(이전 환경 비밀번호)` | 5: discover, dql, infrastructure, linux-basics, web-basics | [given] |
| 4 | **No Windows endpoint**: `data.win.*`, double-backslash escaping, 4648/4104, 60204, RDP, w32time. Also the old Windows address 10.20.70.10 sits inside the new office network 10.20.70.0/24 | 5: orientation, discover, dql, infrastructure, linux-basics | [live] + [given] |
| 5 | **Pictures are old-lab captures.** 29 images in total: 3 with a `screens` path, 20 pathless slide captures of the old Dashboard, 5 figures, 1 illustration. Three figures and one screenshot display the internal code name ("kt66 VM", "kt66 진입", `kt66-host`) | 5: discover (16), dql (7), infrastructure (2), linux-basics (1), web-basics (2) | [seen] |
| 6 | **Archives index unconfirmed.** Lessons send learners to `wazuh-archives-*` (and have them create the pattern); the helper returned 0 documents for every window | 4: discover, dql, infrastructure, web-basics | [live], cause not determined |
| 7 | **No Active Response, no FIM data, no VirusTotal/GeoLocation/ip_reputation** | 4: orientation, dql, infrastructure, linux-basics | [live] + [given] |
| 8 | **No in-lab attacker container / command log**; rules 100260, 100261 and 119660–119663 missing; attacker VM lacks hydra, sqlmap, nikto, gobuster | 3: dql (p33), infrastructure, linux-basics | [live] + [given] |
| 9 | **No learner host shell / `docker exec`**; privileged second shell on the target is assumed | 2: linux-basics (C08-01..05, -12, -14), infrastructure (p42 checks) | [given] |
| 10 | **Only 2 of 7 web apps; no detection-only target.** juice returns 403, so the "attack succeeded with 200" (31106) lesson point has no source | 3: dql (p33), infrastructure, web-basics | [live] + [given] |
| 11 | **ModSecurity guidance inverted**: Core raises alerts for the audit log (rule 119672) and error log (30411); lessons say "no rule, look in archives" | 2: infrastructure, web-basics | [live] |
| 12 | **Time zone / NTP**: lessons claim all-KST with an `xocrange-ntp` container; Core has no NTP container and its access log is stamped `+0000` | 3: orientation, infrastructure, linux-basics | [live] + [given] |
| 13 | **Damaged text from a blind name replacement**: `github.com/mrgrit/xOC Range`, `data.alert.signature:xOC Range*`, `xOC Rangeaudit`, `xOC Range이` | 2: dql, infrastructure (plus particles in most manuscripts) | read |
| 14 | **`rule.level >= 10` is flooded** (~19.7 k alerts/day, mostly Sysmon rule 111201), so the syntax examples that use it will not show attacks | 1: dql | [live] |

### Not checked (stated so nobody assumes it was)
- The Core Dashboard UI itself (menu names, pre-existing index patterns, learner permissions for Dev Tools, saved searches, Ruleset Test, creating index patterns).
- Anything about `office-pc01` beyond the brief; no alerts from it exist yet.
- Field mapping types (keyword vs text vs number) in Core.
- Whether the archives result is "empty index" or "helper cannot read it"; the `xoc-events-*` helper query failed on sort field.
- 18 of the 20 slide captures were not opened (only p6 and p15 were). Of the 9 manuscript images, 7 were opened; `menu.png` and `evidence.png` were not.
