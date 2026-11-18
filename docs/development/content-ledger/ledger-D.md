# Ledger D — Linux host cases (case-16 … case-23)

Porting the Wazuh threat-hunting courseware from the old kt66 lab to the current Core, now
with the office PC (`office-pc01`, 10.20.70.21, Ubuntu 26.04 container).

## Cross-cutting facts (apply to every lesson below)

- **Old host `bastion` / `xocrange-bastion` → new `office-pc01`.** Every lesson's SSH target,
  every `agent.name: "bastion"` query, and every "bastion root 관리 셸" work-where.
- **Old account `ccc` → `student`.** Home `/home/ccc` → `/home/student`. `ccc` has NOPASSWD sudo in
  the old lab; `student` has NOPASSWD sudo on the office PC (`/etc/sudoers.d/90-xoc-office`).
- **Old SSH port `2204` → `2222`** (host 2222 → firewall DNAT → IPS → PC:22).
- **Old target addresses `192.168.0.107` / `192.168.0.189` → the Core address.**
- **Old attacker address `192.168.0.108` → NOT visible.** Through the DNAT entry the PC sees every
  outside client as the ingress address **10.20.30.20**. All `data.srcip` on auth events become
  10.20.30.20; the real attacker address is gone. Any query keyed on `.108`, and any srcip-pivot
  that assumes a unique attacker IP, degrades to the shared ingress address.
- **`hydra` is NOT on the attacker VM** (has curl, nmap, ssh, python3, nc only). Every lesson that
  drives the attack with `hydra` (16, 17, 18) needs a rewrite to an ssh/python/nc loop, or hydra
  must be added to the attacker image.
- **No Active Response on the Manager** (ossec.conf verified: no `<active-response>`/`<command>`).
  The office PC has **no iptables** and sshd runs with NET_ADMIN dropped, so firewall-drop cannot
  run there anyway. Any "auto-block / 3-minute firewall-drop / rule 58" narrative is dead (case 16;
  mentioned in 17, 18).
- **FIM caveats on the office PC** (`components/office-pc/ossec.conf`): syscheck watches
  `/etc,/usr/bin,/usr/sbin,/home` **realtime, check_all**, but **no `report_changes="yes"`** →
  `syscheck.diff`, `size_before/after`, `sha256_before/after` content will be **absent**; and
  **no `whodata` and no auditd** → `syscheck.uname_after` (who changed the file) will be **absent**.
  Cases 22 and 23 depend on `syscheck.diff` and `syscheck.uname_after`.
- **All referenced rule IDs EXIST on the Core Manager** (verified via rule.sh):
  5710, 5712, 5715, 5716, 5720, 5760, 5763, 5401, 5402, 5403, 5901, 5902, 5903, 5904, 5555,
  550, 553, 554. Note the slide text in case 21 mislabels 5904 as "user delete" (5903 is delete,
  5904 is "changed user") — a content error, not an environment gap.
- **`agent.name` today = `xoc-manager` (id 000)** for all native sources; the office PC agent
  (`office-pc01`) is implemented but **not yet live** — live query `agent.name:"office-pc01"` = 0
  hits, `rule.groups:syscheck` = 0 hits, `rule.id:5715` = 0 hits. So every query is **unverified
  against real office-PC data**; it will only return data once the PC agent reports. When it does,
  `agent.name: "bastion"` must become `agent.name: "office-pc01"`.
- `where: Windows · Discover · wazuh-alerts-*` → Core Dashboard at `https://<core>/siem/`
  (no Windows). Index names unchanged (`wazuh-alerts-4.x-*`, `wazuh-archives-4.x-*`).

---

## case-16 — SSH 브루트포스 (8.2 동일 계정 암호 대입)

1. **Learner does:** from the attacker VM, runs hydra against `ccc` with 12 wrong passwords,
   then finds the individual + correlated SSH auth-failure alerts, inspects the repeated-failure
   correlation, and checks whether Active Response fired and auto-unblocked.

### Environment assumptions
| Assumption | Where | Status vs Core+office PC | Note |
|---|---|---|---|
| host `bastion`, SSH `:2204` at 192.168.0.107 | C08-15…17, slide p206 | renamed → office-pc01 `:2222`, Core addr | target host/port/addr all change |
| attacker VM has `hydra` | C08-16/17, slide p206 | missing | rewrite to ssh/python loop or add hydra |
| account `ccc` exists, wrong-password target | C08-16/17 | renamed → student | |
| `~/book08/` work dir on attacker VM | C08-15/16 | unverified | learner-created; fine |
| `agent.name:"bastion"` | Q08-02, Q08-03, slide p212 | renamed → office-pc01 | |
| rules 5760, 5763 (indiv + correlated fail) | Q08-02 | same | exist on Manager |
| rules 5712/5720/5763 (brute-force freq) | slides p204/207/212 | same | exist |
| `data.srcip` = attacker .108 | prose, Q08-02 | missing → 10.20.30.20 | shared ingress addr |
| `message repeated` rsyslog folding | C08-16 code, Q08-03 | unverified | rsyslog present on PC; behaviour not verified |
| Active Response firewall-drop (rule 58), 180s | prose [21], C08-18 | missing | no AR on Manager, no iptables on PC |
| `/var/ossec/logs/active-responses.log`, `iptables -S` on bastion root shell | C08-18 | missing | no AR log activity, no iptables binary |
| `auth.log` collection | prose | same | PC collects /var/log/auth.log |

### command blocks
| id | where | tool | runs in Core+office PC? |
|---|---|---|---|
| C08-15 | attacker VM att shell | cd/ls | yes |
| C08-16 | attacker VM att shell | printf/cat/wc | yes |
| C08-17 | attacker VM att shell | **hydra** | tool missing (rewrite / add hydra); also address+port rename |
| C08-18 | bastion root shell | tail active-responses.log, iptables -S | feature missing (no AR log, no iptables); host rename |

### query blocks
| id | index | fields / rule IDs | returns data in Core? |
|---|---|---|---|
| Q08-02 | alerts | agent.name, rule.id 5760/5763 | rules exist; needs agent.name→office-pc01; unverified (PC not live) |
| Q08-03 | alerts | agent.name, full_log "message repeated" | depends on rsyslog folding on PC; unverified |

5. **Images:** 3 total — 2 screenshots (`screens/5763-fields.png`; lesson.json `719db…`,`4f96…`,
   `abf2…`,`e4c7…`,`2b54…` = 6 more old-env screenshots on slides) + 1 diagram
   (`figures/correlation.png`). Counting both files: explanation has 1 screenshot + 1 diagram;
   lesson.json has 6 old-env example-screen captures. All screenshots are old environment.
6. **Blocking gaps:** hydra on attacker side; Active Response + iptables story has no equivalent
   (remove or rewrite); srcip no longer identifies the attacker; agent.name rename.

---

## case-17 — 없는 계정의 인증 시도 (8.3)

1. **Learner does:** tries three non-existent usernames over SSH (hydra `-L`), confirms with
   `getent` they don't exist, then finds the `Invalid user` (rule 5710) alerts and reads the
   account name from `data.srcuser`.

### Environment assumptions
| Assumption | Where | Status | Note |
|---|---|---|---|
| bastion root shell for `getent` | C08-19 | renamed → office-pc01 (via student sudo) | no root SSH; use `sudo getent` |
| attacker VM `hydra` (`-L`,`-p`) | C08-21, slide p215 | missing | rewrite / add hydra |
| host `:2204`@192.168.0.107 | C08-21 | renamed → :2222 / Core addr | |
| `agent.name:"bastion"` | Q08-04, slide p216 | renamed → office-pc01 | |
| rule 5710 (non-existent user), 5712 (freq) | Q08-04, slides | same | exist |
| `data.srcuser` holds the bad name | prose [8], slide p210/221 | same | decoder field, unchanged |
| `predecoder.hostname` column | slide p216 | unverified | on an agent, hostname = office-pc01 |

### command blocks
| id | where | tool | runs? |
|---|---|---|---|
| C08-19 | bastion root shell | getent | yes as `sudo getent` on PC (student) |
| C08-20 | attacker VM | printf/cat | yes |
| C08-21 | attacker VM | **hydra -L** | tool missing; rename addr/port |

### query blocks
| id | index | fields/rules | returns data? |
|---|---|---|---|
| Q08-04 | alerts | agent.name, rule.id 5710/5712 | rules exist; agent rename; unverified (PC not live). srcuser unaffected by ingress NAT |

5. **Images:** explanation 1 screenshot (`screens/5710-fields.png`). lesson.json 5 old-env
   example-screen captures. All old environment.
6. **Blocking gaps:** hydra; agent.name rename; root-shell step → student sudo.

---

## case-18 — 인증 실패 뒤의 성공 (8.4)

1. **Learner does:** three wrong passwords then the real password (hydra `-f`), logs in, then
   correlates the failures and the success for the same source on one timeline, pivoting on
   `data.srcip`; falls back to `wazuh-archives-*` auth.log for raw lines.

### Environment assumptions
| Assumption | Where | Status | Note |
|---|---|---|---|
| attacker VM `hydra` | C08-22/23, slide p224 | missing | rewrite / add hydra |
| host `:2204`@192.168.0.107/.189 | C08-23/24 | renamed → :2222 / Core | |
| account `ccc` + known lab password | C08-22/23/25 | renamed → student; pw via `xoc platform credentials` | |
| `agent.name:"bastion"` | Q08-05, Q08-06 | renamed → office-pc01 | |
| rules 5760, 5715 | Q08-05, slides | same | exist |
| `data.srcip:"192.168.0.108"` pivot | Q08-05, prose, slide p229 | missing → 10.20.30.20 | shared ingress; pivot degraded |
| **DQL `NOT data.srcip:10.20.*`** | slide p225 (p229 note) | **broken** | office-PC attacker now IS 10.20.30.20 → filter removes the very success it should show; 0 hits |
| `data.srcport` same across fail/success | Q08-06, prose [14] | unverified | should hold on the PC's sshd |
| archives `location:"/var/log/auth.log"`, `predecoder.program_name:"sshd"` | Q08-06 | same once PC logs | live archives query = 0 hits today |

### command blocks
| id | where | tool | runs? |
|---|---|---|---|
| C08-22 | attacker VM | printf/cat | yes |
| C08-23 | attacker VM | **hydra -f** | tool missing; rename |
| C08-24 | attacker VM | ssh | yes (rename port/addr) |
| C08-25 | office-pc01 via ccc→student SSH | hostname/whoami/id/exit | yes |

### query blocks
| id | index | fields/rules | returns data? |
|---|---|---|---|
| Q08-05 | alerts | agent.name, data.srcip .108, 5760/5715 | rules exist; srcip must change to 10.20.30.20; agent rename |
| Q08-06 | archives | agent.name, location auth.log, predecoder sshd | fine once PC logs; agent rename |

5. **Images:** explanation 2 screenshots (`success-fields.png`) + 1 diagram (`figures/timeline.png`).
   lesson.json 3 old-env captures. Screenshots all old.
6. **Blocking gaps:** hydra; the `NOT data.srcip:10.20.*` filter must be reworked (attacker is now
   inside 10.20.*); srcip no longer unique to attacker; agent.name rename.

---

## case-19 — root 직접 로그인 (8.5)

1. **Learner does:** instructor temporarily enables `PermitRootLogin yes` + sets a root password on
   bastion, logs in directly as root from the attacker VM, finds rule 5715 + `data.dstuser:root`,
   then restores sshd_config and /etc/shadow from backups and confirms root is refused again.

### Environment assumptions
| Assumption | Where | Status | Note |
|---|---|---|---|
| bastion root management shell | C08-26…39 | renamed → office-pc01; **no root SSH** | all root steps via `student` NOPASSWD sudo |
| `/etc/ssh/sshd_config`, `PermitRootLogin no` default | C08-26…32 | present on PC | PC default `PermitRootLogin no` in `sshd_config.d/10-xoc-office.conf` |
| editable sshd config + `service ssh reload` | C08-29/31/32/35 | partial | PC's sshd is PID1 `sshd -D`; `service ssh reload` has no init; reload/restart behaves differently — needs verification/rewrite |
| `/etc/shadow` backup/restore, `passwd root` | C08-27/30/34 | works via sudo | root pw is locked by default |
| `vim` editor | C08-29 | renamed | PC has `vim-tiny` (vim may be absent) |
| `/usr/sbin/sshd -t -T -C` | C08-31 | yes | present |
| attacker VM `ssh` as root | C08-33/37 | yes | rename port/addr |
| `agent.name:"bastion"`, rule 5715, data.dstuser root | Q08-07, slides | renamed/same | rule exists |
| config override via Include/Match | prose [12] | unverified | PC uses `sshd_config.d/` include — relevant, may surprise |

### command blocks (all bastion-root → office-pc01 via student sudo unless noted)
| id | where | tool | runs? |
|---|---|---|---|
| C08-26 | root shell | ls, passwd -S | sudo; yes |
| C08-27 | root shell | cp, chmod | sudo; yes |
| C08-28 | root shell | cmp | sudo; yes |
| C08-29 | root shell | **vim** sshd_config | vim-tiny only; config lives in sshd_config.d include |
| C08-30 | root shell | passwd root | sudo; yes |
| C08-31 | root shell | sshd -t/-T -C | yes |
| C08-32 | root shell | **service ssh reload** | no init manager; needs rework/verify |
| C08-33 | attacker VM | ssh root@ | yes (rename); PermitRootLogin must be enabled |
| C08-34/35/36 | root shell | cp/cmp/sshd -t/reload/passwd -S | reload caveat as C08-32 |
| C08-37/38 | attacker VM | ssh root / ssh ccc | yes (rename) |
| C08-39 | root shell | rm -i backups | yes |

### query blocks
| id | index | fields/rules | returns data? |
|---|---|---|---|
| Q08-07 | alerts | agent.name, rule 5715, data.dstuser root | rule exists; agent rename; unverified (PC not live) |

5. **Images:** explanation 2 — 1 screenshot (`root-fields.png`) + 1 diagram (`figures/root-state.png`).
   lesson.json 4 old-env captures. Screenshots all old.
6. **Blocking gaps:** `service ssh reload` under a PID1 `sshd -D` container (no systemd) — verify or
   rewrite restart; `vim` vs `vim-tiny`; root management done through student sudo (no root SSH);
   agent.name rename. sshd config override lives in a `sshd_config.d` include file.

---

## case-20 — sudo 권한 사용 (8.6)

1. **Learner does:** as ccc, runs `sudo -l`, `sudo -i id`, `sudo cat /etc/shadow`, then finds the
   sudo alerts (5402 root exec, 5403 first-time) and reads `data.srcuser/dstuser/command/pwd`.

### Environment assumptions
| Assumption | Where | Status | Note |
|---|---|---|---|
| account ccc with `(ALL) NOPASSWD: ALL` | C08-41, prose, slide p248 | renamed → student (NOPASSWD:ALL) | matches: lesson already notes 5401 won't fire |
| office-pc01 ccc SSH shell | C08-40…43 | renamed | student via :2222 |
| `/etc/shadow` readable by root | C08-43 | same | present |
| `agent.name:"bastion"`, rules 5402/5403 | Q08-08, slide p243 | renamed/same | exist |
| sudo decoder fields srcuser/dstuser/pwd/command | prose, slide p240 | same | standard sudo decoder |
| rule 5401 (3 wrong sudo pw) | slide p240/248 | same (won't fire) | NOPASSWD → no password prompt |

### command blocks
| id | where | tool | runs? |
|---|---|---|---|
| C08-40 | attacker VM | ssh | yes (rename) |
| C08-41 | office-pc01 student shell | id, sudo -l | yes |
| C08-42 | office-pc01 student shell | sudo -i id | yes |
| C08-43 | office-pc01 student shell | sudo cat /etc/shadow | yes |

### query blocks
| id | index | fields/rules | returns data? |
|---|---|---|---|
| Q08-08 | alerts | agent.name, rule 5402/5403 | rules exist; agent rename; unverified (PC not live). Not srcip-dependent |

5. **Images:** explanation 2 — 1 screenshot (`sudo-fields.png`) + 1 diagram (`figures/sudo.png`).
   lesson.json 5 old-env captures. Screenshots all old.
6. **Blocking gaps:** agent.name rename only. This lesson ports cleanly (student NOPASSWD sudo
   matches the ccc assumption).

---

## case-21 — 계정·그룹 생성과 삭제 (8.7)

1. **Learner does:** as ccc, `useradd -m` a throwaway account, adds it to `sudo` group with
   `usermod -aG`, inspects alerts (5902 add, 5901 group, 5903 delete), then `userdel -r`.

### Environment assumptions
| Assumption | Where | Status | Note |
|---|---|---|---|
| office-pc01 ccc SSH shell, sudo | C08-44…50 | renamed → student | NOPASSWD sudo present |
| `useradd/usermod/userdel/getent/id` | C08-45…50 | same | base Ubuntu tools on PC |
| `sudo` group gid 27 | C08-47 | unverified | Ubuntu default; should hold |
| `/var/log/auth.log` has useradd/usermod lines | C08-48, Q08-12 | same | PC collects auth.log |
| `agent.name:"bastion"`, rules 5901/5902/5903/5904/5555 | Q08-09/10/11/12, slides | renamed/same | all exist |
| archives auth.log | Q08-12 | same once PC logs | live archives = 0 today |

### command blocks (all office-pc01 student shell unless noted)
| id | where | tool | runs? |
|---|---|---|---|
| C08-44 | attacker VM | ssh | yes (rename) |
| C08-45 | student shell | getent/ls | yes |
| C08-46 | student shell | sudo useradd, passwd -S | yes |
| C08-47 | student shell | sudo usermod -aG sudo | yes |
| C08-48 | student shell | sudo grep auth.log | yes |
| C08-49 | student shell | sudo userdel -r | yes |
| C08-50 | student shell | getent/id/ls | yes |

### query blocks
| id | index | fields/rules | returns data? |
|---|---|---|---|
| Q08-09 | alerts | agent.name, rule 5902 | exists; rename; unverified |
| Q08-10 | alerts | agent.name, data.command usermod | depends on sudo decoder; rename |
| Q08-11 | alerts | agent.name, rule 5903 | exists; rename |
| Q08-12 | archives | agent.name, location auth.log, full_log | fine once PC logs; rename |

5. **Images:** explanation 3 — 2 screenshots (`useradd-fields.png`,`userdel-fields.png`) + 1 diagram
   (`figures/account.png`). lesson.json 5 old-env captures. Screenshots all old.
6. **Blocking gaps:** agent.name rename only. Ports cleanly. (Content note: slide p249 labels 5904
   as "user delete" — it is "changed user"; 5903 is delete.)

---

## case-22 — 핵심 계정 파일 변경 / FIM (9.2)

1. **Learner does:** as ccc, writes/appends a comment-only file in `/etc/sudoers.d/`, then reads the
   FIM alerts (554 add, 550 modify, 553 delete), the `syscheck.diff`, and the matching sudo command.

### Environment assumptions
| Assumption | Where | Status | Note |
|---|---|---|---|
| office-pc01 ccc SSH shell, sudo tee/chmod/visudo | C09-09…11 | renamed → student | sudo + visudo on PC |
| FIM realtime on `/etc` (incl. sudoers.d) | Q09-01, slides | **same** | PC syscheck realtime /etc |
| rules 554/550/553 | Q09-01, slides | same | exist |
| `agent.name:"bastion"` | Q09-01/02 | renamed → office-pc01 | |
| **`syscheck.diff`, size_before/after** | prose [5], image, slide | **missing** | PC config has no `report_changes="yes"` → no diff/size content |
| rule.groups:"sudo" + `data.command` | Q09-02 | same | sudo decoder present |
| xOC "보강" realtime of passwd/shadow/sudoers/cron | slide p258/267 | partial | PC realtime covers /etc (passwd/shadow/sudoers) + /home; **/var/spool/cron NOT in PC syscheck** |

### command blocks (office-pc01 student shell)
| id | where | tool | runs? |
|---|---|---|---|
| C09-09 | student shell | sudo tee/chmod/visudo -c | yes |
| C09-10 | student shell | sudo tee -a/visudo -c | yes |
| C09-11 | student shell | sudo cat/rm/visudo -c | yes |

### query blocks
| id | index | fields/rules | returns data? |
|---|---|---|---|
| Q09-01 | alerts | agent.name, syscheck.path /etc/sudoers.d/… | 554/550/553 exist; rename; diff/size fields will be empty (no report_changes); unverified (PC not live) |
| Q09-02 | alerts | agent.name, rule.groups sudo, data.command | sudo decoder; rename |

5. **Images:** explanation 1 **screenshot** (`screens/sudoers-fields.png`). lesson.json: p260/263/264/
   265/266 = 5 old-env example-screen captures. All old environment.
6. **Blocking gaps:** enable `report_changes="yes"` in the PC syscheck (else no diff/size — the core
   teaching point of the lesson); add `/var/spool/cron` to syscheck if the "보강" claim is to hold;
   agent.name rename. `whodata`/auditd absent → no `syscheck.uname_after`.

---

## case-23 — SSH 키 지속화 / authorized_keys FIM (9.3)

1. **Learner does:** generates an ed25519 keypair on the attacker VM, appends the public key to
   `~ccc/.ssh/authorized_keys`, logs in key-only, then reads the FIM alert on authorized_keys
   (550) and the `Accepted publickey` success (5715), and restores the file.

### Environment assumptions
| Assumption | Where | Status | Note |
|---|---|---|---|
| attacker VM `ssh-keygen`/`ssh -i` | C09-12/15, slides | same | ssh present on attacker VM |
| bastion **root** management shell | C09-13/16 | renamed → office-pc01; **no root SSH** | backup/restore of authorized_keys via student sudo |
| ccc home `/home/ccc/.ssh/authorized_keys` | C09-13/14, Q09-03 | renamed → /home/student/.ssh/authorized_keys | |
| FIM realtime on `/home` | Q09-03, slide p270 | **same** | PC syscheck realtime /home |
| rule 550 (authorized_keys modify) | Q09-03, slides | same | exists |
| rule 5715 + `full_log:"Accepted publickey"` | Q09-04 | same | exists; PasswordAuthentication yes + pubkey both allowed on PC |
| `agent.name:"bastion"` | Q09-03/04 | renamed → office-pc01 | |
| **`syscheck.diff`** (added key line) | C09-14 result, Q09-03, prose [8], slides p270/277 | **missing** | no report_changes on PC |
| **`syscheck.uname_after`** (who changed) | slide p270/273 | **missing** | no whodata/auditd on PC |
| host :2204@192.168.0.189 | C09-15 | renamed → :2222 / Core | |

### command blocks
| id | where | tool | runs? |
|---|---|---|---|
| C09-12 | attacker VM | ssh-keygen | yes |
| C09-13 | bastion root shell | cd/ls/cp -p/cmp | via student sudo on PC (no root SSH) |
| C09-14 | office-pc01 ccc shell | cat >> authorized_keys | yes (student, /home/student) |
| C09-15 | attacker VM | ssh -i key | yes (rename port/addr) |
| C09-16 | bastion root shell | cp -p/cmp restore | via student sudo |

### query blocks
| id | index | fields/rules | returns data? |
|---|---|---|---|
| Q09-03 | alerts | agent.name, syscheck.path authorized_keys | 550 exists; rename path to /home/student; diff/uname_after empty; unverified |
| Q09-04 | alerts | agent.name, rule 5715, full_log "Accepted publickey" | exists; rename; pubkey login allowed on PC |

5. **Images:** explanation 1 **screenshot** (`screens/publickey-fields.png`). lesson.json: p271/274/
   275/276 = 4 old-env example-screen captures. All old environment.
6. **Blocking gaps:** `report_changes="yes"` (diff of added key) and `whodata`/auditd
   (`syscheck.uname_after`) — both central to this lesson, both absent on the PC; root backup step
   → student sudo; path `/home/ccc`→`/home/student`; agent.name rename.

---

# Consolidated requirements

## Office PC image (`components/office-pc`)
- **report_changes + whodata for syscheck** — needed by **case-22, case-23** (and improves 16/18
  evidence). Today: realtime+check_all only, no `report_changes`, no `whodata`, no auditd → no
  `syscheck.diff`, no `size_before/after`, no `sha256_before/after`, no `syscheck.uname_after`.
  `report_changes` is a config flag; `whodata`/`uname_after` additionally need auditd, which the PC
  deliberately omits — so decide whether to drop the uname_after teaching or add auditd.
- **Add `/var/spool/cron` (and cron.d) to syscheck** if the slide "보강" claim is kept — case-22
  (and case-24 cron, out of my range).
- **vim** (full) vs `vim-tiny` — case-19 C08-29 edits sshd_config with vim.
- **sshd restart/reload under PID1 `sshd -D`** — case-19 uses `service ssh reload`; there is no init
  manager, so the reload/restart path must be rewritten or verified. sshd config lives in a
  `sshd_config.d/` include (also relevant to case-19's Include/Match prose).
- Base tools present and fine: openssh server+client, rsyslog, sudo, cron, getent/useradd/usermod/
  userdel, passwd, chpasswd, ssh-keygen (via client). student has NOPASSWD:ALL.

## Office PC agent configuration (Manager side already OK)
- **Agent name rename `bastion` → `office-pc01`** in EVERY query — **all 8 lessons (16–23)**.
- Collects `/var/log/auth.log` and `/var/log/syslog` — satisfies 16–21 auth and 22/23 FIM needs,
  once the agent is actually enrolled and reporting (currently 0 hits — **unverified live**).

## Manager configuration
- **All required rules already exist** (5710/5712/5715/5716/5720/5760/5763/5401/5402/5403/5901/5902/
  5903/5904/5555/550/553/554) — no rule work needed.
- **No Active Response** and the PC has **no iptables** — **case-16** firewall-drop / auto-block
  narrative (rules 58, 180s) must be removed or rewritten; case-17/18 references to auto-block too.
- Account `ccc` → `student` everywhere; home `/home/ccc` → `/home/student` (case-23 path).
- No Windows / no `wazuh-archives` auth lines until the PC logs (cases 18, 21 use archives).

## Attacker side (external attacker VM)
- **`hydra` is missing** — **case-16, case-17, case-18** drive the attack with hydra. Either add
  hydra to the attacker image, or rewrite the three attacks as ssh/python/nc loops.
- **Source-address change: attacker is seen as the ingress 10.20.30.20**, not a unique address —
  **case-18's `NOT data.srcip:10.20.*` filter is now self-defeating** (removes the success it should
  show) and must be reworked; **case-16/17/18 srcip pivots** no longer isolate the attacker.
- SSH target rename **`:2204`@192.168.0.107/.189 → `:2222`@Core address** — cases 16–21, 23.
- `ssh`, `ssh-keygen` present — case-19, case-23 work as-is (aside from rename).
