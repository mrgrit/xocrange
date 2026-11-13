# 정리 작업 분할·kt66 주소 체계·업데이트 사전 계획 검증 (2026-11-13)

개발 VM(Ubuntu 26.04, 디스크 임의 읽기 약 500 IOPS)에서 확인한 결함 세 가지와 수정, 그리고 K12 체크리스트의 콘솔 개별 제외·로그인 필요 시험 결과를 기록한다.

## 1. 모듈 트랜잭션이 SIEM 수용 단계에서 롤백된 원인

`xoc module remove console-fw`(로그 `install-20261113T105904-2855567.log`)가 `siem-telemetry` 단계에서 실패해 자동 복원됐다. 모든 수집원 검사(C1 8종·native 8종)가 false였다.

| 시각(UTC) | 일 |
|---|---|
| 11:06:00 | collector 시작(이미지 빌드 직후, 페이지 캐시 비어 있음) |
| 11:06:48 | 적체 해소, 검증이 probe를 만들고 180초 대기 시작 |
| 11:06:50 ~ 11:09:53 | collector가 첫 정리(`Store.prune` → `compact`)에 머묾. 그동안 수집·전달 없음 |
| 11:09:5x | 180초 만료, 실패 → 자동 복원 |

health 표의 마지막 갱신 시각(wazuh 11:06:48, retention 11:09:53)으로 루프 위치를 확인했다.

**측정(운영 DB 11 GB의 온라인 복사본)**
- 키가 내용 해시라 행 하나를 지울 때 색인·overflow 페이지를 파일 전역에서 무작위로 읽는다. 캐시가 빈 상태에서 약 30분치 행 정리에 **1121초**(행당 약 20 ms), 이어서 캐시되지 않은 다음 구간 약 24분치에 558초.
- 쿼리 계획은 모두 색인 탐색이다. 비용은 계획이 아니라 임의 읽기다. 운영 collector는 캐시가 차 있어 5분 주기를 따라간다(가장 오래된 행이 보존 기준보다 약 10분 뒤).

**수정**(`17815f6`)
- `Store.prune(budget=, batch=64)`: 표마다 `rowid IN (… LIMIT 64)` 단위로 커밋하며 지우고, 기한이 지나면 False를 돌려준다. `compact`도 2048 페이지씩 기한 안에서만 진행한다.
- collector는 루프마다 3초만 정리에 쓰고 다음 루프에서 이어 간다. 파일·색인 보존(`retention.maintain`)은 저장소 정리가 끝난 뒤에만 실행한다.
- 복사본(캐시 비움)에서 3초 예산 조각의 최대 길이: batch 256에서 5.1초, **batch 64에서 4.5초**.

**실행 검증**: 같은 조건(이미지 빌드 직후)의 `xoc update`에서 SIEM 수용이 **74초 만에 16항목 모두 통과**(이전 0항목).

## 2. `xoc update`가 정책이 바뀐 릴리스를 거부한 결함

`xoc update`는 새 소스로 선택 구성을 미리 계획할 때 **설치된 planner**를 썼다. 검토된 망 정의(`network_policy.py`)와 컴포넌트가 함께 바뀐 릴리스는 옛 상수에 걸려 `security_topology`로 거부됐다(설치본 변화 없음). `install.sh`는 새 코드로 다시 검증하므로 사전 계획도 새 코드로 해야 한다.

**수정**(`c46de6f`): `update`는 준비된 릴리스를 그 릴리스의 소스로 별도 인터프리터에서 계획한다. 모듈 추가·제거는 설치된 코드로 설치된 릴리스를 계획한다(변경 없음).

**실행 검증**: 수정만 얹은 중간 릴리스를 배포한 뒤(`e18c036…`), 주소 체계 변경을 포함한 main을 `xoc update`로 배포해 사전 계획을 통과하고 설치·수용까지 완료(`0d3140b…`).

## 3. kt66 주소 체계

실습망 대역을 이전 버전(kt66)과 같게 맞췄다(`f676f79`). 호스트 번호도 kt66과 같다.

| 망 | 이전 | 현재(kt66) | 고정 주소 |
|---|---|---|---|
| ext | 172.29.10.0/24 | 10.20.30.0/24 | fw .1, ingress .20, lab-client .10 |
| pipe | 172.29.11.0/24 | 10.20.31.0/24 | fw .1, ips .2 |
| dmz | 172.29.12.0/24 | 10.20.32.0/24 | ips .1, web .80 |
| int(내부망) | Docker 임의 배정 | 10.20.40.0/24 | web .80 |

- 컴포넌트는 `int`를 내부망으로만 선언하고, 대역은 planner가 지정한다(`network_policy.BACKEND_NETWORK`). 자동 배정은 `10.20.40.128/25`로 제한해 고정 주소와 겹치지 않는다. 유료 모듈도 대역을 알 필요가 없다.
- 관리 ingress의 바깥쪽 `user` 망(내부망 아님)은 Docker 기본 대역을 그대로 쓴다.
- 장비 콘솔 정책 상태(`state.json`)는 비어 있었고 `current.conf`는 broker가 시작할 때 다시 생성하므로 옮길 데이터가 없었다. 운영자가 옛 주소로 객체·규칙을 만든 설치본이라면 해당 정책은 운영자가 고쳐야 한다.

**실행 검증**(설치본 `0d3140b…`): lab verify·SIEM·관리 수용 통과. 실제 할당 — fw ext 10.20.30.1 / pipe 10.20.31.1, ips pipe 10.20.31.2 / dmz 10.20.32.1, web dmz 10.20.32.80 / int 10.20.40.80, ingress ext 10.20.30.20, lab-client 10.20.30.10, platform·indexer·dashboard·lab-target·siem은 int 10.20.40.128~132.

## 4. 콘솔 개별 제외

kt66 주소 체계 설치본에서 `xoc module remove/add`를 차례로 실행하고, 각 트랜잭션 뒤에 계획·컨테이너·관리자 로그인 수준 상태를 기록했다. 4단계 모두 설치·수용 검사를 통과했다.

| 단계 | 계획의 콘솔 | 로그인 후 메뉴(`/core/api/session`) | `/core/api/console/<장비>` | 장비 broker·소켓 |
|---|---|---|---|---|
| 기준 | fw·ips·waf | fw·ips·waf | 200·200·200 | 셋 다 동작 |
| `remove console-fw` | ips·waf | ips·waf | **fw 404**·200·200 | fw broker·소켓 없음 |
| `add console-fw` | fw·ips·waf | fw·ips·waf | 200·200·200 | 셋 다 동작 |
| `remove console-waf` | fw·ips | fw·ips | 200·200·**waf 404** | waf broker·소켓 없음 |
| `add console-waf` | fw·ips·waf | fw·ips·waf | 200·200·200 | 셋 다 동작 |

- 장비 정책 상태(`console-<장비>-state` 볼륨 해시)는 제거·재추가 전 과정에서 바뀌지 않았다. 콘솔을 빼도 장비 정책은 유지된다.
- `console-ips` 제외는 K09에서 검증했다.

## 5. 로그인이 필요한 시험

관리자 비밀번호가 초기값에서 바뀐 설치본을 위해, 통합 시험은 `XOC_ADMIN_PASSWORD_FILE`(권한 600 파일)에서 현재 비밀번호를 읽는다(`4f5e0f2`). 명령줄에 넣으면 Sysmon이 SIEM 저장소에 기록하므로 인자나 셸 명령에 넣지 않는다. 시험 뒤 파일을 지웠다.

모두 설치본 `0d3140b…`(kt66 주소 체계)에서 실행했다.

| 시험 | 결과 | 내용 |
|---|---|---|
| `concurrent_apply.py` (장비 broker) | 12/12 × 4회 | 같은 버전 동시 preview·동시 apply 중 하나만 성공·나머지 409, 오래된 버전·교체된 검토 토큰 409, rollback 복원, 실행 중 ruleset에 시험 객체 없음 |
| `concurrent_core.py` (Core HTTPS, 신규) | 13/13 × 3회 | 로그인한 관리자 세션 둘이 WAF·인증·DB 쓰기 잠금을 거쳐 동시 preview·apply: 하나만 200·나머지 409(승자는 실행마다 달라짐), 오래된 apply 409, 요청마다 감사 기록(`requested`+`applied` 또는 `requested`+`rejected`), rollback, 쓰기 정책 원복 |
| `device_console.py` | 51/51 | 실제 HTTPS로 세 장비 정책 변경·실제 트래픽 차단과 복원 |
| `workspaces.py` | 78/78 | HTTPS/WAF, 선택 자산 일치, 층 접근, 역할 |
| `workspaces.py --exercise-observer` | 85/85 | 위 + 검증 타깃 중지·관측 지연 주입과 복구 |
| `console_restart.py` | 16/16 | 장비 재시작 뒤 정책 유지 |
| `academy_acceptance.py` | 33/33 | 설치된 리더·기록 증거를 실제 HTTPS/WAF로 |

시험 쪽 수정
- `concurrent_apply.py`: 플랫폼과 같은 `65532:33`으로 실행. 콘솔 소켓 디렉터리가 `0770 root:33`이라 uid만으로는 연결이 거부됐다.
- `workspaces.py`: 아카데미 리더가 설치되면 6F가 카탈로그 전용 층으로 열린다(`d015541`에서 의도한 동작). 시험이 2F만 열려 있다고 가정하던 것을 고치고, 6F 응답에 자산·실행이 없는지 확인을 추가했다.

관찰: 로그인 제한(계정당 15분 10회)은 **성공한 로그인도 센다**. 시험을 연달아 돌리면 정상 비밀번호로도 15분간 429가 난다. 무차별 대입 방지로는 의도대로지만, 여러 사람이 같은 관리자 계정으로 자주 로그인하는 운영에서는 잠길 수 있다. 정책 유지 여부는 결정이 필요하다.

## 6. 잘못된 선택의 실제 거부와 설치본 경계 점검

설치본 `0d3140b…`에서 실제 명령으로 실행했다. 모두 종료 코드 2로 거부됐고, 실행 전후 `last-install.json`·`install-operation.json`이 그대로였다.

| 수준 | 입력 | 거부 |
|---|---|---|
| 설치기 인자 | `--include Bad_ID` | Invalid module ID |
| 설치기 인자 | 알 수 없는 옵션 | Unknown option |
| 설치기 인자 | `--data-dir "/var/../x y"` | Invalid data directory |
| 설치기 인자 | 다른 설치 식별자(`--expected-install`) | The installed selection changed |
| 모듈 | `remove platform`·`security-path`·`management` | `required_component` |
| 모듈 | `remove siem`(siem-ui 선택 상태) | `required_component`: siem 필요 |
| 모듈 | `add no-such-module` | `unknown_component` |
| 모듈 | 선택되지 않은 `remove target-juice` | `module_not_selected` |
| planner(설치기 module-plan 단계와 같은 명령) | `--include siem-ui --without siem` | `required_component` |

설치기의 조합 검사는 `module-plan` 단계(기본 패키지·소스 스냅숏 뒤)에서 같은 planner로 한다. 운영 중 선택 변경은 `xoc module`/`xoc update`가 설치기 실행 전에 같은 검사를 하므로 시스템을 건드리지 않고 거부된다.

경계 점검: `scripts/check-boundary.py --installed --root <설치 릴리스>` — 설치 릴리스 파일 159개, inventory, 계획 Compose에서 위반 0건.

## 7. 분할 정리의 공정성, 상태 조회 잠금, Sysmon 시작 실패

1절의 분할 정리를 배포한 뒤 장기 운영 표본과 상태를 보다가 세 가지 결함을 더 찾았다.

**경보 행이 지워지지 않음**(`4f3ff5a`)
- 배포(13:44) 이후 `wazuh_alerts`가 한 번도 정리되지 않았다. 보존 기준을 89분 넘긴 행이 91,875개였고 모두 색인 완료(삭제 가능) 상태였다. `retention` health가 1.7시간 갱신되지 않아 `xoc siem status`가 계속 `degraded`였다.
- 원인: 조각마다 첫 표(events)부터 시작했다. events·records와 그 연쇄 삭제(native_inputs)에 매번 새로 만료된 행이 있어 3초 예산을 다 썼고, 마지막 표인 경보는 차례가 오지 않았다. 운영 DB에서 경보 행 삭제 비용은 행당 3.8 ms였다.
- 수정: 기한에 걸린 표에서 다음 조각을 이어 시작해 패스마다 모든 표를 한 번씩 돈다. 패스가 끝나지 않았으면 5초 대기 대신 4초 조각을 쓴다(루프 주기는 같고 삭제 처리량은 늘어난다).
- 회귀 테스트: 조각 사이마다 첫 표에 새 만료 행을 넣어도 경보가 모두 지워지는지 확인(이전 코드에서 실패).

**상태 조회가 쓰기 잠금을 기다림**(`4f3ff5a`)
- 저장소를 열 때 `PRAGMA auto_vacuum=INCREMENTAL`을 매번 실행했다. 값이 이미 같아도 쓰기 잠금을 잡으므로, collector가 쓰는 동안 `xoc siem status`가 30초 기다리다 `database is locked`로 실패했다. 장기 표본 5개가 이 때문에 비었다.
- 수정: 이미 incremental이면 설정하지 않는다. 쓰기 트랜잭션이 열린 상태에서 저장소 열기·상태 조회가 되는 회귀 테스트를 추가했다.

**Sysmon 일시적 시작 실패로 업데이트 롤백**(`7845a4f`)
- 위 수정을 배포하던 `xoc update`가 `siem-telemetry`에서 실패해 자동 복원됐다(복원 후 모든 서비스 active, 설치본 `0d3140b` 유지).
- 원인: Sysmon 시작 때 eBPF perf ring buffer용 연속 페이지 할당 실패(커널 `page allocation failure: order:6`, `libbpf: failed to mmap perf buffer: -ENOMEM`, sysmon 종료 코드 6). systemd 자동 재시작으로 10초 뒤 정상 시작했지만, 설치기는 첫 `systemctl enable --now` 실패로 중단했다. 페이지 캐시가 큰 장기 운영 호스트에서 생기는 메모리 단편화다.
- 수정: 설치기가 메모리를 compaction하고 최대 5회 재시작한다. 끝내 active가 아니면 그대로 실패한다(fail closed).

**Sysmon 실패 메시지가 격리 입력으로 남음**(`24f1de9`)
- 위 시작 실패 때 Sysmon journal에 남은 두 줄(`libbpf: failed to mmap perf buffer … -ENOMEM`, `Telemetry failed to start …`)을 collector가 이벤트로 해석하지 못해 격리했다. 격리 입력은 보존 기간(하루) 동안 남으므로 Sysmon이 복구된 뒤에도 상태가 하루 내내 `degraded`였을 것이다.
- 수정: 이 두 형식을 센서 진단 이벤트(`agent-failure`, 심각도 65 — 이벤트 유실 보고와 같은 수준)로 기록한다. 센서가 멈췄던 구간이 SIEM에 사건으로 남는다.

**실행 검증**(설치본 `9b2dd86` → `dce4136`)
- 공정성 수정 배포 후 만료 경보 116,946행이 약 10분 만에 500행 미만으로 줄었다. 이어서 빈 페이지 회수가 분당 약 10만 페이지(약 425 MB)씩 진행돼 retention health가 다시 갱신됐다. DB 사용량은 10.9 GB에서 9.84 GB로 줄었다.
- Sysmon 재시도 수정이 들어간 설치(`9b2dd86`)에서는 Sysmon이 첫 시도에 시작돼 재시도 경로는 실행되지 않았다(단위 테스트로 일시 실패 복구·지속 실패 시 실패를 확인).
- 진단 분류 수정 배포 후 `xoc siem retry`로 격리 2건을 다시 처리해 `agent-failure`(심각도 65) 진단 이벤트가 됐고, `xoc siem status`가 `ready`(대기 9, 지연 3초, 격리 0)로 돌아왔다.

## 8. 외부 클라이언트 출처 IP 보존

K05는 서버 자신에서 보낸 요청만 확인했고(SIEM 출처 172.18.0.1, docker-proxy 경유), 외부 PC의 출처 보존은 미확인으로 남겼다.

**방법**: 호스트에 임시 network namespace와 veth 쌍(문서용 대역 198.51.100.0/24)을 만들어, 요청이 Docker 밖의 인터페이스로 들어오게 했다. 외부 PC와 같은 커널 경로(PREROUTING DNAT → ingress → fw → IPS → WAF)다. 시험 뒤 namespace와 veth를 지웠다.

| 출발지 | ingress(HAProxy) 기록 | WAF access·ModSecurity | SIEM C1 `network.source.ip` |
|---|---|---|---|
| 모의 외부 클라이언트 198.51.100.2 → `https://192.168.16.100` | 198.51.100.2 | 198.51.100.2 | 198.51.100.2 (apache-access, modsecurity) |
| 서버 자신 → 자기 LAN 주소 192.168.16.100 | 192.168.16.100 | 192.168.16.100 | 192.168.16.100 |

- HTTP(80)는 HTTPS로 308 전환되므로 위 결과가 실제 경로다.
- `127.0.0.1`로 접속하면 docker-proxy를 거쳐 172.18.0.1로 기록된다(K05의 관찰). 로컬 루프백만의 특성이다.
- 실제 외부 PC로 같은 확인을 RC 후보에서 한 번 더 하면 된다. 가상화 소프트웨어의 NAT 네트워크를 쓰면 출처가 그 NAT 게이트웨이 주소로 보일 수 있다. 이는 VM 밖의 주소 변환이다.
