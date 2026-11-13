# Observation 자기 발생량 제거 — 2026-11-13

2026-11-09 조정([이전 기록](OBSERVATION-VOLUME-VALIDATION-2026-11-09.md)) 후에도 개발 VM의 SIEM DB가 하루 만에 12.9 GB로 늘었다. Sysmon 이벤트가 시간당 약 3만 건(초당 8.4건)으로 일정하게 들어왔고, 대부분은 xoc가 스스로 만든 프로세스 실행 기록이었다.

## 원인

설치본의 Sysmon journal 10분 구간(05:00–05:10 UTC, 작업자 활동 없음)을 명령줄 단위로 집계했다.

| 발생원 | 10분 건수(대략) | 내용 |
|---|---:|---|
| SIEM 컨테이너 `start.sh` | 약 2,700 | 10초마다 `wazuh-control status`를 실행. 호출마다 `ls`·`cat`·`ps`·`grep`·`awk`·`dirname` 등 약 45개 프로세스 |
| 수집기 Wazuh 전송 | 약 1,200 | 5초 주기마다 C1·native 각각 `docker compose exec … xoc-queue.py`를 새로 실행. docker·compose 플러그인·runc·Python 프로세스가 생기고, 이 기록을 다음 주기에 다시 전송하는 자기 증식 루프 |
| observer 타이머(15초) | 약 300 | `volume ls`·`volume inspect`·`ps`·`inspect` |
| 수집기 journal 읽기·센서 확인 | 약 150 | 주기마다 `journalctl`, 30초마다 `systemctl`·`compose ps` |

저장 측면에서는 이벤트 1건이 원본(records), C1(events), Wazuh 경보 2건(C1 경로와 native 경로, 각각 원본과 색인 문서)으로 저장돼 이벤트당 약 17 KB를 차지했다. `wazuh_alerts`만 150만 행·7.2 GB였다.

## 변경

- `components/siem/start.sh`: 필수 daemon 확인을 upstream `wazuh-control status`와 같은 판정(PID 파일의 프로세스가 살아 있는지 `kill -0`)으로 바꾸고 bash 내장 명령만 사용한다. 실행 중인 Manager에서 upstream 결과와 daemon별로 일치함을 확인했다. 10초 주기와 daemon 중지 시 PID 1 종료 동작은 그대로다.
- `src/xocrange/collector.py`: Wazuh queue 전송을 큐별 상시 프로세스 1개(`Transport`)로 바꿨다. 기존 queue 스크립트가 입력 줄마다 확인 응답을 내므로 프로토콜은 그대로다. 응답 순서·ID 불일치, 종료, 30초 시간 초과 시 프로세스를 버리고 다음 주기에 새로 시작한다. 실패 전까지 확인된 ID만 `sent`로 기록하므로 재전송 범위는 기존과 같거나 더 작다. 쓰기와 응답 읽기를 번갈아 처리해 4096건 배치에서도 파이프가 막히지 않는다.
- `src/xocrange/ui_setup.py`: `owned_volume`이 먼저 `volume inspect`를 시도하고, 없을 때만 목록 확인 후 생성한다. observer 실행마다 `volume ls` 2회가 줄었다.
- Sysmon 정책(`components/siem/sysmon.xml`)은 바꾸지 않았다. Docker·수집기 명령줄을 제외 필터로 숨기면 같은 명령줄을 흉내 낸 실행도 숨겨지므로, 기록을 만드는 원인 쪽을 고쳤다.

## 함께 고친 결함

첫 업데이트 시도에서 다음 두 결함이 드러났다.

1. **설치 중 자동 업그레이드 경쟁.** 설치 도중 unattended-upgrades가 libc6를 갱신하면서 systemd가 재실행(`daemon-reexec`)됐고, `boot-service` 단계의 `systemctl`이 `D-Bus connection terminated`로 실패했다. 설치기는 이제 실행 동안 `apt-daily.timer`·`apt-daily-upgrade.timer`를 멈추고, 이미 시작된 실행은 최대 30분 끝나기를 기다린 뒤 진행하며, 종료(성공·실패·복원 후) 시 멈춘 타이머만 다시 켠다.
2. **IPS 시작 시 fail-open 구간.** IPS 컨테이너는 생성 시점부터 `ip_forward=1`인데, `policy drop`·NFQUEUE 테이블은 정책 초기화·Suricata 설정 생성·`suricata -T` 뒤에 로드됐다(이 VM에서 약 0.6초, 규칙 수에 비례). 그 사이 경로 트래픽이 검사 없이 전달됐다. 복원 직후 `lab verify`가 이 구간에 경로 probe에 성공한 뒤 아직 없는 `xoc_ips` 카운터를 조회해 `docker_failed`로 실패했고, 자동 복원과 `xoc recover` 2회가 모두 같은 단계에서 멈췄다. 이제 IPS는 nft 테이블을 라우트·설정보다 먼저 로드한다. queue bypass가 없으므로 Suricata가 queue 0에 붙기 전 패킷은 버려진다. FW도 테이블을 라우트보다 먼저 로드한다. `lab verify`는 platform `/healthz` 응답을 최대 60초 기다린다.

구 릴리스 복구는 `xoc recover`가 데이터 복원까지 마친 뒤 마지막 서비스 기동만 실패한 상태였다. 컨테이너가 준비된 뒤 `resume()`과 같은 순서로 서비스를 수동 기동해 모두 정상임을 확인했고, 복구 저널을 `recovered`(수동 완료 메모 포함)·`rolled-back`으로 정리한 다음 수정된 소스로 다시 업데이트했다.

## 실제 VM 검증

`sudo xoc update --source`로 두 단계에 걸쳐 설치했다. 각 설치는 경로 수용 검사 15항목, 관리·SIEM·SIEM UI 수용 검사를 모두 통과했다. 측정은 작업자 명령이 없는 10분 구간의 Sysmon journal 전체다.

| 구간 | 릴리스 | 전체 | 실행(EventID 1) | 연결(EventID 3) |
|---|---|---:|---:|---:|
| 05:00–05:10 | 변경 전 `d9b1e0f8…` | 4,971 | 4,698 | 273 |
| 07:59–08:09 | 1단계 `3f0f7db4…` (상태 확인·상시 전송) | 1,189 | 818 | 371 |
| 08:30–08:40 | 2단계 `4d723bd0…` (+볼륨 일괄 조회·FIFO 대기) | 796 | 520 | 276 |

- 2단계 구간의 실행 기록 520건 중 61건은 측정을 기다리던 작업자 셸의 `sleep 10`이다(User `ccc`, 부모 `/bin/bash`). 이를 빼면 xoc 자체의 실행 기록은 약 460건/10분으로 변경 전 대비 약 90% 줄었다.
- 1단계 구간은 복구 직후 적체분을 처리하던 때라 연결 기록이 평소보다 많다.
- Sysmon 유입은 변경 전 시간당 약 3만 건(DB 시간별 집계)에서 시간당 약 4.4천 건 수준이 됐다. 남은 주요 발생원은 수집기의 주기별 `journalctl`(약 70건/10분), observer 타이머(약 200건/10분), 수집기의 30초 상태 확인(약 100건/10분)이다.
- 2단계 설치 후 `xoc siem status`: `ready`, 미분석 19건(최장 5초), 분석 격리 0건, Sysmon 지연 5초, 미색인 0건. 기존 DB(12.7 GB)는 보관 정책(로컬 1일)에 따라 순차 정리된다.
- IPS 재시작 직후 측정: 첫 확인 시점(시작 후 1.7초)부터 `inet xoc_ips` 테이블이 있었고 경로 응답은 정상이었다. 이 VM에서 구 순서의 노출 구간에 해당하는 설정 검사 단계는 약 0.6초(컨테이너 시작 08:41:56.16 → 검사 완료 56.74, 엔진 시작 56.89)였다. 규칙이 많아지면 길어진다.
- 단위·계약 테스트 460개 통과(브라우저 렌더러 1개는 Node 미설치로 건너뜀). 신규: 상시 전송(배치 재사용·5000건 무교착·부분 확인 보존·재시작·시간 초과), 설치기 APT 타이머 일시 중지, 장비 테이블 선적용 순서, 볼륨 일괄 조회, 운영 잠금 대기.
- 2단계 릴리스에서 `xoc backup create`(45개 묶음, 약 8.2 GB, portable) 후 `xoc backup restore`를 실행했다. 복원은 데이터 교체 → 서비스 재기동 → `lab verify`까지 끝나 저널이 `complete`가 됐고(09:10 UTC), 6개 서비스 모두 active였다. 시험용 백업과 복원 전 체크포인트는 검증 후 삭제했다.
- 백업 직후 복원은 1분 주기 로그 정리가 공통 잠금을 잡은 순간과 겹쳐 처음에 `operation_busy`로 거부됐다(변경 없음). 이에 따라 운영자 명령(`backup`·`recover`·`license`)은 잠금을 최대 120초 기다리고, 설치기도 `flock -w 120`으로 기다리며, 주기 작업만 기존처럼 바로 포기하도록 고쳤다. 이 변경은 단위 테스트로만 확인했고 설치본에는 커밋 후 반영한다.
- 복원 직후 `lab verify`가 실패한 정확한 docker 명령은 기록하지 못했다. 실패 시점(시작 후 3~6초)에 실패할 수 있는 두 단계(platform `/healthz` 미준비, IPS 테이블 부재 중 카운터 조회)를 모두 고쳤다.

## 남은 범위

- 수집기는 주기마다 `journalctl`을 새로 실행하므로 주기당 1건의 자기 관측이 남는다. 상시 journal 읽기로 바꾸면 없앨 수 있다.
- 이벤트당 저장량(원본·C1·경보 2건의 원본과 문서)은 그대로다. 경보 문서를 원본에서 재구성하는 방식 등은 색인·조회 경로와 함께 별도로 설계한다.
- 수집기가 적체분을 처리하며 긴 쓰기 트랜잭션을 잡는 동안 `xoc siem status`가 30초 대기 후 `database is locked`로 실패할 수 있다(복구 직후 관찰).
- 구 릴리스로 되돌리는 복원은 구 릴리스의 IPS 시작 순서를 그대로 쓰므로 같은 경쟁이 남는다. 이번 릴리스 이후 체크포인트부터 해소된다.
