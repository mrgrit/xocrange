# 새 VM 설치·재부팅·디스크 고갈 검증 — 2026-11-13

K12 RC 체크리스트의 1번(빈 VM 한 번 설치), 2번(재부팅), 5번 중 디스크 고갈을 별도 VM에서 확인했다. 소스는 main `5c2514a`(로그인 제한이 실패만 세도록 바꾼 커밋)이며 개발 체크아웃을 git bundle로 옮겨 변경 없이 사용했다. 개발 VM의 24시간 장기 측정은 그대로 두었다.

## 대상

| 항목 | 값 |
|---|---|
| VM | VMware, Ubuntu 26.04.1 LTS, 커널 7.0.0-43, x86_64 |
| 자원 | 8 vCPU, 15 GiB RAM, 285 GB ext4 루트 |
| 설치 전 상태 | Docker 없음, `/var/lib/xocrange`·`/etc/xocrange`·`/opt/xocrange` 없음, 패키지 728개 |
| 설치 후 | Docker 29.9.3, Compose 5.7.1, 이미지 10개, 호스트 패키지 739개 |

## 1. 빈 VM 한 번 설치

`sudo bash install.sh`를 한 번 실행했다. 23:28:23 → 23:35:51 UTC(약 7분 30초), 종료 코드 0, 중간 수정·재실행 없음. 22단계(`dedicated-host-check` … `release-inventory`)를 모두 지났다.

| 설치기 수용 검사 | 결과 |
|---|---|
| 네트워크 사전 조건 | 11/11 |
| 보안 경로(`acceptance`) | 15/15 |
| 공통 관리 | 6/6 |
| SIEM 수집(8종) | 8/8 |
| SIEM HTTPS/WAF/검색 | 52/52 |

설치 직후 `xoc siem status`는 `ready`(격리 0, 색인 대기 0), `xocrange-core`·collector·osquery·sysmon·auditd·docker 모두 active, 컨테이너 10개 running. 실습망은 kt66 주소 체계(ext 10.20.30, pipe 10.20.31, dmz 10.20.32, int 10.20.40)로 생성됐다. `install-operation.json`은 `complete`.

## 2. 재부팅

`tests/integration/siem_lifecycle.py checkpoint --run rc-fresh-reboot --isolated-vm`으로 8종 × 3 = 24개 증거를 고정한 뒤 `systemctl reboot`. boot ID가 바뀌고 Core·collector가 active가 된 뒤 `verify --after reboot`: **17/17 통과**. 원본 24·C1 24·색인 24 일치, 재부팅 후 새 보안 경로 15·수집원 8·HTTPS 52 검사 통과.

## 3. 설치본 경계와 통합 시험 재실행

| 시험 | 결과 |
|---|---|
| `scripts/check-boundary.py --installed` | 160개 파일, 위반 0 |
| `scripts/verify-platform.py`(초기 비밀번호 변경 포함) | 31/31 |
| `device_console.py` | 51/51 |
| `console_restart.py` | 16/16 |
| `workspaces.py` | 78/78 |
| `academy_acceptance.py` | 33/33 |
| `concurrent_apply.py` | 12/12 |
| `concurrent_core.py` | 13/13 |
| `source_ip.py`(모의 외부 클라이언트) | 7/7 |

`check-boundary.py` 설명의 `xoc-python`은 존재하지 않는 명령이었다. 설치본 venv의 Python으로 실행하도록 설명을 고쳤다.

### 로그인 제한(실패만 센다)

설치본 HTTPS로 관리자 로그인 성공 12회는 모두 200, 틀린 비밀번호 10회는 401, 그 직후 맞는 비밀번호는 429. 성공은 한도에 세지 않고 실패 10회 뒤에는 창이 끝날 때까지 잠긴다.

## 4. 디스크 고갈

`fallocate`로 루트 파일시스템을 채웠다. 채운 파일은 trap과 시간 제한으로 반드시 지워지게 했고, 기록은 tmpfs에 남겼다. 30초마다 상태를 기록하고 HTTPS 요청 5건씩을 표시(`xoc-disk-a/b/c`)와 함께 보냈다.

| 단계 | 조건 | 관찰 |
|---|---|---|
| A (3분) | 여유 1.5 GiB(예약 2 GiB 미만) | 모든 수집원 `disk_reserve`, 상태 `degraded`, 새 기록 0건. collector·Core 재시작 0, 컨테이너 10개 running, Core HTTPS 200 |
| B (4분) | 루트 예약 블록까지 소진(여유 16~70 MiB, 일반 사용자 0) | A와 같음. Apache는 요청 40건 중 5줄만 로그에 썼다 |
| C | 채운 파일 삭제 | 30초: Indexer가 디스크 차단으로 거부(`indexer_rejected`) → 90초: 모든 수집원 ready, 색인 대기 0. `lab verify` 15/15 |

- 수집 위치 보존: A 단계 요청 30건은 수집이 멈춘 동안 원본 로그에만 있었고(23:44~23:51 기록 0건), 해제 후 apache-access·ModSecurity 각 30건 모두 수집됐다.
- 손실 범위: 디스크가 찬 동안 생산자(Apache·ModSecurity·osquery)가 쓰지 못한 줄은 원본에 없다. 쓰다가 잘린 4줄은 원본에 잘린 채 남아 `invalid_event`/`invalid_json`으로 격리됐다. 격리 건수 때문에 상태는 보존 기간(1일) 동안 `degraded`로 남는다. 손상된 입력을 정상으로 처리하지 않는다는 점에서 의도된 동작이다.
- collector·Core의 재시작 0회, 컨테이너 재시작 0회, 해당 시간 collector/Core 저널의 오류 0줄.

## 5. 실제 외부 PC의 출처 IP

같은 네트워크의 Windows PC(192.168.0.84) 브라우저로 `https://192.168.0.76/rc-external-pc-check`를 열었다(인증서 경고 후 404, 없는 경로를 일부러 요청). 2026-11-14 00:09:08 UTC.

| 위치 | 기록된 출처 |
|---|---|
| ingress 로그 | 192.168.0.84(해당 시각 6줄) |
| WAF access log | `192.168.0.84 - - [14/Nov/2026:00:09:08 +0000] "GET /rc-external-pc-check HTTP/1.1" 404` |
| SIEM C1 `network.source.ip` | apache-access 1건(`failure`)·ModSecurity 2건(`observed`) 모두 192.168.0.84, Wazuh 확인·색인 완료 |

Docker 게이트웨이 주소(172.18.0.1)는 나타나지 않았다.

## 남은 것

- 24시간 장기 운영 분석(개발 VM, 2026-11-14 16:30 UTC 이후).
- 최종 RC 커밋이 정해지면 같은 VM에서 설치·재부팅을 다시 실행한다.
