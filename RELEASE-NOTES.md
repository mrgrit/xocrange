# xOC Range Core Community 0.1.0 릴리스 노트

버전 **0.1.0**, 태그 `v0.1.0`, 2026-11-15. 첫 공개 Community 릴리스다. 출시 판정 근거는 [K12 체크리스트](docs/development/K12-RC-CHECKLIST.md)와 [최종 RC 재실행](docs/development/RC-FINAL-2026-11-15.md)에 있다.

```bash
git clone --branch v0.1.0 https://github.com/mrgrit/xocrange.git
cd xocrange && sudo bash install.sh
```

xOC Range Core는 방화벽·IPS·WAF·SIEM으로 이루어진 보안 운영 실습 환경을 Ubuntu 서버 한 대에 설치 명령 한 번으로 구성한다. Community는 키 없이 동작하며, 학교·대학의 수업과 개인 학습에 무료로 쓸 수 있다. 설치와 사용은 [사용자 안내](docs/USER-GUIDE.md)를 본다.

## 포함 기능

| 영역 | 내용 |
|---|---|
| 설치 | `sudo bash install.sh` 한 번으로 패키지·Docker·이미지 빌드·기동·수용 검사·부팅 서비스 등록. 실패 시 비정상 종료와 실패 단계 표시 |
| 보안 경로 | TLS ingress → 방화벽(nftables) → IPS(Suricata, NFQUEUE) → WAF(Apache·ModSecurity·OWASP CRS) → 타깃. 출처 IP 보존, 우회 차단 |
| 장비 콘솔 | 방화벽·IPS·WAF 정책의 미리보기·적용·복원, 변경 감사, 관리자의 쓰기 허용 정책, 동시 적용 충돌 방지 |
| SIEM | 8종 로그(nftables·Suricata·ModSecurity·Apache access/error·osquery·Sysmon·auditd) 수집, 원본 SHA-256 보관, C1 정규화, Wazuh Manager 분석과 처리 확인, Indexer·전용 Dashboard 검색 |
| 수업 운영 | `xoc siem clear`로 수업 전 SIEM·장비 로그 초기화(계정·정책·실습 노트 유지) |
| 관리 | Core 관리 화면, 관리자·운영자·조회자 역할, 서버 세션·CSRF, 감사 기록, 계정당 실패 로그인 제한 |
| 화면 | 데이터센터 시각화, 운영 개요, NOC 2층, 아카데미(교재 1–339쪽, 36개 차시 실습 노트) |
| 실습 타깃 | Juice Shop·DVWA 선택 추가(`xoc module add`), `*.xoc.range` 이름으로 보안 경로 뒤에서 접속 |
| 운영 | 모듈 추가·제거, 업데이트(실패 시 자동 복원), 백업·검증·복원, 정전 뒤 복구, 로그 회전과 보존 예산 |

## 요구 사양

Ubuntu Server 26.04 LTS amd64 전용 VM 또는 서버. 기본 구성(SIEM 웹 관제 포함)은 8 GiB RAM 이상이 필요하고 16 GiB를 권장한다. `--without siem-ui`이면 4 GiB. 디스크는 100 GB 이상(최소 60 GB)을 권장한다. 24시간 연속 운영에서 메모리 최대 6.0 GiB, 수집 지연 최대 9초, SIEM 저장 최대 17.6 GiB를 측정했다([사용자 안내 9절](docs/USER-GUIDE.md#9-권장-사양)).

## 이번 릴리스에서 검증한 것

최종 소스로 새 VM에서 다시 실행한 결과다(2026-11-15). 출처 IP·디스크 고갈은 2026-11-13~14 실행 결과다.

| 검증 | 결과 |
|---|---|
| 빈 VM 한 번 설치 | Docker도 없는 새 Ubuntu 26.04.1 VM(8 vCPU·15 GiB·100 GB)에서 8분 30초, 수용 검사 11·15·6·8·52 통과 |
| 같은 VM 재설치 | 4분, 계정·학습 기록 보존 |
| 재부팅 | 17/17, 증거 24건 보존 |
| 통합 시험 | Core 보안 31, 장비 콘솔 51, 콘솔 재시작 16, 작업공간 78, 아카데미 33, 동시 적용 12·13, 모의 외부 클라이언트 출처 IP 7 |
| 출처 IP | 실제 외부 PC의 주소가 ingress·WAF·SIEM까지 그대로 기록 |
| 디스크 고갈 | 예약 공간 미만·완전 소진 중에도 서비스 유지, 해제 후 회복과 멈춘 동안의 로그 수집 |
| 경계 | 배포물에 유료·AI·채점 코드 없음(설치본 162개 파일 점검) |
| `xoc siem clear` | 12/12, 이후 8종 수집과 SIEM 웹 검사 52/52 |
| 웹 요청 User-Agent | 실습 요청 원본에 기록, 스캐너 이름은 Wazuh 규칙 111303 경보 |

상세 기록: [최종 RC 재실행](docs/development/RC-FINAL-2026-11-15.md), [새 VM 검증](docs/development/RC-FRESH-VM-2026-11-13.md), [보존·주소 체계 검증](docs/development/RETENTION-ADDRESS-PLAN-2026-11-13.md).

## 이전 개발 버전에서 바뀐 점

- 실습망 주소를 이전 시스템과 같은 체계로 변경: ext 10.20.30.0/24, pipe 10.20.31.0/24, dmz 10.20.32.0/24, int 10.20.40.0/24. 기존 설치는 업데이트 때 새 주소로 다시 구성된다.
- 로그인 제한이 실패한 로그인만 센다(계정당 15분 10회, 전체 100회).
- SIEM 보존 정리가 수집을 막지 않도록 나눠서 실행하고, 모든 표를 차례로 정리한다. 빈 페이지를 디스크에 돌려준다.
- 디스크가 찬 뒤 auditd가 기록을 멈춘 상태를 SIEM에 표시하고, 공간이 돌아오면 자동으로 다시 시작한다.
- 업데이트 사전 검사가 새 소스 자신의 계획기로 검사한다(주소·구성 변경 업데이트 허용).
- Sysmon 시작이 일시적으로 실패하면 메모리를 정리하고 다시 시도한다.
- 수업 전 초기화 명령 `xoc siem clear` 추가.
- 업데이트 복구 지점은 성공 후 최신 하나만 남긴다(이전에는 업데이트마다 쌓여 디스크를 채웠다). 직접 만든 백업은 지우지 않는다.
- 아카데미 Community 콘텐츠를 Core 저장소 `contents/`에 포함해 설치 중 별도 다운로드가 없다(ADR 0009). 이전 개발 설치는 `git pull` 전에 기존 `contents/`를 옮긴다([사용자 안내 6절](docs/USER-GUIDE.md#6-백업업데이트복구)).
- 실습 웹 요청(관리 화면 제외)의 User-Agent를 WAF 접근 로그에 남기고, 알려진 스캐너 이름은 Wazuh 경보(규칙 111303)로 표시한다. 쿠키·인증 헤더는 기록하지 않는다.

## 알려진 제한

- 단일 서버·단일 기관용. 다중 사용자 격리, 공방전·자동 채점, AI 근무자는 유료 모듈 범위다.
- `ssh-lab`(SSH 실습)과 `bootstrap` 단독 설치는 포함하지 않는다.
- 관리자 비밀번호 재설정 명령이 없다. 관리자 계정을 두 개 이상 둔다.
- 디스크가 가득 찬 동안 각 프로그램이 쓰지 못한 로그는 복구되지 않는다. 쓰다 잘린 줄은 격리되어 보존 기간(1일) 동안 상태를 `degraded`로 만든다.
- 학습자 타깃 이름은 hosts 파일·기관 DNS로 쓴다(공개 DNS 없음).
- 교재와 실습 환경의 정합성 검토는 후속 작업이다.

## 라이선스

Core 자체 코드와 프로젝트 자산은 [PolyForm Noncommercial 1.0.0](LICENSE)과 [교육용 추가 허락](LICENSE-EDUCATION.md)을 따른다. 서드파티 구성요소(Suricata·Wazuh·Apache·ModSecurity·DVWA·Juice Shop 등)는 각자의 라이선스를 유지한다([NOTICE](NOTICE), [DEPENDENCIES](docs/development/DEPENDENCIES.md)).

## 출시 전 정리 기록

- 24시간 이상 장기 운영 측정과 SIEM 포함 권장 사양 확정(2026-11-14).
- 최종 소스로 새 VM 설치·재부팅·통합 시험 재실행(2026-11-15).
- 서드파티 라이선스와 설치본 inventory 대조(2026-11-14), 공개 전 저장소 전체 이력의 비밀값·개인정보 점검(2026-11-15).
- 저장소 공개와 버전 `0.1.0` 확정(소유자, 2026-11-15).
