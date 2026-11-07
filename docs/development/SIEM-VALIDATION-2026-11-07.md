# Core SIEM 실환경 검증 — 2026-11-07

Ubuntu 26.04.1 전용 VM에서 Core의 8종 로그를 실제로 수집하고 C1 정규화, Wazuh 분석, 영속 저장소 조회까지 확인했다. 이는 K06의 수집·디코딩 백엔드 검증이며 전체 Community 출시 완료를 뜻하지 않는다.

- 검증 시각: 2026-11-07 14:32 UTC.
- 설치 소스 SHA-256: `9ddda09b3eca8e70261286eb612c193adfa06021f7780aa8815e4ad657697eca`.
- 환경: hostname `xoc`, Ubuntu Server 26.04.1 amd64, kernel `7.0.0-43-generic`, 8 vCPU / 16 GiB RAM / 300 GiB disk.
- 분석 엔진: Wazuh `4.14.10`; 호스트 센서: osquery `5.24.1`, Sysmon for Linux `1.6.0`, auditd `4.1.2`.
- [기계 판독용 검증 기록](../provenance/siem-acceptance-2026-11-07.json).

## 통과 기준과 결과

| 항목 | 결과 | 확인 범위 |
|---|---|---|
| 단위·계약 테스트 | Python 3.10 / 3.14 각각 156개 통과 | 8종 파싱, 민감 필드 제외, XML 안전성, audit 결합, 재처리, 파일 회전, 저장 원자성, 선택 설치 정책 |
| 보안 경로 | 15개 통과 | fw/IPS/WAF 실제 경유, 우회 차단, 표식 차단, IPS 중지·재시작 복구 |
| 실제 디코딩 | 8종 모두 통과 | nftables, Suricata, ModSecurity, osquery, Sysmon, auditd, Apache access/error |
| 부팅 복구 | 5개 서비스 active | Core, collector, osquery, Sysmon, auditd 자동 시작 |
| 증거 보존 | 20건 일치 | 재부팅 전후 event ID·원본 참조·원본 byte SHA-256 대조 |
| 선택 제외·재포함 | 통과 | SIEM 제외 시 관련 수집 서비스 중지, SIEM 볼륨 보존, 다시 설치 후 8종 수집 복구 |
| 컨테이너 경계 | 7개 확인 | read-only root, privileged 미사용, 호스트 공개 포트 없음 |

최종 재부팅 뒤 `scripts/verify-siem.py`가 정상 요청·FW 거부·WAF/IPS 표식 요청 및 `/usr/bin/true` 실행을 생성했다. **검사 시작 시각 이후 발생하고 수집된 이벤트**에 대해 실제 Wazuh `alerts.json`의 event ID·producer·원본 hash가 일치해야 성공한다. fixture만 주입하거나 과거 분석 결과를 재사용해서 통과하지 않는다. Sysmon은 시작 배너가 아닌 observation 이벤트를 요구한다. 시간대가 없는 Apache error 기본 형식은 문서화된 관측 시각을 사용한다.

최종 관측에서 격리 레코드는 0건, 수집 상태는 `ready`, Sysmon 발생 시각 대비 지연은 3초였다. 계속 들어오는 이벤트 중 분석 대기 59건의 가장 오래된 대기 시간은 3초였다. 이는 해당 시점의 상태이며 처리량 보장 수치가 아니다.

선택 제외·재포함 검사는 이번 개발 중 선행 설치본에서 수행했다. 이후 수집 성능·시각 호환성 수정과 최종 설치본의 재부팅·15개 경로 검사·8종 실수집 검사를 수행했다. 최종 소스만으로 빈 OS부터 다시 설치한 검증과 구분한다.

## 실환경에서 수정한 문제

- nftables NFLOG 메타데이터와 fw/IPS/web의 영속 로그 볼륨을 연결했다. 컨테이너가 다시 만들어져도 볼륨·inode 기반 수집 위치를 유지한다.
- auditd ENRICHED 레코드의 ASCII GS를 줄바꿈으로 오인하던 문제를 수정했다. 부분 설치에서 이미 존재하는 xOC 감사 규칙만 건너뛰도록 했다.
- Sysmon 서비스 배너·통계와 실제 관측 이벤트를 구분했다. 실제 XML의 나노초 시각을 Python 3.10·3.14 모두 마이크로초 정밀도로 동일하게 정규화한다.
- 매 로그 읽기마다 Docker exec를 실행하던 방식을 검증된 로컬 볼륨 직접 읽기로 바꿨다. Sysmon의 수집기 자체 관측 증가를 줄이고 journal 지연을 상태에 표시한다.
- Wazuh 큐 전송과 실제 디코딩 확인을 구분했다. 분석 확인 로그를 먼저 읽고 재전송하며, 중복 전송이 생겨도 로컬 조회 저장소의 event ID는 중복되지 않는다.
- 초기 파싱 오류는 원본을 보존한 상태로 재처리했다. 수정 전 오류를 삭제해서 정상으로 표시하지 않았다.

## 남은 범위

Wazuh Indexer·Dashboard, 웹 관제 UI, 원격 에이전트 인증·등록, 다중 사용자 권한 제어는 아직 구현·검증하지 않았다. 현재 조회는 로컬 관리자 CLI와 SQLite 저장소를 사용한다.

이 VM은 이전 단계의 빈 Ubuntu 설치부터 사용했지만 이번 단계에서는 설치본을 반복 갱신했다. 최종 소스의 완전 신규 설치, 운영 규모 부하, 장기 보존·디스크 고갈 복구, 패키지·이미지 digest 고정은 RC 전에 별도로 검증한다. Windows Sysmon XML은 fixture 검증 범위이며 실제 Windows VM 수집은 포함하지 않는다. CI는 기존 비활성 템플릿 상태다.

운영 명령과 지원 형식은 [SIEM 구성 문서](SIEM.md), 이전 보안 경로 설치 검증은 [VM 검증 기록](VM-VALIDATION-2026-11-07.md)을 참고한다.
