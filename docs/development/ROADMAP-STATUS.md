# Core 로드맵 실행 상태

기준: 2026-11-07 확인한 `xocrange_plan@f548caa`. 정본 [CORE-KICKOFF](https://github.com/mrgrit/xocrange_plan/blob/f548caa/docs/CORE-KICKOFF.md)와 [ROADMAP](https://github.com/mrgrit/xocrange_plan/blob/f548caa/docs/ROADMAP.md)의 순서·제품 경계를 따른다. 이 문서는 구현 저장소의 진행 기록이며 정본을 대체하지 않는다.

## 현재 위치

**Wazuh Manager/API·Indexer·전용 Dashboard의 기반 연결을 구현했다. K05/K06 전체와 Community 출시는 아직 진행 중이다.** 전용 화면을 연결한 사실과 기존 기능 전체의 동등성은 구분한다.

| 구간 | 확인한 것 | 남은 것 |
|---|---|---|
| K01~K04 기반 | 선별 소스 기준선, C1 v0.2, 8종 매핑, manifest·의존성·권한·Compose 검사 | 전체 이식 자산·서비스 의존성 대조, 릴리스 단위 버전/digest 고정 |
| K05 보안 경로·설치 | Ubuntu 26.04 설치기, fw→IPS→WAF, 내부 검증 타깃, 선택형 SIEM·HTTPS, 정식 Wazuh 구성 연결 | 실제 Juice Shop/DVWA 선택 타깃, Community hosts 연계, 외부 에이전트 등록·상태 기능 |
| K06 수집·SIEM 회귀 | 8종 C1·원본 독립 분석, 처리 receipt·원본 경보 색인과 증거 연결, 검토한 kt66 fixture 대조, 전용 화면·WAF 회귀 | 전체 운영 규칙·외부 에이전트 탐지 대조, 고급 설정·규칙 편집 회귀, 장기 부하·보존 |
| K07 공통 보안 | Dashboard 자체 로그인·TLS, 내부 Manager API TLS는 있음 | 플랫폼 공통 인증·권한·세션·감사·장비 API 보호; Dashboard 로그인으로 완료 처리하지 않음 |
| K08/K09 콘솔·화면 | 정본 위치와 구성요소 catalog | 콘솔 3종, 장비 프로파일·쓰기 잠금, registry/C4/C5, portal/NOC 2층·번들 열람 |
| K10 모듈 수명주기 | fixture 계획·조합 검사, SIEM UI/전체 선택 변경의 데이터·감사 규칙 보존 | C7, 전체 설치/제거, 위조·만료·티어 거부, 실패 복원 |
| K11/K12 운영·RC | VM 설치·보존 검증 기록 | 백업·업데이트·복원·최소 사양·용량·권리 목록, G1 전체 통합 검증 |

## Wazuh 통합 순서

[ADR 0007](../adr/0007-wazuh-roadmap-alignment.md)에 따라 K05/K06의 완료 조건을 유지한다. 세부 구현 경계는 [정식 Wazuh 연동 범위](WAZUH-NATIVE.md)에 기록한다.

| 실행 ID | 작업 | 상태 / 완료 증거 |
|---|---|---|
| K05-S1 | 정식 Manager·내부 API·원본 규칙·지속 데이터 | 기반 연결 통과. 4.14.10, 설치별 계정·CA, API TLS 거부 검사, 필수 daemon, 기본 SSH 규칙 확인. 에이전트 등록·feed 범위는 별도 |
| K05-S2 | 같은 Wazuh 릴리스의 정식 Dashboard 연결 | 연결 통과. 전용 플러그인 API, 홈·서버 상태·Threat Hunting, C1 화면·로고 확인 |
| K06-S1 | 원본 Wazuh 경보 색인과 C1 연결·재전송 | 8종 원본 독립 입력·Manager 처리 receipt·경보 증거 연결 구현. kt66 4.10/후보 4.14.10 엔진 50건의 decoder·rule·level·주요 필드 비교 통과. 전체 kt66 규칙·운영 로그 동등성은 별도 |
| K06-S2 | Wazuh 전용 요청에 대한 HTTPS·세션·WAF 회귀 | 조회 범위 HTTPS/API 52개·재부팅 후 브라우저 15개 통과. 기존 제한 예외를 확대하지 않음. 고급 설정·규칙 편집은 남음 |
| K06-S3 | 보존·재설치·재부팅·Indexer 장애 | 정식 구성의 UI 제외·재활성화, 최종 소스 재설치·실제 재부팅 보존 통과. Indexer 장애 후 C1 100건·Wazuh 경보 100건과 원본 분석 경보 표본 100건 복구 통과. SIEM 전체 제외·제외 상태 재설치·재포함 보존 통과. 장기 장애는 별도 |

## 이번 증분

- 8종 원본을 C1과 독립적으로 분석하고, Manager archives의 입력 ID·frame hash·decoder로 실제 처리 완료를 확인한다. 정상/level 0/no_log 기록을 경보 유무만으로 판정하지 않는다.
- nftables 시각 형식, Linux Sysmon, osquery row wrapper와 Apache common access를 연결했다. ModSecurity는 AHZ의 상태값 생략을 처리하며 일반 403·인용 문자열·detection-only 오분류를 막는다.
- [엔진 비교 도구](../../tests/integration/native_rules.py)는 kt66 4.10.0/후보 4.14.10의 25개 입력씩을 비교한다. 50개 기대 결과가 통과했으며, 기존 분류 유지와 의도한 보완을 구분한다.
- [전체 선택 검증](../../tests/integration/siem_selection.py)에서 SIEM 제외·제외 상태 재설치·재포함을 실행했다. 일반 auditd/감사 규칙은 유지하고 xOC watch·센서만 선택에 맞게 해제/복원한다. 두 제외 상태의 증거 건수는 동일했다.
- 재포함과 실제 재부팅 때 원본/C1 24건·Wazuh 경보 24건·8종 native 처리 receipt, 두 CA와 계정·추가 API 사용자·saved search를 보존했다.
- 실제 원본 4종 재전송은 최초 경보와 네 고유 검색 문서를 유지했다. Indexer 중단 후 C1 100건·Wazuh 경보 표본 100건과 원본 분석 경보 표본 100건을 각각 복구했다. 경보 표본은 겹칠 수 있어 합산하지 않는다.

최종 소스 `9ee0b08d…`의 개발/VM 단위 검사 각각 240개, 실제 엔진 비교 50개, 보안 경로 15개, 새 C1/native 입력 각 8종, HTTPS/API 52개, 재부팅 후 브라우저 15개가 통과했다. 전체 SIEM 제외 13개·제외 상태 재설치 14개·재포함 18개·재부팅 보존 16개 검사도 통과했다. [상세 기록](WAZUH-RAW-VALIDATION-2026-11-07.md), [실행 결과](../provenance/wazuh-raw-acceptance-2026-11-07.json), [원본 분석 경계와 재실행 절차](WAZUH-RAW-SOURCES.md)를 참조한다.

이전 정식 기반 통합의 `ea511755…`/209개 단위·48개 HTTPS 검사는 [이전 기록](WAZUH-NATIVE-VALIDATION-2026-11-07.md)에 남긴다. 실험 UI 구성의 `7fff737a…`/197개 단위 검사는 [기존 실행 기록](../provenance/siem-lifecycle-tool-validation-2026-11-07.json)에 보존하며 현재 결과와 혼합하지 않는다.

## 다음 작업

1. K05/K06의 에이전트 등록·상태 기능과 실제 선택 타깃을 이어간다. 원본 직접 분석의 검증 범위를 전체 kt66 운영 규칙·외부 에이전트로 확대한다.
2. 고급 Wazuh 설정·규칙 편집의 WAF 회귀와 로컬 증거 용량·보존·복구 정책을 확정한다.
3. K07의 공통 보안을 선행해 K08 콘솔·K09 화면을 진행한다. K05/K06의 미완료 항목을 출시 게이트에서 제외하지 않는다.
