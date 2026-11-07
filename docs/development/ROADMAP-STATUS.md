# Core 로드맵 실행 상태

기준: 2026-11-07 확인한 `xocrange_plan@f548caa`. 정본 [CORE-KICKOFF](https://github.com/mrgrit/xocrange_plan/blob/f548caa/docs/CORE-KICKOFF.md)와 [ROADMAP](https://github.com/mrgrit/xocrange_plan/blob/f548caa/docs/ROADMAP.md)의 순서·제품 경계를 따른다. 이 문서는 구현 저장소의 진행 기록이며 정본을 대체하지 않는다.

## 현재 위치

**Wazuh Manager/API·Indexer·전용 Dashboard의 기반 연결을 구현했다. K05/K06 전체와 Community 출시는 아직 진행 중이다.** 전용 화면을 연결한 사실과 기존 기능 전체의 동등성은 구분한다.

| 구간 | 확인한 것 | 남은 것 |
|---|---|---|
| K01~K04 기반 | 선별 소스 기준선, C1 v0.2, 8종 매핑, manifest·의존성·권한·Compose 검사 | 전체 이식 자산·서비스 의존성 대조, 릴리스 단위 버전/digest 고정 |
| K05 보안 경로·설치 | Ubuntu 26.04 설치기, fw→IPS→WAF, 내부 검증 타깃, 선택형 SIEM·HTTPS, 정식 Wazuh 구성 연결 | 실제 Juice Shop/DVWA 선택 타깃, Community hosts 연계, 외부 에이전트 등록·상태 기능 |
| K06 수집·SIEM 회귀 | 8종 C1·원본 SHA-256, Wazuh 기본 규칙·원본 경보 색인과 C1 연결, 전용 화면·WAF 회귀 | 8종 원본 직접 입력의 native 탐지 대조, 고급 설정·규칙 편집 회귀, 장기 부하·보존 |
| K07 공통 보안 | Dashboard 자체 로그인·TLS, 내부 Manager API TLS는 있음 | 플랫폼 공통 인증·권한·세션·감사·장비 API 보호; Dashboard 로그인으로 완료 처리하지 않음 |
| K08/K09 콘솔·화면 | 정본 위치와 구성요소 catalog | 콘솔 3종, 장비 프로파일·쓰기 잠금, registry/C4/C5, portal/NOC 2층·번들 열람 |
| K10 모듈 수명주기 | fixture 계획·조합 검사, SIEM UI 선택 보존 | C7, 전체 설치/제거, 위조·만료·티어 거부, 실패 복원 |
| K11/K12 운영·RC | VM 설치·보존 검증 기록 | 백업·업데이트·복원·최소 사양·용량·권리 목록, G1 전체 통합 검증 |

## Wazuh 통합 순서

[ADR 0007](../adr/0007-wazuh-roadmap-alignment.md)에 따라 K05/K06의 완료 조건을 유지한다. 세부 구현 경계는 [정식 Wazuh 연동 범위](WAZUH-NATIVE.md)에 기록한다.

| 실행 ID | 작업 | 상태 / 완료 증거 |
|---|---|---|
| K05-S1 | 정식 Manager·내부 API·원본 규칙·지속 데이터 | 기반 연결 통과. 4.14.10, 설치별 계정·CA, API TLS 거부 검사, 필수 daemon, 기본 SSH 규칙 확인. 에이전트 등록·feed 범위는 별도 |
| K05-S2 | 같은 Wazuh 릴리스의 정식 Dashboard 연결 | 연결 통과. 전용 플러그인 API, 홈·서버 상태·Threat Hunting, C1 화면·로고 확인 |
| K06-S1 | 원본 Wazuh 경보 색인과 C1 연결·재전송 | 두 outbox와 원본 경보 색인 구현. 8종 C1 연결과 별도 SSH 기본 규칙 확인. 8종 원본 직접 디코딩·kt66 탐지 대조는 남음 |
| K06-S2 | Wazuh 전용 요청에 대한 HTTPS·세션·WAF 회귀 | 조회 범위 HTTPS/API 48개·브라우저 15개 통과. 기존 제한 예외를 확대하지 않음. 고급 설정·규칙 편집은 남음 |
| K06-S3 | 보존·재설치·재부팅·Indexer 장애 | 정식 구성의 UI 제외·재활성화, 최종 소스 재설치·실제 재부팅 보존 통과. Indexer 장애 후 C1 100건·원본 경보 100건 복구 통과. SIEM 전체 제외와 장기 장애는 별도 |

## 이번 증분

- Manager API와 전용 Dashboard를 연결하고, 원본 Wazuh 경보 바이트·SHA-256·문서를 별도로 보관·전송한다. C1 연결을 유지하며 다시 수집 경로로 순환시키지 않는다.
- 기본 규칙과 C1 규칙의 충돌을 방지하고, 기존 Indexer 보안 DB의 설치기 소유 전송 role만 갱신한다.
- [수명주기 검증 도구](../../tests/integration/siem_lifecycle.py)는 8종 원본/C1 24건과 원본 Wazuh 경보 24건, 두 CA·자격 증명, 사용자 saved search, 별도 Manager API 사용자를 대조한다.
- `verify --after reinstall`은 다른 설치 실행 기록을, `verify --after reboot`는 달라진 boot ID를 요구한다. 매번 보안 경로·8종·HTTPS 검사를 새로 실행한다.
- Indexer 중단 후 C1 100건과 원본 경보 100건의 대기·중복 없는 복구를 확인한다. 검사 중 예외가 발생해도 재기동을 시도한다.
- [실행 절차](SIEM-LIFECYCLE-VALIDATION.md)에서 준비·재설치·재부팅·정리를 구분한다. 설치기와 검증 도구는 같은 잠금을 사용하며 증거·볼륨을 삭제하지 않는다.

최종 소스 `ea511755…`에서 개발·VM 단위 검사 각각 209개, 보안 경로 15개, 8종 새 이벤트, HTTPS/API 48개, 재부팅 후 브라우저 15개가 통과했다. 재설치·재부팅 때 원본/C1 24건과 원본 Wazuh 경보 24건, 두 CA·계정·저장 화면·추가 API 사용자를 보존했다. [상세 검증 기록](WAZUH-NATIVE-VALIDATION-2026-11-07.md)과 [실행 결과](../provenance/wazuh-native-acceptance-2026-11-07.json)를 참조한다.

이전 실험 구성의 197개 단위 검사, 33개 HTTPS 검사, 11개 브라우저 검사와 수명주기 결과는 [기존 실행 기록](../provenance/siem-lifecycle-tool-validation-2026-11-07.json)에 보존한다. 그 기록의 런타임 소스는 `7fff737a…`이며 정식 구성의 결과와 혼합하지 않는다.

## 다음 작업

1. K05/K06의 남은 8종 원본 직접 디코딩·기존 탐지 대조, 에이전트 등록·상태 기능, 실제 선택 타깃과 전체 SIEM 선택 회귀를 이어간다.
2. 고급 Wazuh 설정·규칙 편집의 WAF 회귀와 로컬 증거 용량·보존·복구 정책을 확정한다.
3. K07의 공통 보안을 선행해 K08 콘솔·K09 화면을 진행한다. K05/K06의 미완료 항목을 출시 게이트에서 제외하지 않는다.
