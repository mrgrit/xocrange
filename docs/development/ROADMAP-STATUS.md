# Core 로드맵 실행 상태

기준: 2026-11-07 확인한 `xocrange_plan@f548caa`. 정본 [CORE-KICKOFF](https://github.com/mrgrit/xocrange_plan/blob/f548caa/docs/CORE-KICKOFF.md)와 [ROADMAP](https://github.com/mrgrit/xocrange_plan/blob/f548caa/docs/ROADMAP.md)의 순서·제품 경계를 따른다. 이 문서는 구현 저장소의 진행 기록이며 정본을 대체하지 않는다.

## 현재 위치

**현재는 K05/K06 진행 중이다. 정식 Wazuh 통합이나 Community 출시가 완료된 상태가 아니다.**

| 구간 | 확인한 것 | 남은 것 |
|---|---|---|
| K01~K04 기반 | 선별 소스 기준선, C1 v0.2, 8종 매핑, manifest·의존성·권한·Compose 검사 | 전체 이식 자산·서비스 의존성 대조, 릴리스 단위 버전/digest 고정 |
| K05 보안 경로·설치 | Ubuntu 26.04 설치기, fw→IPS→WAF, 내부 검증 타깃, 선택형 SIEM·HTTPS | 정식 Wazuh Manager/API·Dashboard, 실제 Juice Shop/DVWA 선택 타깃, Community hosts 연계 |
| K06 수집·SIEM 회귀 | 8종 C1·원본 SHA-256, Wazuh 분석 확인, 실험 검색 화면, WAF 예외·Indexer 장애 복구 | Wazuh 원본 경보 경로·전용 화면과 C1 연결, 최종 구성의 재설치·재부팅·선택 회귀 |
| K07 공통 보안 | Dashboard 자체 로그인·TLS는 있음 | 플랫폼 공통 인증·권한·세션·감사·장비 API 보호; Dashboard 로그인으로 완료 처리하지 않음 |
| K08/K09 콘솔·화면 | 정본 위치와 구성요소 catalog | 콘솔 3종, 장비 프로파일·쓰기 잠금, registry/C4/C5, portal/NOC 2층·번들 열람 |
| K10 모듈 수명주기 | fixture 계획·조합 검사 | C7, 설치/제거, 위조·만료·티어 거부, 실패 복원 |
| K11/K12 운영·RC | 일부 VM 설치·보존 검증 기록 | 백업·업데이트·복원·최소 사양·권리 목록, G1 전체 통합 검증 |

## Wazuh 통합 순서

[ADR 0007](../adr/0007-wazuh-roadmap-alignment.md)에 따라 아래 작업을 K05/K06의 완료 조건으로 유지한다.

| 실행 ID | 작업 | 상태 / 완료 증거 |
|---|---|---|
| K05-S1 | 정식 Manager·내부 API·원본 규칙·지속 데이터 | 대기. 현재는 분석 엔진만 실행 |
| K05-S2 | 같은 Wazuh 릴리스의 정식 Dashboard 연결 | 대기. 현재 일반 OpenSearch 화면은 실험 검증용 |
| K06-S1 | 원본 Wazuh 경보 색인과 C1 연결·재전송 | 대기. 현재 C1 분석 확인 경로와 구별해 검증 필요 |
| K06-S2 | Wazuh 전용 요청에 대한 HTTPS·세션·WAF 회귀 | 대기. 현재 실험 화면의 33개 API·11개 브라우저 검사는 보존 |
| K06-S3 | 보존·재설치·재부팅·Indexer 장애 | 실험 구성 통과: 동일 소스 재설치·실제 재부팅·24건 보존·100건 장애 복구·브라우저 11개. 정식 구성으로 전환 후 반복 필요 |

## 이번 증분

- [수명주기 검증 도구](../../tests/integration/siem_lifecycle.py): 관리자 전용 기준 상태를 만들고 8종 증거 24건, CA·자격 증명, saved object와 검색 문서를 대조한다.
- `verify --after reinstall`은 다른 설치 실행 기록을, `verify --after reboot`는 달라진 boot ID를 요구한다. 과거 결과 파일만 보고 통과하지 않고 실제 경로·8종·HTTPS 검사를 다시 실행한다.
- Indexer 중단 후 로컬 분석 확인과 대기를 관찰하고 복구 뒤 문서 수를 확인한다. 검사 중 예외가 발생해도 재기동을 시도한다.
- 설치기와 검증 도구는 같은 잠금을 사용한다. 기존 checkpoint·로그·볼륨·자격 증명을 덮어쓰거나 삭제하지 않는다.
- [실행 절차](SIEM-LIFECYCLE-VALIDATION.md)에서 준비·재설치·재부팅·정리 단계를 구분한다.

검증 도구를 VM Python 3.14에서 실행했다. 동일 소스 재설치와 실제 재부팅에서 8종 원본·C1·검색 문서 24건, 계정·CA·saved object 보존을 확인했다. 각 단계에서 보안 경로 15개·8종 수집·HTTPS 33개를 새로 실행했다. 재부팅 후 Chromium 11개도 통과했다. 개발·VM 단위 검사는 각각 197개 통과했다. [실행 결과](../provenance/siem-lifecycle-tool-validation-2026-11-07.json)를 참조한다. 이 기록의 런타임 소스는 `7fff737a…`다.

## 다음 작업

1. 완료한 실험 구성의 K06-S3 증거를 보존한다.
2. K05-S1 → K05-S2 → K06-S1/S2 순서로 정식 Wazuh를 연결하고 같은 검증을 반복한다.
3. K07의 공통 보안을 선행해 K08 콘솔·K09 화면을 진행한다. K05/K06의 미완료 항목을 출시 게이트에서 제외하지 않는다.
