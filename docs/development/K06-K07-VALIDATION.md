# K06/K07 검증 기록

2026-11-07~08 검증 대상은 전용 xoc VM의 Ubuntu Server 26.04.1, 8 vCPU·16 GiB RAM 환경이다. kt66 원본은 읽기 전용으로 참조했다. 실제 Windows 게스트나 별도 호스트에서의 에이전트 통신을 검증했다고 표현하지 않는다.

검증 소스 SHA-256: `1f426ab45380828da888532a6def0fc9762760443acdd9e994b83f3aef79ca30`. 소스 묶음의 파일별 SHA를 정렬한 JSON의 SHA이며 Git commit ID와 구분한다. 최신 실행 증거는 [공개 결과 JSON](../provenance/k06-k07-acceptance.json)에 수록한다. 비밀번호·에이전트 키·세션 쿠키·개인 상태 checkpoint는 공개 결과에 포함하지 않는다.

## 확인 항목

| 검증 | 결과 |
|---|---|
| 단위·계약·CLI·Django·보존 검사 | 개발 호스트 275개, Ubuntu 26.04 VM 275개 통과 |
| 실제 Wazuh 엔진 | kt66 4.10 / 후보 4.14.10 각각 26건, 합계 52건 통과 |
| 실제 보안 경로 | nftables→Suricata→ModSecurity 15개 통과 |
| 공통 관리 설치 검사 | 로그인 화면·JS·익명 세션·익명 장비/계정/감사 거부 6개 통과 |
| 8종 수집 | 새 C1 8종과 독립 native 처리 receipt 8종 통과 |
| SIEM HTTPS·WAF·검색 | 52개 통과 |
| 고급 Wazuh 요청 | 규칙 CRUD·설정 검증·logtest·잘못된 XML 보존·익명 편집 거부·다른 필드/경로 차단 17개 통과 |
| Core 보안 HTTPS | 로그인·역할·CSRF·세션 폐기·정책 버전·감사 전후 값·TCP 우회·민감값 로그 미기록 30개 통과 |
| 실제 Linux 에이전트 | 등록·동일 키 재등록·5710 탐지·통신 단절/재연결·재시작·중복 방지·테스트 자원 제거 13개 통과 |
| Core 실제 브라우저 | 로고·로그인·3개 장비 정책·계정/감사 화면·세션·로그아웃 9개 통과 |
| Wazuh 실제 브라우저 | 로그인·4개 패널·검색·세션·native 홈/상태/탐지 화면 15개 통과 |
| SIEM 선택 수명주기 | 전체 제외 19개, 제외 상태 재설치 20개, 재포함 19개 통과 |
| 실제 재부팅 | 원본·C1·native 경보·계정·키·정책 보존 17개와 부팅 후 새 수집/HTTPS 통과 |
| Indexer 단절·복구 | Wazuh 분석 지속·장애 상태 표시·대기 C1 100건 및 native 경보 복구·중복 방지 통과 |

SIEM 전체 제외·제외 상태 재설치·재포함과 실제 재부팅 결과는 공개 JSON의 개별 보고서에 기록한다. 각 단계는 같은 소스와 24개 원본/C1·24개 native 경보 표본, 8종 receipt, CA·계정, 사용자 생성 Wazuh API 계정·saved search, Core 계정/암호 해시/역할/서명 키/장비 정책을 대조한다. 원본과 정규화 증거 건수는 SIEM 제외 상태 재설치 동안 변하지 않아야 한다.

최종 상태 수집 시 collector 재시작 0회, 입력/분석 격리 0건, native 입력 오류 0건이었다. 계속 생성되는 로그의 대기 건수는 453건·최장 4초였으며, 색인 대기는 0건이었다. 장애 시험의 C1·native·raw-source 복구 건수는 서로 겹칠 수 있으므로 합산하지 않는다. 시험용 에이전트·Wazuh API 계정·saved search·audit watch를 제거했으며, Core 시험 계정은 감사 이력을 유지한 채 비활성화했다. 원본 및 영속 볼륨은 유지했다.

## 실환경에서 발견해 수정한 문제

- 기존 8 GiB 수집 예산에 도달했을 때 audit flush 예외로 collector가 반복 재시작했다. 쓰기 제한을 상태로 보고하면서 cursor·미확인 입력을 보존하도록 수정하고, 수집/분석 공간과 파일시스템 여유를 분리했다.
- Wazuh 날짜별 hardlink·gzip archive에서 읽지 못한 꼬리를 복구하고, 높은 Sysmon 입력 때문에 드문 소스가 밀리지 않도록 전송 몫을 나눴다. 5분 정리 작업에는 별도의 10분 상태 유효 시간을 적용한다.
- 재부팅 때 관측한 Apache `"-" 408` 연결 시간초과 형식에 디코더를 추가했다. 원본 바이트와 IP·상태·크기를 유지하며, 요청 메서드나 URL을 만들어 넣지 않는다. 누락 처리였던 기록은 규칙 revision 갱신 후 자동 재전송한다.
- 비ASCII 원본 경보의 HTTP 전송을 UTF-8로 수정했다. 원본 필드·바이트는 저장소에 유지한다.
- 규칙 편집은 관측한 CRS ID의 해당 XML 필드만 예외로 삼고, Wazuh API에 필요한 임시 경로만 tmpfs로 제공한다. 잘못된 XML의 기존 파일 보존을 실제 API로 확인했다.
- 에이전트 최초 설정 동기화 중 수집기 재시작 구간의 로그 누락을 발견했다. `only-future-events=no`로 중지 중 기록을 이어 읽고 재시작 중복까지 검사했다.
- 탐지 결과 중 전역 첫 100건을 조회하던 검사에서는 높은 Sysmon 입력이 다른 소스를 가렸다. 원천별 기대 rule·evidence 연결을 직접 조회하도록 바꿨다.

## 재실행 도구와 경계

`pytest`, `scripts/verify-management.py`, `scripts/verify-platform.py`, `scripts/verify-siem.py`, `scripts/verify-siem-ui.py`, `tests/integration/{native_rules,siem_advanced,agent_transport,siem_selection,siem_lifecycle}.py`, `tests/browser/{platform_browser,siem}.py`를 사용한다. 수명주기 검증은 부팅 자동 점검(`ExecStartPost`)이 끝나 Core unit이 active가 된 뒤 실행해 IPS 중단 시험의 충돌을 피한다. 통합 검증은 전용 VM에서 root로 실행하며, 실제 설정 변경·서비스 중단·시험 계정 생성이 있다. 설치기는 계정을 바꾸지 않는 6개 공통 관리 검사를 자동 실행한다. 전체 Core 보안 검증은 초기 암호 변경과 시험 계정 비활성화를 포함하므로 설치 때 자동 실행하지 않는다.

Core와 Wazuh의 계정·세션은 별개다. Windows 평가판 번들은 M6, 실제 장비 설정 preview/apply/configtest/rollback은 K08이다. 전체 디스크 고갈·원천 로그 회전·장기 부하·백업·업데이트·복원은 K11 출시 게이트다. 본 검증을 무제한 보존이나 Community 전체 완성으로 해석하지 않는다.
