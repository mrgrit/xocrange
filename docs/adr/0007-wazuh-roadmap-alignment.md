# ADR 0007: Wazuh 기능 유지와 단계별 완료 조건

- 상태: 개발 기준, 2026-11-07
- 근거: 사용자의 기존 기능 유지 요구와 `xocrange_plan@f548caa`의 [CORE-KICKOFF §2·4·6](https://github.com/mrgrit/xocrange_plan/blob/f548caa/docs/CORE-KICKOFF.md)
- 관계: [ADR 0005](0005-core-telemetry.md)·[ADR 0006](0006-siem-web-and-scoped-exclusions.md)의 실험 범위를 명확히 하고, ADR 0006의 일반 OpenSearch Dashboards 선택을 최종 제품 구성으로 확정하지 않는다.

## 결정

Core SIEM의 목표는 정식 Wazuh Manager·Indexer·Dashboard와 기존 원본 경보 경로를 유지하고, 그 위에 C1 통합 조회를 제공하는 것이다. 무료 구성요소의 선택 설치와 전체 Community의 기능 범위를 구분한다.

이 ADR을 작성한 시점의 구현은 Wazuh 분석 엔진에 정규화된 C1을 보내 분석 확인을 받고, Wazuh Indexer의 `xoc-events-*`와 일반 OpenSearch Dashboards로 조회한다. 이 경로는 실제로 검증했지만 정식 Manager 전체 서비스·API, Wazuh 전용 Dashboard 플러그인, 원본 경보 색인까지의 호환을 검증한 것은 아니다. 로그인·검색 성공이나 버전 일치만으로 기존 Wazuh 기능이 유지됐다고 판정하지 않는다.

정식 구성의 통합은 K05/K06 안에서 진행한다. 그 완료 조건을 G1 이후로 미루거나 기존 Wazuh 기능을 없애는 것으로 로드맵을 바꾸지 않는다. 한편 M17의 고급 엔드포인트 에뮬레이션·자동 공격, 기관 운영과 Live Fire의 다중 사용자 기능을 이번 작업에 앞당겨 포함하지 않는다.

후속 정식 구성과 실제 검증 결과는 [Wazuh 통합 범위](../development/WAZUH-NATIVE.md)와 [로드맵 실행 상태](../development/ROADMAP-STATUS.md)에서 관리한다. 아래 완료 조건은 그대로 적용한다.

## 이어갈 구현 단위

1. **K05-S1:** 정식 Manager 서비스·내부 API·원본 규칙과 지속 데이터를 구성한다. 설치별 자격 증명과 검증된 TLS를 사용하고 관리 API를 호스트에 무조건 공개하지 않는다.
2. **K05-S2:** Manager·Indexer와 맞는 Wazuh Dashboard를 연결한다. Manager API 연결, 제품 버전, 초기 사용자, 세션과 전용 화면을 실제로 확인한다. C1 화면과 README 로고도 유지한다.
3. **K06-S1:** 원본 수집 → Wazuh 경보와 C1 문서의 연결을 보존한다. 원본 경보 색인, 안정된 ID, 재전송·중복 제거·격리·보존을 검증하고 C1이 수집 경로를 다시 순환하지 않게 한다.
4. **K06-S2:** Wazuh 전용 로그인·API·검색·설정의 실제 요청을 기준으로 WAF 예외를 재검증한다. 기존 Rule 예외를 통째로 넓히지 않는다.
5. **K06-S3:** 선택 제외/재포함·재설치·재부팅·Indexer 장애의 보존 검증을 완료한다. 실험 화면의 결과와 정식 Wazuh 결과를 각각 기록한다.

각 단위는 검증 가능한 변경으로 진행하며, 실환경 검증을 하지 않은 변경을 배포 완료로 표시하지 않는다. 상세 상태는 [로드맵 실행 상태](../development/ROADMAP-STATUS.md)에 기록한다.

## 기존 작업의 사용

8종 수집·원본 보관·C1 계약·설치 조립·TLS·WAF 예외와 검증 코드는 이어서 사용한다. 현재 통과 기록은 해당 실험 구성에 대한 증거로 보존한다. 정식 Wazuh 구성으로 바뀌면 그 구성에서 수용 검사를 다시 실행한다.

전체 Community 또는 Wazuh 기능 동등성의 완료 표시는 정식 구성과 로드맵의 수용 조건을 충족한 이후에만 한다.
