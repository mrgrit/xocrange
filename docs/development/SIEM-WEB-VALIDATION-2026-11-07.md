# Core SIEM 웹 관제 실환경 검증 — 2026-11-07

대상은 전용 Ubuntu Server 26.04.1 amd64 VM(8 vCPU·16GB RAM·300GB 디스크)이다. Wazuh 분석기·Indexer 4.14.10, 내부 OpenSearch와 Dashboards 2.19.6, Apache ModSecurity 2.9.12·CRS 3.3.8을 사용했다. [기계 판독 가능한 결과](../provenance/siem-web-acceptance-2026-11-07.json), [구성 및 예외 목록](SIEM-WEB.md), [ADR 0006](../adr/0006-siem-web-and-scoped-exclusions.md)을 함께 본다.

검증한 런타임 소스 SHA-256은 `7fff737a8024799e5d7a21bb9391c120a1079494f4d17528e4a1438c3497fbda`다. 설치기는 이 소스를 불변 release 디렉토리로 복사하고 실제 검사 통과 후 완료를 기록했다. 문서·일반 테스트 파일은 설치 소스 해시 대상에서 제외한다.

## 확인한 결과

| 항목 | 결과 |
|---|---|
| 단위·계약 검사 | 개발 Python 3.10과 VM Python 3.14에서 각각 181개 통과 |
| Compose 구성 | 검증된 SIEM UI 계획에 대해 `docker compose config --quiet` 통과 |
| 실제 보안 경로 | 정상 통신·차단·우회 방지·IPS 중단/복구 등 15개 통과 |
| 실제 Wazuh 디코딩 | nftables·Suricata·ModSecurity·osquery·Sysmon·auditd·Apache access/error 8종의 새 이벤트 통과 |
| 실제 HTTPS·WAF·UI API | 33개 통과; 설치 완료 조건에 포함 |
| 실제 Chromium 브라우저 | 로그인·4개 패널·로고·세션 재사용·Discover 검색/필터 등 11개 통과, 인증 후 HTTP 오류 없음 |
| Indexer 중단/복구 | 로컬 Wazuh 확인 지속, 오류 상태 표시, 대기 이벤트 100건 재전송 후 검색 문서 정확히 100건 |
| 웹 관제 제외 | 7개 백엔드 서비스·공개 포트 없음, UI 볼륨 6개 보존; 이후 웹 관제 재포함 |
| 빈 검색 저장소 초기화 | 개발 중 생성한 UI 데이터는 별도 보존 후 빈 UI 저장소에서 매핑·기본 화면 생성; 기존 Core 원본 DB 유지 |

브라우저는 개발 호스트의 Chromium에서 SSH 전달을 통해 VM의 실제 443 포트에 접속했다. WAF나 IPS를 생략한 직결 검사가 아니다. CA와 호스트 이름을 검증하고 테스트 브라우저는 해당 서버 공개키만 고정했다. Windows 사용자 PC에서 CA 신뢰 등록까지 수행한 검사는 아니다.

웹 관제 제외 검사는 마지막 auditd·JSON 수용 검사 보완 전 소스로 실행했다. 선택 구성은 동일하며, 최종 소스에서는 기본 웹 관제 포함 설치를 확인했다. 빈 UI 저장소 검증 역시 기존 Core VM에서 수행했으므로 모든 패키지가 없는 새 OS의 전체 설치 검증으로 표현하지 않는다.

## WAF 긍정·부정 회귀 검사

실제 인증 쿠키를 사용해 다음을 확인했다.

- 정상 로그인·세션·JavaScript·일반 검색·강조 표시·파일 경로 검색·큰 필드 목록·saved object 수정/삭제는 성공한다.
- 예외 경로에서도 익명 요청과 틀린 비밀번호는 인증을 통과하지 못한다.
- 다른 경로·메서드·필드의 공격 패턴, XSS, 파일 접근 패턴과 1MiB 초과 요청은 계속 차단된다.
- 위조한 전달 출처 헤더는 무시하며, HTTPS를 해제한 내부 경로에서도 Suricata 검증 Rule의 실제 차단 증거가 남는다.
- 전송 전용 Indexer 계정의 검색은 거부된다. 로그아웃 뒤 기존 브라우저 세션도 거부된다.

잘린 JSON은 ModSecurity 2.x의 [공식 이슈 #2807](https://github.com/owasp-modsecurity/ModSecurity/issues/2807)과 같은 500 응답이 재현됐다. 일반 JSON 문법 오류는 400으로 차단된다. 잘린 JSON 검사는 단순히 500을 허용하지 않고 동일 요청 ID에 연결된 WAF 파서 오류 증거를 확인한다. 이후 정상 요청도 다시 성공해야 한다. 이 상위 프로젝트의 상태 코드 문제를 해결했다고 주장하지 않는다.

## 설치 과정에서 해결한 문제

- HTTPS 쿠키와 프록시 경로를 일치시키고, 내부 TLS에서는 Dashboard 서버 이름을 검증하도록 구성했다.
- PROXY 프로토콜을 TLS 앞에 삽입해 생긴 Suricata 파서 오류를 제거했다. TLS 종료 후 HTTP를 IPS에 통과시킨다.
- 명시적인 JSON body processor를 활성화하여 JSON 필드가 실제 WAF 검사 대상이 되도록 했다.
- 확인된 CRS 오탐을 경로·메서드·필드 단위 예외로 제한했다. 전체 SIEM 경로나 Rule engine을 해제하지 않았다.
- journald가 긴 Sysmon 메시지를 null로 출력하는 문제를 `--all`로 해결하고 byte-array 메시지의 원본 바이트를 보존한다.
- Ubuntu 26.04에서 auditd가 `true`·`sudo`의 실제 실행 파일을 감시하도록 했다. 기존 audit 규칙을 지우지 않고 소유 규칙만 전환한다. 이미 실행 중인 auditd의 Wants인 비지속 `audit-rules` 서비스와 규칙 수정이 경합하지 않도록 했다.

## 남은 검증과 범위

연결 복구 후 동일 소스 재설치와 실제 재부팅 검증을 완료했다. 8종 원본·C1·검색 문서 24건, 자격 증명·CA·사용자 saved object가 유지됐다. 각 단계에서 보안 경로 15개·수집 8개·HTTPS 33개를 새로 통과했고, 재부팅 후 Chromium 11개도 통과했다. Indexer 중단/복구 100건 역시 새 도구로 반복 검증했다. 개발·VM 단위 검사는 수명주기 회귀 16개를 포함해 각각 197개다. [수명주기 실행 결과](../provenance/siem-lifecycle-tool-validation-2026-11-07.json)에 기록했다. 브라우저 검사는 경로를 중단하는 장애 검사와 순차 실행해야 한다. 최초 동시 실행은 페이지 재로딩 시간 초과가 발생했고, 장애 검사 종료 후 동일 코드로 11개가 통과했다.

운영 규모 부하·장기 장애·기관별 다중 사용자 권한·외부 Windows 에이전트·전체 Community 포털은 이번 범위가 아니다. 실험 버전의 기능·회귀 검증 결과이며 운영 릴리스 인증이 아니다. 비밀번호·키·원본 로그·개인 증거 참조·스크린샷은 공개 기록에 포함하지 않는다.
