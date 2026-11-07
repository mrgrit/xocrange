# 정식 Wazuh 구성 실환경 검증 — 2026-11-07

Ubuntu Server 26.04.1 amd64 전용 VM(8 vCPU·16 GiB RAM·300 GiB 디스크)에서 Wazuh Manager/API·Indexer·전용 Dashboard 4.14.10을 연결했다. 검증한 설치 소스 SHA-256은 `ea51175547ffb005aff8fb835be43dafa664d3c1ada0b390d07cb883ea009840`다. [기계 판독 결과](../provenance/wazuh-native-acceptance-2026-11-07.json), [구현 경계](WAZUH-NATIVE.md), [로드맵 상태](ROADMAP-STATUS.md)를 함께 본다.

## 실행 결과

| 검사 | 결과 |
|---|---|
| 단위·계약 검사 | 개발 Python 3.10.12와 VM Python 3.14에서 각각 209개 통과 |
| 실제 보안 경로 | fw→Suricata→ModSecurity→대상, 우회 방지·IPS 장애 차단·복구 등 15개 통과 |
| 실제 8종 수집 | nftables·Suricata·ModSecurity·osquery·Sysmon·auditd·Apache access/error의 새 이벤트 확인 |
| HTTPS/API | 로그인·세션·WAF 예외·공격 차단·Manager API·TLS 부정 검사·최소 전송 권한 등 48개 통과 |
| 브라우저 | 재부팅 후 C1 검색·필터·로고·재로딩, Wazuh 홈·서버 상태·Threat Hunting 등 15개; 인증 후 HTTP 오류 없음 |
| 동일 소스 재설치 | 원본/C1 24건과 원본 Wazuh 경보 24건, 검색 문서·저장 화면·두 CA·계정·추가 API 사용자 보존 |
| 실제 재부팅 | 달라진 boot ID 확인, Core·collector 자동 기동, 같은 48건과 설정 보존 |
| Indexer 중단·복구 | Wazuh 분석 지속, C1 100건·원본 경보 100건 대기 확인, 재기동 후 각각 중복 없이 검색 |
| 웹 관제 제외·재활성화 | UI 서비스 중단 상태에서도 8종 수집·Manager API 지속; 재활성화 후 24+24건과 계정·CA·사용자·저장 화면 보존 |

재설치·재부팅 검사마다 보안 경로 15개·8종 새 이벤트·HTTPS/API 48개를 새로 실행했다. 남아 있던 성공 JSON으로 재검증을 대신하지 않았다. 검증 후 전용 saved search와 역할 없는 API 테스트 사용자만 정리했고 증거·볼륨·checkpoint·보고서는 보존했다.

선택 제외 시 소스는 `da5e0505…`, 재활성화 시 소스는 위 `ea511755…`였다. 두 설치 manifest를 대조해 **차이가 README 표의 문구뿐임**을 확인했다. 실행 코드·구성은 동일했고 별도로 24+24건과 설정의 보존을 대조했다. 이후 최종 `ea511755…` 자체의 동일 소스 재설치와 실제 재부팅을 따로 검증했다.

## 발견해 고친 문제

- Manager의 기본 JSON decoder·일반 오류 규칙이 C1 확인을 가로채던 문제를 전용 prefix와 level 0 grouping rule로 해결했다.
- 지속 볼륨의 PID·시작 잠금을 임시 파일시스템으로 분리하고, 선택하지 않은 daemon의 상태 반환값 때문에 Manager 전체가 실패하지 않도록 필수 daemon을 따로 검사한다.
- API 구성 형식·인증서 경로·RBAC 권한 초기화를 실제 Manager에 맞췄다. 기존 Indexer 보안 DB에는 설치기 소유 전송 role만 갱신한다.
- Dashboard API 클라이언트의 상위 TLS 검증 비활성화를 한 곳에서 수정했다. 실제 Dashboard 이미지에서 잘못된 CA·서버 이름의 거부를 확인했다.
- Manager가 준비된 뒤 Dashboard를 시작하고, 첫 접속에 필요한 native 검색 패턴·주간 색인을 초기화했다. 첫 화면의 404와 로고 누락을 해결했다.
- 검색 문서의 5초 refresh 지연을 checkpoint 실패로 오인하던 검증 도구를 수정했다. 같은 기준 문서의 검색 가능 여부를 제한 시간 안에 기다리며 회귀 검사를 추가했다.
- 설치 중 밀린 C1 때문에 새 로그가 계속 대기하지 않도록 오래된 이벤트와 새 이벤트를 함께 처리한다.

WAF Rule 예외의 범위는 이번 통합에서 확대하지 않았다. 정상 전용 화면 요청이 통과하는 것과 다른 필드의 XSS·LFI, 위조 출처 헤더, 과대 요청 등이 계속 차단되는 것을 함께 확인했다. ModSecurity 2.x의 잘린 JSON 처리 문제는 상위 동작으로 남는다. 해당 요청은 WAF에서 HTTP 500으로 차단되며, 일반 비정상 JSON은 400을 반환한다.

## 해석 범위

8종은 현재 C1 decoder로 확인한다. 원본 Wazuh 경보 보존·색인과 C1 연결을 추가했고, 기본 SSH 규칙 5710은 별도의 합성 queue 로그로 확인했다. 실제 SSH 로그인 공격이나 호스트 사용자 변경을 하지 않았다. 이것을 8종 원본의 기본 Wazuh 직접 디코딩·기존 kt66 탐지 동등성 완료로 표현하지 않는다.

이번 검증은 기존 전용 VM의 업그레이드·재설치·선택 변경·재부팅이다. 최종 native 번들을 새 OS 디스크에 처음부터 설치하는 검증은 이번 증분에서 반복하지 않았다. 외부 에이전트 등록, 호스트/에이전트 SCA·취약점 feed·inventory, 모든 고급 설정·규칙 편집, SIEM 전체 제외, 공통 RBAC, 장기 부하·보존·백업은 후속 수용 조건이다. 로컬 증거 DB의 현재 4 GiB 수집 한도도 운영 용량 검증에서 다룬다.

이전 일반 OpenSearch 화면의 검증 기록은 별도 파일로 보존한다. 이번 결과를 Community 출시나 Wazuh 전체 기능 동등성으로 확대하지 않는다. 비밀번호·키·원본 로그·증거 ID·스크린샷은 공개 보고서에 포함하지 않는다.
