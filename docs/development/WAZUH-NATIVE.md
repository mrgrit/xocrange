# 정식 Wazuh 연동 범위

로드맵 K05-S1/S2와 K06의 연동 작업이다. Manager·Indexer·Dashboard는 4.14.10으로 맞춘다. 일반 OpenSearch Dashboards에서 Wazuh 전용 플러그인이 포함된 Dashboard로 전환하며 기존 C1 화면과 저장 객체를 유지한다. [출처·이미지 digest·수정 내용](../provenance/wazuh-native-sources.json), [상위 라이선스](../licenses/WAZUH-GPL-2.0.txt)를 보관한다.

## 구성과 보존

- Manager는 API, DB, 분석기, remoted, logcollector, syscheck, modules, execd, monitord를 실행한다. 기본 decoder·rule·CDB 목록과 xOC C1 decoder/rule을 함께 읽는다.
- `siem-etc`, `siem-api`, `siem-queue`, `siem-var`, `siem-logs`에 설정·RBAC·DB·경보를 유지한다. PID와 시작 잠금은 임시 파일시스템에 둔다. 재시작 때 DB seed로 덮어쓰지 않는다.
- `ossec.conf`, xOC C1/native decoder/rule, API TLS 설정과 기본 서비스 계정은 설치기가 관리하며 기동 시 배포 정의로 맞춘다. 이 파일을 화면에서 직접 바꾼 내용은 유지 대상이 아니다. 별도 사용자 decoder/rule 디렉토리와 추가 API 사용자·RBAC DB는 초기화하지 않는다. 전체 설정 편집 수명주기는 후속 작업이다.
- Manager API는 내부망의 검증된 HTTPS만 사용한다. 설치별 `wazuh`·`wazuh-wui` 비밀번호와 별도 CA는 관리자 전용 `/var/lib/xocrange/manager`에 보관한다. Compose 환경 변수와 이미지에 비밀번호를 넣지 않는다.
- Dashboard의 상위 API 클라이언트에 있던 `rejectUnauthorized:false`를 검토한 한 곳에서 `true`로 바꾸고 Manager CA를 신뢰한다. 이미지 digest와 수정 대상 개수가 달라지면 이미지 빌드를 실패시킨다. Indexer와 외부 HTTPS의 검증도 유지한다.
- Manager는 읽기 전용 root filesystem, 내부 네트워크, 검토된 named volume과 제한 capability를 사용한다. `FOWNER`는 RBAC 파일 권한 조정, `KILL`은 다른 UID로 실행되는 자체 daemon의 상태 확인과 종료에 필요하다. 호스트 PID·Docker socket·privileged 모드는 사용하지 않는다.
- 선택하지 않은 daemon 때문에 상위 `wazuh-control status`가 1을 반환하는 것을 서비스 전체 장애로 오인하지 않는다. 대신 필요한 daemon을 각각 검사한다. 실제 필수 daemon이 죽으면 container도 실패한다.

## 경보와 C1

8종 로그 → 원본 보관 → C1 → Wazuh 확인 → `xoc-events-*` 경로를 유지한다. C1 메시지에 전용 prefix를 붙이고 level 0 grouping rule 아래 소스별 rule을 둔다. 기본 JSON decoder나 일반 오류 문자열 rule이 C1 확인을 가로채는 문제를 방지한다. 다른 Wazuh rule로 발생한 경보는 C1 처리 성공으로 인정하지 않는다.

Wazuh `alerts.json`의 원본 바이트와 SHA-256, 원본 경보 문서를 별도의 SQLite outbox에 저장한다. 같은 transaction에서 파일 cursor를 갱신하고, Indexer 개별 응답이 성공한 문서만 처리 완료한다. `wazuh-alerts-4.x-*`는 상위 Wazuh 매핑을 사용한다. `xoc.event_id`·`xoc.evidence_ref`로 확인된 C1과 연결하고 원본 필드는 유지한다. Manager 경보를 다시 C1 수집기에 넣지 않는다.

Indexer 장애 중 두 경로를 보존하고 재시도한다. 안정된 문서 ID로 재전송 중복을 막는다. 복구 시 새 이벤트와 오래된 C1을 나누어 보내 어느 쪽도 계속 대기하지 않게 한다. 전송 계정은 두 namespace의 쓰기만 허용한다. 업그레이드에서는 설치기 소유 전송 role만 갱신하며 다른 사용자·role을 초기화하지 않는다. C1·원본 경보 검색 색인은 7일 보존 정책을 사용한다. 웹 관제를 선택한 동안에는 미전송 로컬 증거를 전송 확인 전 삭제하지 않는다. 웹 관제를 제외한 구성은 로컬 7일 보존 정책을 적용한다.

## 이번 단계의 경계

전용 화면, Manager API, 기본 규칙, 원본 경보 색인과 C1 연결을 통합하는 단계다. 아래는 별도 K05/K06 이후 수용 조건으로 남는다.

- [8종 원본 분석 경로](WAZUH-RAW-SOURCES.md)는 별도 입력·처리 확인과 검토한 kt66/Wazuh fixture 비교까지 구현했다. 실제 kt66 운영 로그 전체·모든 규칙·Windows 에이전트와 동등하다는 의미는 아니다.
- 외부 Linux/Windows 에이전트 등록과 포트 정책. 현재 1514/1515를 호스트에 공개하지 않고 authd를 활성화하지 않는다.
- 호스트/외부 에이전트의 전체 SCA·취약점·inventory 상태 색인과 feed 정책. 컨테이너 자신의 syscheck/syscollector 실행을 호스트 전체 검사로 표현하지 않는다. SCA·rootcheck·취약점 feed·자동 active response는 이번 기본 구성에서 활성화하지 않는다.
- 로컬 증거 DB의 현재 8 GiB 신규 수집 중단 기준, native 경보 추가에 따른 용량 산정과 장기 보존·복구 정책. 한도 도달 시 수집을 중단하며 이 단계의 단기 장애 검증이 무제한 보존을 뜻하지 않는다.
- Filebeat GeoIP 등 추가 enrich, Wazuh 고급 설정·규칙 편집의 모든 WAF 회귀, 플랫폼 공통 RBAC·다중 사용자 분리, 대규모 장기 운영.

따라서 전용 화면의 로그인·조회 성공만으로 기존 Wazuh 기능 전체의 동등성이나 Community 출시 완료를 표시하지 않는다. 기반 통합은 [이전 기록](WAZUH-NATIVE-VALIDATION-2026-11-07.md), 원본 분석·전체 선택·재부팅은 [후속 검증](WAZUH-RAW-VALIDATION-2026-11-07.md)과 로드맵 상태에 남긴다.
