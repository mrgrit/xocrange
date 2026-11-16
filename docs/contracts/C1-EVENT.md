# C1 이벤트 계약 v0.1 / v0.2

상태: K03 기반 + K06의 v0.2 확장. 새 정규화 출력은 `xoc.event/0.2.0`이며 기존 v0.1 이벤트 검증을 유지한다. 버전이 식별 입력에 포함되므로 v0.1→v0.2 재변환은 새 event ID를 만든다. [정식 스키마](../../src/xocrange/contracts/c1-event.json), [정규화기](../../src/xocrange/events.py), [합성 fixture](../../tests/fixtures/events/).

## 범위와 신뢰 경계

한 번에 최대 1 MiB의 소스 레코드 하나를 입력받아 C1 이벤트 배열을 반환한다. Suricata EVE alert, ModSecurity **2.x JSON audit**, kt66/xoc 접두사의 nftables 커널 로그를 지원한다. v0.2는 osquery 결과·Sysmon XML·auditd 이벤트 묶음·Apache access/error도 지원한다. EVE의 다른 유형과 ModSecurity 3.x/native audit는 현재 수집 프로필의 지원 범위 밖이다. 파일 수집·재시도·보관은 [SIEM 구현](../development/SIEM.md)을 따른다. fixture는 예약된 문서용 IP를 사용한 합성 자료이며 실제 고객 트래픽을 포함하지 않는다.

`tenant_id`, `range_id`, `source_id`는 호출자의 Context에서만 가져온다. 원본 로그의 동일 이름 필드를 신뢰하지 않는다. CLI 인수 자체가 인증 수단은 아니다. 실제 수집기는 인증된 source 등록과 Context를 결합해야 한다. 로그 접두사·producer 표식도 출처 인증을 대신하지 않는다. ID 필드만으로 다중 사용자 격리가 완성되지 않는다.

## 필드와 식별

| 필드 | 의미 |
|---|---|
| `schema_version` | `xoc.event/0.1.0` |
| `event_id` | 아래 식별 입력의 canonical JSON에 대한 SHA-256 |
| `tenant_id`, `range_id`, `source_id` | 수집 컨텍스트가 정한 범위·생성원 |
| `timestamp` | 원본 발생 시각을 UTC로 변환; 없으면 수집 시각 |
| `observed_at` | 호출자가 제공한 실제 수집 시각, UTC |
| `time_basis` | 발생 시각 출처: `source` 또는 `observed` |
| `event` | 유형·동작·결과·0~100 severity |
| `network` | IP·port·protocol의 제한된 메타데이터 |
| `rule` | 소스 rule ID와 원래 severity |
| `correlation` | transaction, 부모 event ID, 메시지 순번 |
| `evidence` | 비밀값 없는 원본 참조와 입력 바이트 SHA-256 |

식별 입력은 `[schema_version, tenant_id, range_id, source_id, producer, evidence_ref, raw_sha256, discriminator]`이다. JSON은 UTF-8, 키 정렬, 공백 없는 구분자로 직렬화한다. `discriminator`는 EVE의 `alert`, nftables의 `packet`, ModSecurity의 `transaction` 또는 `message:<0부터 시작하는 순번>`이다.

같은 레코드 참조·원본 바이트·범위를 재처리하면 수집 시각이 달라도 ID가 같다. 별개 레코드는 내용이 같더라도 다른 `evidence_ref`를 사용해야 한다. 추후 수집기는 파일 세대/offset 또는 메시지 offset 등으로 안정된 참조를 발급하고, 중복 재처리 시 최초 관측 시각을 보존해야 한다. 현재 정규화기는 보관·중복 제거 상태를 갖지 않는다.

UTC offset 없는 시각과 잘못된 날짜는 거부한다. EVE의 `+0900`, ISO의 `+09:00`·`Z`를 지원한다. 원본 시각이 없거나 연도/시간대가 없는 BSD syslog이면 `time_basis=observed`를 명시한다. 빈 문자열이나 잘못된 원본 시각을 임의로 교정하지 않는다. 윤초 표기는 v0.1 지원 범위에 없다.

## 소스별 의미

| 소스 | 결과 판단 | severity 변환 |
|---|---|---|
| Suricata alert | `alert.action=blocked`일 때만 `blocked`; 나머지는 `observed` | 1→80, 2→50, 3→20 |
| ModSecurity transaction | engine `ENABLED`이며 audit message가 `Access denied`로 시작할 때 `blocked` | 차단 transaction=70, 그 외=0 |
| ModSecurity rule message | 해당 message의 차단 여부를 따로 판단; transaction 부모에 연결 | EMERGENCY=100, ALERT=90, CRITICAL=80, ERROR=65, WARNING=50, NOTICE=30, INFO=10, DEBUG=0; 미기재/미인식=0 |
| nftables kernel log | DROP/REJECT→`blocked`, ACCEPT→`allowed` | 차단=50, 허용=0 |

HTTP 403 응답이나 HTML 본문에 등장한 ModSecurity 문자열만으로 WAF 차단을 만들지 않는다. 탐지 전용 모드도 차단으로 기록하지 않는다. Suricata 탐지는 최종 경로 통과를 입증하지 않으므로 `observed`를 사용한다.

ModSecurity는 transaction 1개와 audit message별 자식 이벤트를 만든다. 집계기는 `event.type=transaction`과 `event.type=alert`를 구분해야 요청/탐지 건수를 중복 계산하지 않는다. severity 변환은 v0.1의 명시적인 매핑이며 위험도 평가나 플랫폼 채점이 아니다.

## 데이터 최소화와 검증

본문·URL query·쿠키·Authorization·원본 메시지를 정규화 이벤트에 복사하지 않는다. IP, transaction ID, rule ID, evidence ref 등 남는 메타데이터도 보관 정책 대상이다. `evidence_ref`는 접근 토큰을 담지 않는 참조를 사용한다. 원본 보관, 접근 제어, TTL은 K06/K07 후속 범위다.

중복 JSON 키, NaN/무한대, 잘못된 endpoint, 범위를 벗어난 port, 알 수 없는 출력 필드는 거부한다. 스키마 오류는 입력 값을 포함하지 않는 오류 코드로 반환한다. 스키마는 패키지 안에서 읽으며 외부 참조를 조회하지 않는다.

계약 버전은 `schema_version`으로 구분한다. 필수 필드·식별 알고리즘·의미가 변경되면 버전을 올리고 fixture 및 호환 계획을 함께 변경한다.

## v0.2 추가 필드

`process`(PID·부모 PID·실행 파일·이름·GUID), `user.id`, `host.name`, `file.path`, `http`(method·status_code·bytes), `log`(level·module·AH code), `osquery`(query·row_index·row_count·허용 목록 columns), `sysmon.event_id`, `audit`(serial·record_types·complete·arch·syscall·key)를 선택 필드로 추가했다. 프로세스 명령행·환경·URL query·임의 osquery 컬럼은 정규화 출력에 복사하지 않는다.

이벤트 category에 host/process/file, type에 observation/audit/diagnostic, outcome에 success/failure를 추가했다. syscall 실패나 HTTP 오류는 `failure`이고, 실제 보안 장비 차단 판정인 `blocked`와 구분한다. auditd EOE가 없는 묶음은 idle timeout 후 `audit.complete=false`로 저장한다. XML DTD/외부 엔티티는 거부한다. ENRICHED audit의 ASCII GS는 줄바꿈이 아니다.

이 문서 앞부분의 v0.1 식별·시간·최소화 규칙은 유지되며 새 출력의 schema_version만 v0.2로 대체한다. 원본 전체에는 민감한 내용이 있을 수 있다. 수집 저장소는 0700, DB는 0600이며 관리자만 접근한다. 정규화·원본 보존의 기본 기간은 7일이고, 미분석 outbox는 기간만으로 폐기하지 않는다.

Sysmon의 9자리 소수 초는 원본에 그대로 보관하고 정규화 시 마이크로초 6자리로 절삭한다. Python 3.10과 3.14에서 동일한 결과를 보장한다.

## v0.3 — 에이전트 활동(`xoc-agent`)

생성 주체 `xoc-agent`, category `agent`, 선택 필드 `agent`(role·tool·decision·mode·code·skill·receipt·
arguments_sha256·result_sha256·module)를 추가했다. 기존 생성 주체는 계속 `xoc.event/0.2.0`을 내보내고
`xoc-agent` 이벤트만 `xoc.event/0.3.0`이다. 그래서 v0.2만 아는 소비자는 기존 이벤트를 그대로 읽는다.

- 원천: 증거 조회 권한이 있는 유료 모듈(예: Joint Force 운영자)마다 쓰기 가능한 활동 볼륨
  `activity-<모듈>`이 `/run/xoc-activity`에 붙는다. 모듈은 도구 호출마다 `xoc.agent-activity/0.1.0` JSON 한 줄을
  `activity.jsonl`에 쓴다. 볼륨 소유자는 증거 서비스가 모듈 사용자로 맞춘다(0700).
- 수집: 호스트 수집기가 수집원 `agent-<모듈>`로 읽어 정규화한다. tenant_id/range_id는 수집기의 서버 측
  식별에서만 온다(기록 안의 값은 무시).
- 내용: 정책이 허용한 호출(`outcome: allowed`)과 거부한 호출(`blocked`, severity 30) 모두 남는다. 인자와
  결과는 해시만 남고 내용은 남지 않는다. 식별 discriminator는 `receipt`.
- Wazuh 원본 입력으로 보내지 않는다(디코더 없음). 네트워크 출발지가 없으므로 출발지별 집계에 주소로 나타나지 않는다.
- SIEM UI 인덱스 매핑은 바꾸지 않았다. `agent` 필드는 인덱서 원본(`_source`)에 남지만 검색 필드는 아니다. 매핑을
  바꾸면 설치 시 기존 이벤트 전체를 다시 내보내도록 표시하는데, 큰 저장소와 느린 디스크에서 이 갱신이 서비스 시작
  제한(600초)을 넘었다(2026-11-16 데모 Core). 검색 필드는 배경 재색인을 설계할 때 추가한다.
- Core는 기록만 저장한다. 에이전트 실행·모델 호출은 유료 모듈 쪽에 있다.
