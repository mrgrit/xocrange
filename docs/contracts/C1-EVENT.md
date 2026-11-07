# C1 이벤트 계약 v0.1.0

상태: K03의 첫 실행 가능한 계약. [정식 스키마](../../src/xocrange/contracts/c1-event.json), [정규화기](../../src/xocrange/events.py), [합성 fixture](../../tests/fixtures/events/).

## 범위와 신뢰 경계

한 번에 최대 1 MiB의 소스 레코드 하나를 입력받아 C1 이벤트 배열을 반환한다. Suricata EVE alert, ModSecurity **2.x JSON audit**, kt66/xoc 접두사의 nftables 커널 로그를 지원한다. EVE의 다른 유형, ModSecurity 3.x/native audit, 파일 tail·회전·재시도·저장은 아직 구현하지 않았다. fixture는 예약된 문서용 IP를 사용한 합성 자료이며 실제 고객 트래픽을 포함하지 않는다.

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
