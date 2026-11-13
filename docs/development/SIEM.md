# Core SIEM 수집·디코딩 백엔드

원본을 보관한 뒤 `C1 정규화 → Wazuh C1 규칙`과 `원본 형식 변환 → Wazuh native 규칙` 두 경로를 독립적으로 실행한다. Wazuh Manager/API 4.14.10의 기본 규칙과 C1 규칙을 함께 사용한다. 선택형 `siem-ui`가 같은 버전의 Wazuh Indexer와 전용 Dashboard를 연결하며 원본 경보도 별도로 보존·색인한다. [웹 관제·WAF 예외](SIEM-WEB.md)와 [정식 연동 범위](WAZUH-NATIVE.md)를 함께 참고한다. [에이전트 등록·Windows 범위](AGENTS-AND-WINDOWS.md), [공통 보안](COMMON-SECURITY.md)을 별도로 정의한다. Community 전체 출시 완료를 뜻하지 않는다.

## 소스와 매핑

| 소스 | 실제 수집 위치 | 주요 디코딩 필드 / 의미 |
|---|---|---|
| nftables | fw NFLOG group 10 → `/var/log/nftables/events.log` | IP·port·protocol·ACCEPT/DROP; 실제 로그 판정, payload 미보관 |
| Suricata | ips `/var/log/suricata/eve.json` | alert SID·severity·IP/port·action; `blocked`만 차단 |
| ModSecurity | web `/var/log/apache2/modsec_audit.json` | 2.x multiline JSON, transaction과 message별 이벤트·부모 연결·rule ID |
| osquery | host `/var/log/xocrange/osquery/osqueryd.{results,snapshots}.log` | event/batch differential·snapshot, query·row 순서·PID/UID·허용된 columns |
| Sysmon | host `journalctl -t sysmon` | XML EventID·PID/PPID·Image·GUID·IP/port·file; 시작 배너는 diagnostic |
| auditd | host `/var/log/audit/audit.log` | node+발생시각+serial로 여러 record를 결합; SYSCALL·프로세스·UID·key·완결 여부 |
| Apache access | web `/var/log/apache2/access.log` | 시각·client IP·HTTP method/status/bytes·ModSecurity와 동일 request ID |
| Apache error | web `/var/log/apache2/error.log` | module·level·PID·client·AH code; 시간대 없는 기본 형식은 관측 시각 사용 |

Apache combined access와 Windows Sysmon의 내보낸 XML의 오프라인 C1 정규화도 지원한다. Windows VM/에이전트 실통신, EVTX 바이너리, Wazuh Windows JSON envelope는 이번 검증에 포함하지 않는다. EVE stats 등 다른 event_type과 ModSecurity native/v3 형식은 현재 지원하지 않으며 파싱 실패를 정상 탐지로 바꾸지 않는다.

osquery는 processes 메타데이터를 60초, 센서 상태 snapshot을 30초마다 조회한다. audit subsystem은 auditd가 담당하며 osquery audit/event subscriber는 비활성화한다. auditd 기본 규칙은 `/etc/xocrange` 변경, sudo 실행, 수용 검사 `/usr/bin/true` 실행이다. Sysmon은 프로세스 생성·네트워크 연결을 관측한다. 전체 프로덕션 탐지 규칙이나 모든 행위 감사가 완성된 상태는 아니다.

`observation`은 Sysmon·osquery의 일반 행위 관측 분류다. 해당 기록은 공격 여부를 분석하는 재료이며, 분류만으로 공격이 탐지됐다는 의미는 아니다. Core의 Sysmon 기본 정책은 ProcessCreate(EventID 1)와 NetworkConnect(EventID 3)를 수집한다. ProcessTerminate(EventID 5)는 빈 `include` 필터로 명시적으로 끈다. 필터를 생략하면 프로세스 종료 기록도 발생하여 Docker·수집기 등의 반복 실행이 대량의 관측 기록을 만든다. [Microsoft의 설정 예제](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#configuration-files)와 동일한 필터 방식이며, Linux VM에서도 실제 적용·수집을 검증한다. 실행·연결 필터에는 Docker 등 관리 프로그램 전체를 제외하는 예외를 두지 않는다.

프로세스 종료 시점·수명 추적이 필요한 별도 센서 정책은 EventID 5를 활성화할 수 있으며 C1 디코더의 `process/stop` 지원은 유지한다. 설치기는 `components/siem/sysmon.xml`을 `/etc/xocrange/sysmon.xml`에 설치하고 `sysmon -c`로 적용한다. 기존 호스트에는 정책 파일을 백업한 뒤 같은 설정을 적용할 수 있다.

xoc 자신의 주기 작업도 Sysmon 관측 대상이므로, 주기마다 프로세스를 많이 띄우지 않도록 구현한다. Manager 컨테이너의 필수 daemon 확인은 셸 내장 명령만 쓰고, 수집기는 Wazuh queue마다 상시 전송 프로세스 1개를 유지한다. 배치마다 `docker compose exec`를 새로 띄우면 그 실행 기록을 다음 배치가 다시 전송하는 자기 증식 루프가 생긴다. 근거와 측정은 [2026-11-13 검증](OBSERVATION-VOLUME-VALIDATION-2026-11-13.md)에 있다.

## 설치와 선택

```bash
sudo bash install.sh                 # 기본 보안 경로 + SIEM + 호스트 관측
sudo bash install.sh --without siem-ui # 로컬 수집·분석만 유지
sudo bash install.sh --without siem  # 보안 경로만 선택
sudo xoc siem status
sudo xoc siem credentials             # 웹 주소와 관리자 자격 증명
sudo xoc siem query --source auditd --confirmed --limit 20
sudo xoc siem evidence --ref xoc-evidence:실제_참조값
sudo xoc siem retry --source auditd
```

Docker·Python·Microsoft Ubuntu 26.04 저장소·osquery 저장소·auditd를 설치기가 준비한다. 이미 있는 다른 Docker를 제거하거나 kt66 호스트를 변경하지 않는다. SIEM 제외 시 xOC collector/osquery/Sysmon 실행과 xOC audit 규칙을 해제하고 기존 수집 데이터는 보존한다. 일반 OS auditd 및 다른 감사 규칙은 유지한다.

서비스는 `xocrange-core`, `xocrange-collector`, `xocrange-osquery`, `sysmon`, `auditd`다. 설치 결과는 `/var/lib/xocrange/{last-install,siem-acceptance}.json`, 상세 설치 로그는 `/var/log/xocrange`에 있다. source/module 상태를 확인하려면 `sudo xoc catalog`를 사용한다.

## 보관·재시도·접근

`/var/lib/xocrange/siem/events.sqlite3`는 로컬 관리자 전용이다. 원본 byte와 SHA-256, opaque evidence ref, C1 이벤트, 수집 위치, 분석 대기/확인을 트랜잭션으로 기록한다. 로그의 tenant/range/source 주장 대신 설치기의 고정 등록부에서 `community/local` 범위를 부여한다. 네트워크 수집 API나 다중 사용자 접근 제어는 아직 없다.

파일은 활성본과 `.1/.2` 회전본을 inode로 추적한다. 부분 JSON/줄은 다음 읽기까지 보류하고, audit 이벤트는 EOE 또는 2초 idle 경계까지 모은다. EOE 없는 경우 `audit.complete=false`다. copy-truncate는 파일 크기/anchor 변화로 새 세대를 부여한다. 파일 교체·정지·대량 회전 중 읽기 전에 소스에서 사라진 데이터까지 복구한다고 보장하지 않는다. rename 회전을 권장한다.

오류 레코드는 원본을 남기고 격리한다. 디코더를 수정한 뒤 `siem retry`로 같은 증거·최초 관측 시각을 유지하며 재처리한다. 원본에 명령행·사용자 입력 등 민감한 값이 있을 수 있다. 정규화 출력에는 본문·인증 헤더·URL query·명령행·임의 osquery 컬럼을 복사하지 않는다. Native 경보에는 분석에 사용한 원본 필드와 `full_log`가 포함될 수 있으므로 관리자용 검색 데이터로 다룬다. Apache common access의 요청 URI는 원본/native 분석에 남고 C1에서는 제거한다. ModSecurity는 AHZ 부분만 기록하여 요청/응답 헤더와 본문을 새로 수집하지 않는다.

원본과 정규화의 기본 로컬 보존 기간은 1일이다. 미분석 outbox는 기간만으로 삭제하지 않는다. 신규 수집 예산은 24 GiB, SQLite 한도는 32 GiB이며 파일시스템 여유 2 GiB를 확보하지 못하면 쓰기를 중지한다. 분석 확인·재전송에 여유 공간을 남기고 오류 상태를 표시한다. 이 값은 신규 수집 중단 기준이며 이미 진행 중인 분석/경보 쓰기와 다른 볼륨을 포함한 전체 디스크 상한은 아니다. Wazuh alerts/archives 로그는 1시간/10 MiB 기준으로 회전한다. 원천 볼륨과 OS journal의 전체 수명주기·보존 용량 자동 관리, 장기 부하 및 디스크 고갈 복구는 RC 전 후속 검증 항목이다. 입력·처리량이 작은 전용 개발 VM을 대상으로 검증한다.

Wazuh queue에 넣었다고 바로 성공 처리하지 않는다. 실제 `alerts.json`에 같은 event ID·producer·원본 hash가 나타나야 `--confirmed` 조회 대상이 된다. 전송 중 재시작 시 재전송할 수 있지만 검색 저장소는 event ID로 중복 제거한다. `status`는 파싱 격리 건수, 소스 상태, 미분석 건수와 가장 오래 대기한 시간, Sysmon journal의 실제 발생 시각 대비 지연을 표시한다. 누적 journal은 한 회차 최대 5초/4096건씩 처리하며 120초 이상 뒤처지면 `lagging`으로 표시한다.

Native 입력은 별도 ID·frame hash·전송/처리 상태를 갖는다. `archives.json`에서 같은 입력 ID·source·frame hash와 해당 소스의 decoder를 확인해야 분석 완료로 처리한다. 경보가 없는 정상/level 0/no_log 결과도 이 경로로 확인한다. Native 경보는 `xoc.input_id`·`xoc.event_id`·`xoc.evidence_ref`로 연결한다. 재전송으로 새 Wazuh ID가 생겨도 같은 입력의 동일 분석 결과는 첫 원본 한 건을 유지한다. 규칙·분석 결과가 달라진 경우는 별도 경보로 보관한다. [형식·검증 범위](WAZUH-RAW-SOURCES.md)

## 검증

최종 설치본의 재부팅·실수집 결과는 [2026-11-07 SIEM 실환경 검증](SIEM-VALIDATION-2026-11-07.md)과 [검증 JSON](../provenance/siem-acceptance-2026-11-07.json)에 기록했다.

단위 검증은 8종 fixture, 신뢰 컨텍스트·민감 필드 제외, audit ENRICHED 구분 문자·다중 record·중간 종료, XML 외부 엔티티 거부, 부분 로그·회전·재시작·원본 충돌·오류 재처리·Wazuh 분석 확인을 다룬다. VM 수용 검사는 실제 fw·IPS·WAF 표식 트래픽과 host telemetry를 생성하고 **검사 시작 이후 발생하고 관측된 8종 이벤트**가 Wazuh에서 디코딩될 때 통과한다. Sysmon 시작 배너만으로 통과하지 않는다.

소프트웨어 기준은 Ubuntu 26.04.1/kernel 7.0, Wazuh 4.14.10, osquery 5.24.1, Sysmon for Linux 1.6.0, auditd 4.1.2다. 이미지 digest와 모든 패키지 버전이 고정된 재현 배포본은 아직 아니다.

웹 관제를 선택하면 Wazuh가 확인한 C1만 `xoc-events-*` 색인으로 전송한다. 각 문서의 `_id`는 원래 event ID이며 원본 로그 본문은 전송하지 않는다. 개별 bulk 응답이 성공해야 SQLite에 색인 완료를 기록한다. 최근 이벤트를 우선 보내면서 과거 데이터를 채우고, Indexer 중단·429 응답은 다음 회차에 재시도한다. 매핑 또는 Indexer cluster UUID 변경을 감지하면 보존 중인 확인 이벤트를 재전송한다. 아직 색인되지 않은 증거는 기본 보존 기간만으로 지우지 않는다. 호스트 collector가 미전송 상태를 확인한 뒤 7일보다 오래된 일별 색인을 정리한다. 나이만 보고 삭제하던 이전 ISM 정책은 제거한다. collector 중지 중에는 이 정리도 실행되지 않는다.

공식 형식·설치 근거: [Wazuh JSON decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html), [Wazuh 규칙 검증](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html), [Wazuh 로그 회전](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/global.html), [osquery 로그](https://osquery.readthedocs.io/en/stable/deployment/logging/), [Sysmon Linux 설치](https://github.com/microsoft/Sysmon-Linux/blob/main/INSTALL.md), [NFLOG/ulogd](https://www.netfilter.org/projects/ulogd/).

## 보존과 복구 설정

root 전용 `/var/lib/xocrange/siem/retention.json`에서 `days`, `ingest_bytes`, `database_bytes`, `reserve_bytes`, `index_days`, `archive_days`를 조정할 수 있다. 기본값은 각각 1일·24 GiB·32 GiB·2 GiB·7일·2일이다. collector 재시작 때 설정을 검증한다. 미확인 입력·미색인 증거는 나이만으로 제거하지 않으며, 여유가 부족하면 cursor를 보존하고 수집을 중지한다. 여유 확보 후 다시 수집한다.

Wazuh의 날짜별 hardlink 회전을 인식하고, 압축된 파일도 이전 논리 offset부터 이어 읽는다. archive 정리는 읽기가 끝났고 활성 hardlink가 아닌 닫힌 파일에만 적용한다. 새 SQLite 저장소는 `auto_vacuum=INCREMENTAL`로 만들고, 정리 때마다 빈 페이지를 최대 256 MiB씩 파일시스템에 돌려준다. 이전 버전에서 만든 저장소(`auto_vacuum=0`)는 수집기를 멈춘 상태에서 `PRAGMA auto_vacuum=INCREMENTAL; VACUUM;`을 한 번 실행해야 전환된다(2026-11-11 개발 VM: 38 GB → 6.1 GB, 약 5분). `status.storage`로 할당량·사용량·파일시스템 여유를 구분한다.

Wazuh 원본 경보(`wazuh_alerts`)는 원본 바이트와 작은 `xoc` 연결 정보(`annotation`)만 저장하고, Indexer로 보낼 검색 문서는 내보낼 때 다시 만든다. 만들어지는 문서는 이전 릴리스가 저장하던 문서와 바이트까지 같다. 이전 릴리스가 저장한 행은 저장된 문서를 그대로 쓴다. 전체 사본을 저장하던 때는 문서가 경보 행의 절반 이상, DB의 약 1/3이었다.

보관 작업은 5분 주기로 실행된다. 로컬 DB의 `days`, Manager 회전 로그의 `archive_days`, 검색 인덱스의 `index_days`는 서로 다른 보관 계층에 적용된다. 수집량을 줄여도 이미 저장된 기록은 각 보관 기한까지 남는다. 설치 전 백업은 SQLite 파일 전체를 복사하므로, 전환하지 않은 저장소는 실제 사용량보다 훨씬 큰 백업과 여유 공간을 요구한다. 디스크를 점검할 때는 DB 외에 Docker의 SIEM 로그·Indexer 볼륨, `/var/lib/xocrange/backups`의 설치 전 복구 지점도 함께 확인한다. 백업은 SIEM 보관 기한으로 삭제되지 않는다.

이 정책은 모든 로그 볼륨과 호스트 디스크의 상한을 보장하지 않는다. 원천 로그가 읽히기 전에 외부 회전으로 제거되는 경우와 장기 장애·전체 디스크 고갈 복구는 K11의 필수 검증이다. 운영 사양을 단기 테스트 결과만으로 확정하지 않는다.
