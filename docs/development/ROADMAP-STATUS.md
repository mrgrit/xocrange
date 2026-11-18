# Core 로드맵 실행 상태

정본: [xocrange_plan@f548caa CORE-KICKOFF](https://github.com/mrgrit/xocrange_plan/blob/f548caa/docs/CORE-KICKOFF.md)와 [ROADMAP](https://github.com/mrgrit/xocrange_plan/blob/f548caa/docs/ROADMAP.md). 이 문서는 구현 저장소의 진행 기록이며 정본의 티어·모듈 경계를 바꾸지 않는다.

## 현재 위치

K06의 현재 선택 구성 수집·SIEM 회귀와 K07 공통 보안을 구현했다. K08에서는 기존 콘솔 생성기를 재사용한 운영 화면과 장비 적용 초안을 구축하고 실환경에서 검증했다. [K08 검증과 화면](K08-VALIDATION.md)을 기준으로 사용자가 현재 UI와 커스텀 정책 관리 방식을 수용했다. K09 등록부·운영 개요·NOC 2층·번들 자료실과 [층별 데이터센터](DATACENTER.md)를 구현했으며 [K09 검증](K09-VALIDATION.md)에 실행 증거를 기록한다. Community 전체 출시와 모든 kt66 운영 규칙의 동등성은 별도 완료 조건이다. K10/K11 구현과 실환경 실행은 [운영 검증](K10-K11-VALIDATION.md)에 기록한다. K06/K07의 실행 이력은 [검증 기록](K06-K07-VALIDATION.md)에 유지한다.

| 구간 | 구현 범위 | 남은 작업 |
|---|---|---|
| K01~K04 기반 | 선별 출처, C1 v0.2, 8종 매핑, manifest·의존성·권한·Compose 검사 | 전체 이식 자산·권리 대조 및 Core 배포 라이선스 결정 |
| K05 설치·보안 경로 | Ubuntu 26.04 설치기, fw→IPS→WAF, 검증 타깃, 선택 SIEM, 독립 HTTPS 관리, Juice Shop/DVWA 선택 타깃과 `*.xoc.range` hosts 접속([2026-11-11 실검증](K05-TARGETS-VALIDATION-2026-11-11.md)) | 신규 VM 기본 설치에 타깃 포함 여부, 외부 PC에서의 출처 IP 보존 확인 |
| K06 수집·SIEM | 8종 C1/native 분석·receipt·검색, 재전송, 분석 오류 격리, 에이전트 등록/상태·격리 Linux 통신, 규칙 편집 WAF 회귀, 보존 예산 | 별도 호스트 실통신, 모듈별 미선택 원천/규칙 대조, K11 장기 부하·전체 디스크 복구 |
| K07 공통 보안 | 공통 로그인·3역할·CSRF·세션 폐기·원자적 감사·장비 정책 API, 직접 TCP 우회 차단 | K08 apply에 연결됨; Wazuh SSO는 현재 범위 밖 |
| K08 장비 콘솔 | FORWARD 중심 운영 UI, 객체·NAT·전체 규칙 탭, 3종 규칙 생성기, Unix socket 제어·버전/쓰기 잠금·검증/적용/복원 초안 | 전체 장비 프로파일 범위·장기 동시 변경 검증 |
| K09 화면 | C4 등록·C5 자산 ID, 데이터센터·선택 구성 포털·NOC 2층·번들 4종, 호스트 상태 관측·지연 표시 | 상용 제공자 연계, 장기 운영 검증 |
| K10 모듈 수명주기 | C7 서명·기관·티어·버전·구매 범위, 외부 모듈 추가/제거/재설치, 만료 차단, 실패 시 복원 | 상용 제공자의 실제 콘텐츠·시나리오 실행 연계 |
| K11 운영 | portable 백업·업데이트·자동 복구, 빈 VM 설치+복원, 로그 회전, 버전/이미지/패키지 목록, 최소 구성 자원 검증 | 장기 운영·다중 사용자 부하와 RC 권리 확정 |
| K12 RC | 단계별 실행 증거와 미완료 범위 관리, [G1 체크리스트](K12-RC-CHECKLIST.md) | G1 전체 통합·배포 검증. 체크리스트의 "RC를 막는 항목" |

2026-11-13 밤 K12 진행([검증](RETENTION-ADDRESS-PLAN-2026-11-13.md)): 모듈 트랜잭션이 SIEM 수용에서 롤백된 원인(재시작 직후 보존 정리가 캐시가 빈 상태에서 3분 넘게 수집을 막음)을 루프당 3초 분할 정리로 수정했다. `xoc update`가 정책이 바뀐 릴리스를 설치된 planner로 미리 계획해 거부하던 결함을 고쳤다. 실습망을 kt66 주소 체계(ext 10.20.30, pipe 10.20.31, dmz 10.20.32, int 10.20.40)로 바꿔 배포했다. 그 위에서 `console-fw`·`console-waf` 개별 제외·재추가(메뉴·API 제외 확인), 장비 broker·Core HTTPS 수준 동시 apply(신규 `concurrent_core.py`), 로그인이 필요한 통합 시험(`device_console` 51, `workspaces` 78/85, `console_restart` 16, `academy_acceptance` 33)을 실행해 통과했다.

2026-11-14 소유자 결정과 후속([기록](RC-FRESH-VM-2026-11-13.md#6-auditd-기록-중단의-표시와-자동-재개)): Core 라이선스를 PolyForm Noncommercial 1.0.0(`LICENSE`)과 교육용 추가 허락(`LICENSE-EDUCATION.md`)으로 정하고 kt66 자산·로고 배포 허락을 NOTICE에 기록했다. RC 범위는 설치기 기본 구성(ssh-lab·bootstrap 단독은 이후). 수업 전 초기화 `xoc siem clear`를 추가해 새 VM에서 검증했다. 디스크 고갈 뒤 auditd가 기록을 중단한 채 남고 SIEM은 `ready`로 표시하던 결함을 찾아, 중단 표시와 자동 재개로 고쳤다. 실제 외부 PC의 출처 IP 보존도 확인했다.

2026-11-13 새 VM RC 검증([기록](RC-FRESH-VM-2026-11-13.md)): Docker도 없는 Ubuntu 26.04.1 VM에서 `sudo bash install.sh` 한 번으로 기본 전체 구성 설치(7분 30초, 수용 검사 15·6·8·52), 재부팅 17/17, 설치본 경계 160파일·통합 시험 8종 통과, 디스크 고갈(예약 미만·완전 소진) 중 서비스 유지와 해제 후 회복을 확인했다. 로그인 제한(실패만 계산)도 설치본에서 확인했다.

2026-11-13 로그인 제한 정책 결정([공통 보안](COMMON-SECURITY.md)): 계정별 15분 10회·전체 100회 한도가 성공한 로그인도 세던 것을 실패한 로그인만 세도록 바꿨다(소유자 결정). 동시 추측이 한도를 넘지 않도록 시도를 먼저 세고 성공 시 되돌린다. 설치본 배포는 24시간 장기 운영 측정 이후.

2026-11-13 운영 결함 수정([검증](OBSERVATION-VOLUME-VALIDATION-2026-11-13.md)): Sysmon 기록 대부분이 xoc 자신의 주기 작업(Manager 상태 확인, 배치마다 새로 띄우던 Wazuh 전송, 볼륨 조회)에서 나와 SIEM DB가 하루 12.9 GB로 늘던 문제를 발생원에서 줄였다. 같은 작업 중 드러난 IPS 시작 시 fail-open 구간(테이블 로드 전 전달), 설치 중 자동 업그레이드의 systemd 재실행으로 인한 설치 실패, 복원 직후 `lab verify` 경쟁도 고쳤다.

## K06 상세 범위

- Wazuh Manager/API·Indexer·전용 Dashboard는 모두 4.14.10이다. Wazuh를 일반 OpenSearch 검색기로 대체한 구성이 아니다.
- nftables·Suricata·ModSecurity·osquery·Sysmon Linux·auditd·Apache access/error의 원본을 보존한다. C1과 native를 독립 처리하며 정상/level 0 기록도 Manager archive receipt로 확인한다.
- 재전송 중복 방지, 날짜별 회전 archive·gzip 읽기, 미확인 입력 보존, 잘못된 분석 레코드 격리, source별 전송 공정성, UTF-8 원본 경보 전송을 구현했다.
- kt66 규칙은 [이식 범위표](KT66-RULE-DISPOSITION.md)에서 선택 구성·후속 모듈·제외 기능으로 각각 배정한다. 모듈 없이 규칙 파일만 가져와 전체 동등성을 주장하지 않는다.
- 에이전트와 Windows 실행 구조는 [상세 문서](AGENTS-AND-WINDOWS.md)를 따른다. kt66 Windows는 컨테이너 안의 KVM/QEMU 방식이며, 정본 M6 경계를 유지한다.
- 규칙 편집 WAF 예외는 요청 경로·메서드·XML 파일·필드·관측 CRS ID로 제한한다. 잘못된 XML은 Manager가 거부하고 기존 파일을 보존한다.

## K07 상세 범위

[공통 보안](COMMON-SECURITY.md)은 SIEM과 독립된 `management` 구성요소다. SIEM 선택 해제 후에도 `/core/` 계정·역할·감사·장비 정책을 유지한다. 관리자·운영자·조회자, 최초 비밀번호 변경, 15분 비활성/8시간 절대 만료, 비밀번호·역할·활성 상태 변경 시 세션 폐기, CSRF·Origin 검사, 감사 실패 시 변경 취소를 제공한다. K08 장비 콘솔도 이 경계에 연결한다.

## 기존 검증 이력

이전 소스 `9ee0b08d…`의 240개 단위·50개 엔진·15개 경로·8종 C1/native·52개 HTTPS·15개 브라우저, SIEM 전체 선택 변경·재부팅·Indexer 장애 기록은 [원본 분석 검증](WAZUH-RAW-VALIDATION-2026-11-07.md)에 유지한다. 이전 수치를 최신 변경의 검증 수치로 재사용하지 않는다.

K08의 [콘솔](DEVICE-CONSOLES.md)은 현재 UI와 커스텀 관리 방식을 유지한다. K09의 [운영 화면](WORKSPACES.md)을 이어 구성했으며 K10/K11 구현을 연결했으며 다음 출시 단계는 K12 RC 통합 검증이다. K05의 실제 타깃과 K11의 운영 잔여 항목을 출시 게이트에서 제외하지 않는다.

2026-11-08 공간 확장: 6F 아카데미(기관 구매 콘텐츠), 7F Live Fire(기관 구매 공방전), 8F 가상회사(Joint Force 학생 회사·에이전트). Core에서는 공간 배치와 서버 차단까지 구현하며, 실제 실행은 C7 및 M7/M14/M15 후속 작업이다.

2026-11-08 Core 아카데미: 공개 승인된 1–339쪽을 `contents/academy/` 아래 36개 차시·96개 미션으로 구성했다. 설명/실습 화면, 본인 입력·결과·해석과 캡처의 DB 저장, 수정 이력·내보내기를 제공한다. [구현과 검증](ACADEMY.md)에 기록하며, 교재와 실제 타깃 환경의 정합성 검토 및 Live Fire AI 채점·분석·피드백은 후속 범위다.

아카데미 v0.2: 6층 무료 카탈로그 연결, 교재·실습 통합 화면, 미션당 단일 입력. 36차시를 2과목·15개 Live Fire 시나리오/105미션에 연결했다. tw2 순수 로더·컴파일러·채점 입력 계약을 확인했으며 실제 공방전 실행·AI 모델 채점 검증은 상용 엔진 통합 범위다.

아카데미 v0.3: 차시별 블로그형 실습 노트, 다중 캡처·중간/자동 저장·이어쓰기, 큰 글씨와 적정 그림 크기, 접는 목차를 구현했다. 6·7층 공간 안의 큰 디스플레이에 실제 콘텐츠와 개인 학습 현황을 연결하고 콘텐츠 선택을 제공한다. [개인 훈련·교수자 리그](LIVE-FIRE-LEAGUES.md)는 설계만 추가하며, 공방전의 미션별 등록·채점과 개인/리그 실행은 후속 상용 구현이다.

2026-11-15 콘텐츠 위치 변경([ADR 0009](../adr/0009-community-content-in-core.md)): Community 번들(36차시·96미션, 15개 시나리오·105미션)을 비공개 콘텐츠 저장소 다운로드 대신 Core `contents/`에 포함했다. 설치·계획은 `module.json` 파일별 해시와 정확히 일치할 때만 진행하며(`scripts/verify-contents.py`), 유료 콘텐츠 팩은 `xocrange_contents`(비공개)에 둔다. 단위 시험 실행 검증, 새 VM 설치 검증은 RC 재실행에서 한다.

2026-11-15 실습 웹 요청의 Apache 접근 로그에 User-Agent 추가(소유자 결정): 관리 화면 형식은 그대로(질의·헤더 없음), ModSecurity 헤더 기록(B)은 Cookie·Authorization 때문에 켜지 않음. 스캐너 User-Agent 규칙 `111303`. Core Wazuh 이미지로 원천 규칙 33개 사례 실행 검증, 설치본 반영·실제 요청 검증: [WAZUH-RAW-SOURCES](WAZUH-RAW-SOURCES.md) 마지막 절.

2026-11-15 최종 RC 재실행([기록](RC-FINAL-2026-11-15.md)): main `b519677`로 Docker도 없는 새 VM(8 vCPU·15 GiB·100 GB)에 한 번 설치(8분 30초, 수용 검사 11·15·6·8·52), 재부팅 17/17, 설치본 경계 162파일 위반 0, 통합 시험 8종(31·51·16·78·33·12·13·7), `siem clear` 12/12 후 SIEM UI 52/52, User-Agent 기록·111303 경보, 같은 VM 재설치(계정·학습 기록 보존) 통과. 남은 일은 저장소 공개·버전 태그와 공개 저장소에서의 설치 확인.

2026-11-15 **Community 0.1.0 출시**: 소유자가 저장소를 공개하고 버전 `0.1.0`을 확정했다. 태그 `v0.1.0`. 공개 저장소의 비인증 `git clone`과 콘텐츠 검증 확인.

2026-11-15 0.1.0 이후 main: Live Fire 증거 표면(ADR 0008, 브랜치 `livefire-integration`)을 병합했다. 상용 승인이 없는 Community 설치본은 병합된 main으로 업데이트해도 증거 서비스가 꺼진 채 0.1.0과 같이 동작함을 RC VM에서 확인했다. 단독 설치의 다운로드 폴더 잔존, 업데이트 중 로그 정리 unit 실패 표시를 고쳤다([기록](RC-FINAL-2026-11-15.md#7-공개-후-확인-태그-v010--af8b514)).

2026-11-16 모듈 갱신 경로 `xoc module upgrade --package <dir>`(d18d0d5): 레지스트리 모듈의 새 패키지(새 이미지 digest)를 설치된 같은 모듈 자리에 넣고 설치 트랜잭션을 한 번만 돈다. 추가와 같은 검사(선언 파일·digest 고정 이미지·크기)를 하고, 선택된 모듈이면서 패키지로 설치된 것만 바꾼다(Core 구성 요소는 불가). 설정·자격 증명 볼륨이 유지된다. **실행 검증**: Joint Force 데모 Core(192.168.16.52)에서 `xoc update`(554초) 뒤 m7-operator 업그레이드 565초, 자격 증명 재설치 없이 새 이미지로 운영자 주기 정상. 이전 방식(제거→추가)은 트랜잭션 두 번과 자격 증명 재설치가 필요했다.

2026-11-16 C1 v0.3 에이전트 활동(202204e~f8748c7): 자격 있는 에이전트 모듈의 도구 영수증을 SIEM에 저장한다(생성 주체 `xoc-agent`, 범주 `agent`, `agent` 객체는 해시만). 모듈별 활동 볼륨 `/run/xoc-activity`, 수집원 `agent-<모듈>`, Wazuh 원본 입력 아님. 데모 Core(.52) 배포에서 찾아 고친 것:
- 증거 서비스가 정지·백업·복원·재개 대상에서 빠져 복원 뒤 옛 계획으로 재시작을 반복(74449f9).
- 인덱스 매핑 변경이 저장소 전체 재내보내기를 표시해 서비스 시작 제한 초과 → 범위 한정 재내보내기: 저장된 digest가 "새 매핑에서 `agent`만 뺀 것"이면 `xoc-agent` 이벤트만 다시 내보냄(b4fabff).
- Wazuh 전달 큐와 규칙이 v0.2만 받아 에이전트 이벤트가 미확인으로 쌓임 → 큐 v0.3 허용, 규칙 110009. Wazuh 정규식은 문자 묶음(`[23]`)을 지원하지 않아 `|`로 씀. **실행 검증**: Wazuh 4.14.10 일회용 컨테이너에서 에이전트 허용·거부 → 110009, v0.2 suricata → 110020, 미지 버전 거부(543e6a0). 데모 Core에서 `xoc-agent` 14건 저장·Wazuh 확인(110009)·인덱서 전송 14/14.
- 설치 직후 재시작 몰림(대기 2,600건)으로 SIEM 수용 검사의 Sysmon 시험이 180초를 넘김 → 밀린 입력을 처리하는 동안 최대 600초, 해소 후 60초 대기(f8748c7).
- `xoc module upgrade --package P --source S`: Core 소스 갱신과 모듈 교체를 트랜잭션 한 번에(f8748c7). **실행 검증**: 데모 Core에서 f8748c7 소스 + m7 새 패키지 1,080초, 수용 검사 통과, 증거 서비스가 새 릴리스를 가리킴, 운영자 주기 정상·스킬 재채택 후 `adopted`.
- 복원 뒤 SIEM `degraded`: 원인은 경보가 아니라 수집기였다. 복원으로 Manager 보관 파일이 짧아지면 읽다 만 줄 조각(713바이트)을 일반 증거 기록으로 넣었고, 해석기가 없어 `unknown_source`로 격리됐다. Manager 출력은 수신 기록이므로 잘린 조각은 증거로 넣지 않고 `analysis_fragments_dropped`로 센다(확인할 이벤트는 미확인으로 남아 재전송). 1 MiB 초과 줄은 분석 오류 `analysis_oversize`. 기존 격리 조각은 저장소를 열 때 지운다.
- SIEM UI `agent.*`: 데모 Core 인덱서에서 관리자 계정으로 `xoc-agent` 154건, `agent.*` 10개 필드 매핑, term·집계·query_string 검색 성공(**실행 검증**). 단 대시보드에 저장된 `xoc-events` 인덱스 패턴은 처음 만들 때(`overwrite=false`)의 65개 필드 그대로라 Discover 필드 목록에 `agent.*`가 없었다 → 설정 때 템플릿에 새로 생긴 필드만 저장된 패턴에 덧붙인다(사용자 편집 유지). SIEM UI 수용 검사에 `core_pattern_lists_template_fields` 추가.
- 데모 Core 갱신(ea1a0a8) 실패 → 자동 복원: SIEM UI 수용 검사가 출발지 집계를 상위 8개 버킷(`terms size 8`)으로 받았다. C1 v0.3의 `xoc-agent`가 아홉 번째 생성 주체라, 확인 창에서 에이전트 기록(10분에 약 10건)이 Suricata(2건)보다 많으면 Suricata가 빠져 `all_eight_fresh_sources_indexed`·`native_alerts_contain_all_eight_c1_links`가 거짓이 됐다(이전 성공 때는 운영자가 아직 기록을 내기 전). 여덟 소스로 거른 뒤 집계하고, 빠진 소스를 진단에 남긴다. 새 검사 `core_pattern_lists_template_fields`는 이 실행에서 통과.
- 복원 뒤 Sysmon 지연이 30분까지 쌓였다. Sysmon 데몬은 실시간이었고 수집기가 밀린 것. 수집 속도(분당 1,700~2,400건)는 유입(분당 560건)보다 빨라 해소되지만, 유입의 약 40%가 15초마다 도는 호스트 관측기의 `ip`·`nsenter` 프로세스였다 → 실습망 관측을 60초 주기로(화면 신선도 45→150초, 서비스 상태는 15초 그대로).
- **실행 검증(2026-11-16 23:3x, 데모 Core, a15eb50, 릴리스 60f05947):** 갱신 성공, 수용 검사 4종 통과(`core_pattern_lists_template_fields`·`all_eight_fresh_sources_indexed`·`native_alerts_contain_all_eight_c1_links` 포함). SIEM 상태 `ready`, 격리 0(이전 격리 조각은 `analysis_fragments_dropped.wazuh-archive=1`로 옮겨짐). 저장된 `xoc-events` 패턴 65→75개 필드(`agent.*` 10개), Discover 필드 목록에 나타남. 인덱서 `xoc-agent` 354건 term·집계·query_string 검색. 운영자 주기 2분마다 계속, 채택된 스킬로 기록·확인·색인. 관측기 주기 변경(a0f0f4c)은 다음 갱신에 반영.
- **실행 검증(2026-11-17 13:19~13:35, 데모 Core, a5855ae + m7 새 패키지, 릴리스 ed1f21ea):** `module upgrade --package --source` 968초, 수용 검사 4종 통과, 관측기 60초 주기(a0f0f4c) 반영. 운영자 이미지에 스킬 2개(채택된 것 + 그림자 운영 스킬). 이어 m7만 다시 교체(811초, 릴리스 82682167).
- 갱신 뒤 SIEM이 약 70분 `degraded`: 보존 정리 상태가 정리 한 바퀴가 **끝날 때만** 갱신되는데, 어제 바쁜 하루치(Sysmon 약 41만 건)가 만료되는 동안 한 바퀴가 73분 걸려 상태 기록이 600초 기준을 넘겼다(삭제는 계속 진행, 14:26 스스로 `ready`). 행을 지운 조각도 보존 상태를 갱신한다. 아무것도 지우지 못한 조각은 갱신하지 않아 멈춘 정리는 여전히 드러나고, 디스크는 저장 한도 검사가 따로 본다.
- **실행 검증(2026-11-18, 데모 Core, fc2881b, 릴리스 9e4f9a25):** 갱신 652초, 직후 SIEM `ready`, 보존 상태가 갱신 직후 값. 70분 `degraded`는 재현되지 않았다.
- 업무망과 업무용 PC([ADR 0012](../adr/0012-office-network-and-linux-host.md)): 번들 교재가 전제하는 SSH 리눅스 호스트가 현재 실습망에 없어, 이전 인프라의 근무자 PC 망(10.20.70.0/24, IPS 아래)과 리눅스 PC `office-pc01`을 Core에 추가했다. **실행 검증(2026-11-18, 두 번째 Core 192.168.16.51, 릴리스 437ef36a):** 외부 공격자 VM의 `ssh -p 2222` 시도가 방화벽 기록·`auth.log`·경보(5710, 5760, 5715, 5402, `agent.name: office-pc01`)로 남고, PC에서 내부망과 Manager API로는 나가지 못한다. 2F에 스위치 5대.
- 같은 날 찾은 것: (1) 설치 직후 바로 이어 한 두 번째 설치가 SIEM UI 수용 검사 `forwarded_client_header_cannot_be_spoofed`에서 실패하고 자동 복원됐다. 수집기가 앞 설치 뒤 40분 밀려 있어 검사 요청의 기록이 30초 안에 오지 않았다. 수집이 따라잡은 뒤 다시 하면 통과한다. 검사가 수집 지연을 기다리지 않는 점은 남은 문제다. (2) 그 복원이 남긴 옛 에이전트 키로 PC가 Manager에 붙지 못했다 → PC가 키 변경을 따라간다.
- 공격 실습 단말([ADR 0013](../adr/0013-practice-attack-terminal.md)): 코드와 단위 시험, 이미지 빌드까지(도구 8종 확인). 설치본 실행 검증은 진행 중.
- 번들 콘텐츠 전환: 36차시의 환경 전제를 뽑아 현재 Core와 대조했다([계획](CONTENT-PORTING-PLAN.md)). 콘텐츠는 아직 고치지 않았다.
