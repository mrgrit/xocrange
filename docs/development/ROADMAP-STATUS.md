# Core 로드맵 실행 상태

정본: [xocrange_plan@f548caa CORE-KICKOFF](https://github.com/mrgrit/xocrange_plan/blob/f548caa/docs/CORE-KICKOFF.md)와 [ROADMAP](https://github.com/mrgrit/xocrange_plan/blob/f548caa/docs/ROADMAP.md). 이 문서는 구현 저장소의 진행 기록이며 정본의 티어·모듈 경계를 바꾸지 않는다.

## 현재 위치

K06의 현재 선택 구성 수집·SIEM 회귀와 K07 공통 보안을 구현했다. K08에서는 기존 콘솔 생성기를 재사용한 운영 화면과 장비 적용 초안을 구축하고 실환경에서 검증했다. [K08 검증과 화면](K08-VALIDATION.md)을 기준으로 사용자 피드백을 받는다. Community 전체 출시와 모든 kt66 운영 규칙의 동등성은 별도 완료 조건이다. K06/K07의 실행 이력은 [검증 기록](K06-K07-VALIDATION.md)에 유지한다.

| 구간 | 구현 범위 | 남은 작업 |
|---|---|---|
| K01~K04 기반 | 선별 출처, C1 v0.2, 8종 매핑, manifest·의존성·권한·Compose 검사 | 전체 이식 자산·권리 대조, 릴리스 단위 의존성 고정 |
| K05 설치·보안 경로 | Ubuntu 26.04 설치기, fw→IPS→WAF, 검증 타깃, 선택 SIEM, 독립 HTTPS 관리 | 실제 Juice Shop/DVWA 선택 타깃, Community hosts 연계 |
| K06 수집·SIEM | 8종 C1/native 분석·receipt·검색, 재전송, 분석 오류 격리, 에이전트 등록/상태·격리 Linux 통신, 규칙 편집 WAF 회귀, 보존 예산 | 별도 호스트 실통신, 모듈별 미선택 원천/규칙 대조, K11 장기 부하·전체 디스크 복구 |
| K07 공통 보안 | 공통 로그인·3역할·CSRF·세션 폐기·원자적 감사·장비 정책 API, 직접 TCP 우회 차단 | K08 apply에 연결됨; Wazuh SSO는 현재 범위 밖 |
| K08 장비 콘솔 | FORWARD 중심 운영 UI, 객체·NAT·전체 규칙 탭, 3종 규칙 생성기, Unix socket 제어·버전/쓰기 잠금·검증/적용/복원 초안 | 사용자 UX 피드백, 전체 장비 프로파일 범위·장기 동시 변경 검증 |
| K09 화면 | 로고를 사용한 Core 관리와 별도 Wazuh Dashboard | registry/C4/C5, portal/NOC 2층·번들 열람 |
| K10 모듈 수명주기 | fixture 계획, SIEM 선택 해제·재포함 시 보존 | C7, 전체 모듈 설치/제거, 위조·만료·티어 거부와 실패 복원 |
| K11 운영 | 설치·재설치·재부팅과 단기 장애 검증 도구, DB/색인 보존 정책 | 백업·업데이트·복원, 전체 호스트 용량/원천 로그 회전, 최소 사양·장기 부하, 권리 목록 |
| K12 RC | 단계별 실행 증거와 미완료 범위 관리 | G1 전체 통합·배포 검증 |

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

K08의 [콘솔 초안](DEVICE-CONSOLES.md)을 먼저 검토하고 사용자 피드백을 반영한다. K05의 실제 타깃과 K11의 운영 잔여 항목을 출시 게이트에서 제외하지 않는다.
