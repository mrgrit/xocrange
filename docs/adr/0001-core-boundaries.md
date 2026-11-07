# ADR-0001: Community Core의 기능·소스·데이터 경계

상태: 기존 계획에 따른 착수 개발 기준. Windows/C8/배포 권리의 미결정 사항은 별도 추적한다.

근거: `xocrange_plan@5599078`의 CORE-KICKOFF, MODULES, PACKAGING, PRODUCT-PLAN.

## 결정

Core는 무료 제공 기능 범위다. 설치 단위는 필수 platform과 선택 가능한 구성요소로 나눈다. 기본 `community-security` 프리셋은 완전한 보안 실습 경로를 제공하며, `bootstrap` 기동만으로 제품 완료라고 하지 않는다.

| 기능 | Core의 책임 | 확장 모듈 책임 |
|---|---|---|
| 설치·공통 기반 | CLI·구성 검증·등록부·인증·권한·감사 | 모듈 자체 manifest·호환 선언 |
| 보안 경로 | fw·ips·web 및 라우팅 초기화 | 추가 네트워크/타깃 공급자 |
| SIEM·관측 | 일반 이벤트 정규화·수집·상태·감사 | M8 에이전트 실행/근무자 관제 |
| 장비 콘솔 | 장비 제어·미리보기·검사·적용·복원 | 교육 내용은 콘텐츠, 플랫폼 평가는 M15 |
| 접근·실습 | SSH 점프·감사·수동 실습 도구 | M9 AI 보안운영/GraphRAG, M18 AI 공격 참여 |
| 타깃 | Juice Shop·DVWA 선택 | M1 추가 웹앱/허니팟, M3 AI Safety |
| 화면 | portal·NOC 2층 shell·번들 자료 열람 | M4 시설/주입, M7 AI 운영, C4 확장 화면 |
| 자산 | 설치 서비스 registry·안정된 asset ID·health | M13 자동 discovery·HW/SW CMDB |
| 평가·기록 | 운영 로그·보안 로그·장비 변경 감사 | M15 Assessor·대전·성적·Debrief |
| 라이선스 | 키 없는 Community·유료 권한 검증 공개키 | 상용 키 발급·회수·좌석 운영 |

## 구현에 적용하는 규칙

1. `web`은 설치하지 않은 유료 타깃에 의존하지 않는다. 활성 타깃만 vhost·링크를 등록한다.
2. NOC와 portal은 M4/M7 없이 기동한다. 시설·주입·근무자 명단을 필수 파일/API로 취급하지 않는다.
3. Compose에서 서비스를 빼는 것에 그치지 않고 Dockerfile·entrypoint·설치 스크립트의 AI/채점 코드 포함 여부도 확인한다.
4. 콘솔 원본은 `~/pjt/{nft,modsec,suricata}_edu_gui`를 기준으로 하고 kt66 벤더본의 필요한 변경은 diff 검토 후 적용한다.
5. `observability/schema.py`는 에이전트 관제 매핑을 재사용하는 출발점이다. 범용 C1 계약으로 일반화하며 기존 전용 필드를 모든 이벤트의 필수값으로 만들지 않는다.
6. 운영 상태·시크릿·백업·로컬 원본 보존 파일은 소스와 분리한다. 미커밋 원본 코드를 공개 저장소로 자동 복사하지 않는다.
7. Community도 신뢰된 수집원에 묶인 tenant/range ID를 사용한다. ID 필드만으로 다중 사용자 격리가 구현됐다고 간주하지 않는다.

## 미결정 사항

M6 Windows, C8 경험 기록, infraops의 M4/M15 책임 분할, 구체적인 라이선스 문안은 기존 착수안의 보류 상태를 유지한다. 이 항목의 확정을 기다리며 Core C1·설치 기반 개발을 멈추지 않는다.

## 완료 검증

Core 이미지를 유료/AI/평가 코드 없이 구성하고, M1~M19 및 AI credentials/GPU 없이 기본 프리셋을 설치한다. 선택 기능 제거 후 의존성·route·수집 설정 잔재가 없어야 한다. 실제 검증은 K05~K12/G0/G1에서 수행한다.
