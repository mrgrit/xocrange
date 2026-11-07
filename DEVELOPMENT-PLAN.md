# xOC Range Core 개발 착수

이 디렉토리는 xOC Range Core(Community) 구현 목적지다. 전체 제품 계획과 착수 계획의 정본은 `mrgrit/xocrange_plan`에서 관리한다.

- [Core 개발 착수 계획](https://github.com/mrgrit/xocrange_plan/blob/main/docs/CORE-KICKOFF.md)
- [코드 기준선·자산 대조·검증 결과](https://github.com/mrgrit/xocrange_plan/blob/main/docs/CORE-BASELINE.md)
- [기계 판독용 소스 기준선](https://github.com/mrgrit/xocrange_plan/blob/main/docs/evidence/core-baseline-2026-11-07.json)
- 계획 반영 커밋: `67a83cf96ce0349220d0b7d683309c3e0e0dd5d9` (2026-11-07)

계획 이미지도 별도 디렉토리에서 관리한다(PNG·SVG, 2400×1680).

- [마스터 플랜 7장](https://github.com/mrgrit/xocrange_plan/tree/main/visuals/master-plan)
- [Core 상세 WBS 16장](https://github.com/mrgrit/xocrange_plan/tree/main/visuals/core) — K01~K12, 하위 작업 36개
- [이미지 전체 목차·재생성 원본](https://github.com/mrgrit/xocrange_plan/blob/main/visuals/README.md)
- 이미지 반영 커밋: `5599078` (2026-11-07)

## 첫 작업

1. K01: kt66의 HEAD와 미커밋 변경을 구분하고, 이식할 파일·패치의 출처를 보존한다.
2. K02: Core 무료 구성요소·유료 모듈·콘텐츠 경계를 고정한다.
3. K03: C1 이벤트 계약과 Suricata·ModSecurity·nftables fixture를 만든다.
4. K04: manifest·선택 설치·의존성 검사·Compose 조립기의 첫 조각을 구현한다.

첫 10 근무일은 위 작업의 PR-01~04 범위다. Community RC까지의 집중 공수 추정은 47~70인일이며 기준선 확인 후 다시 산정한다.

## 이식 기준

kt66의 네트워크·장비 제어·SIEM 회귀 자산을 재사용한다. 보안콘솔 정본은 `~/pjt/{nft,modsec,suricata}_edu_gui`다. Core의 SSH/일반 관제와 유료 AI 운영/평가 기능을 분리하고, Community의 운영 로그·감사는 유지한다. 상세 의존성·완료 기준·티어 정책 쟁점은 정본 계획을 따른다.

## 실행 상태

현재 단계별 구현·검증·미완료 항목은 [로드맵 실행 상태](docs/development/ROADMAP-STATUS.md)에 기록한다. 정식 Wazuh Manager·Indexer·Dashboard와 원본 경보 유지가 K05/K06의 목표이며, 일반 OpenSearch 실험 화면의 검증을 기능 동등성 완료로 해석하지 않는다.
