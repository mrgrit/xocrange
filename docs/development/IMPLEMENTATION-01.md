# 첫 구현 결과 · 2026-11-07

목표: K03 C1과 K04 설치 기반의 첫 실행 가능한 부분을 만든다. 이번 결과는 전체 Core 또는 해당 WBS 전체의 완료가 아니다.

| WBS | 이번 결과 | 남은 작업 |
|---|---|---|
| K01 기준선 | 기존 19개 선별 파일·patch 보존 상태 유지 | 실제 이식 대상 전체로 확장, 권리·시크릿 검토 |
| K02 경계 | ADR-0001 적용, 구성요소 12개 manifest, ADR-0002 | 33서비스의 이미지·entrypoint·volume·API 의존 그래프 구체화 |
| K03 계약 | C1 v0.1 스키마·3종 소스 정규화·합성 fixture | 실제 수집 통합, C2~C7 및 C8 제안 검토 |
| K04 설치 | catalog/plan/doctor, 조합 검증, Compose·입력 lock, fixture 확장 | install/apply·제거·업데이트·롤백·배포 lock |
| K05 이후 | bootstrap health 서비스 소스·Compose 준비 | 실제 보안 경로·SIEM·인증·콘솔·UI·릴리스 이식 |

## 확인한 결과

- Python 3.10.12, PyYAML 5.4.1, jsonschema 3.2.0에서 **65개 테스트 통과**.
- bootstrap 및 fixture 확장 Compose 생성 후 `docker compose ... config --quiet` 통과.
- wheel 빌드 및 별도 venv 설치 후 `xoc doctor`, C1 normalize→validate 왕복 확인.
- 로고는 계획 저장소 README 원본과 동일한 PNG를 보존하고 출처·SHA-256 기록.

테스트는 scope 위조 무시, replay ID, source/observed 시간, transaction 부모·자식, HTTP 403 오분류 방지, malformed 입력, 의존성·버전·상용 경계·충돌·경로 이탈·출력 덮어쓰기 거부를 포함한다.

테스트 중 Python 3.10의 EVE `+HHMM` 시간대 해석과 jsonschema 3.x의 선택 의존성 없는 날짜 검증 차이를 수정했다. 날짜 검증은 선택 패키지 유무에 의존하지 않는다.

GitHub Actions의 Python 3.10/3.12 테스트·Compose 설정 검사·wheel 빌드를 [CI 템플릿](ci/README.md)으로 작성했다. 첫 게시에 사용한 PAT에 `workflow` 권한이 없어 템플릿 상태로 보관하며, **원격 CI는 아직 활성화하지 않았다.** 기존 kt66의 컨테이너·서비스·설정은 변경하지 않았으며, 실제 bootstrap 컨테이너 build/up 및 보안 경로 통합 테스트도 아직 수행하지 않았다.

## 저장소 상태

현재 작업공간의 `.git`은 읽기 전용이며 유효한 Git 저장소가 아니다. 원격 기록은 쓰기 가능한 별도 체크아웃에서 커밋·푸시하며, 현재 작업공간의 `.git`은 변경하지 않는다. Core 소스·로고·문서·테스트·CI 설정은 `mrgrit/xocrange`에서 관리하고, 기존 계획·이미지는 `mrgrit/xocrange_plan`에서 관리한다. `.local/`의 원본 보존 자료와 운영 데이터는 공개 대상에서 제외한다.

## 다음 착수 단위

1. K02: fw/ips/web/netglue의 실제 파일·이미지·볼륨·API 의존성을 목록화하고 K01 보존 범위를 확장한다.
2. K05: 별도 VM에서 `security-path`를 이식한다. 선택 타깃만 web에 등록하고 유료 서비스의 필수 의존성을 제거한다.
3. K06: C1 어댑터를 실제 수집·원본 보관·중복 제거·SIEM 저장 경로에 연결한다.
4. K07: 수집원 인증, 사용자·역할·감사와 registry를 구현한다. 그 후 콘솔·portal/NOC를 연결한다.

이 순서로 첫 Community 수직 경로인 **수동 실습 → fw/ips/web → C1 이벤트 → SIEM 조회**를 완성한다.
