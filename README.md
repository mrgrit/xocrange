<p align="center">
  <img src="assets/branding/xoc-range-logo.png" alt="xOC Range" width="720">
</p>

# xOC Range Core · Community

선택한 기능으로 구성하는 보안 운영 실습 환경. Core의 공통 계약 위에 Live Fire·Joint Force 모듈을 연결한다.

**개발 초기 단계:** Ubuntu 26.04 VM에서 자동 설치와 fw·IPS·WAF의 실제 통신·차단을 검증했다. 공통 관리 로그인·역할·세션·감사와 8종 보안 로그의 C1 정규화·원본 보관·Wazuh Manager/API·Indexer·전용 Dashboard와 C1 통합 검색을 연결했다. 장비 콘솔·포털과 전체 Community 배포본은 개발 중이다. `bootstrap`은 설치 기반 확인용 health 서비스다.

## 지금 실행할 수 있는 것

| 기능 | 현재 구현 |
|---|---|
| C1 이벤트 계약 | v0.2 JSON Schema, nftables·Suricata·ModSecurity·osquery·Sysmon·auditd·Apache access/error 정규화 |
| SIEM 백엔드 | 8종 원본 직접 분석과 C1 독립 전송, 원본 SHA-256, 처리 확인·재전송, Wazuh Manager/API·기본/보완 규칙, 원본 경보·증거 연결 |
| SIEM 웹 관제 | Wazuh Indexer + 전용 Dashboard, 8종 통합 검색·차트·필터, HTTPS 인증, 범위를 제한한 WAF Rule 예외 |
| 공통 보안 | `/core/` 관리 화면, 관리자·운영자·조회자 역할, 서버 세션·CSRF, 장비 쓰기 정책·변경 감사 |
| 설치 계획 | manifest 검증, 의존성·충돌·포트 검사, Compose·입력 해시 생성 |
| 구성 진단 | `xoc doctor`: 로컬 구성과 Docker CLI 존재 확인 |
| 구성요소 목록 | 필수 platform + 선택 기능; 준비된 기능과 계획 단계 구분 |
| 확장 경계 | 명시적으로 선택한 테스트 fixture 조합; C7 구현 전 상용 모듈 거부 |
| 보안 경로 실험 | fw DNAT·Suricata NFQUEUE·WAF, 선택 타깃 등록, 전용 VM 검사·기동·검증 명령 |
| 단일 실행 설치기 | OS 검사 → 의존성 설치 → 모듈 구성 → 빌드·기동 → 통신 검사 → 부팅 서비스 등록; 실제 VM에서 실행 완료 |

## 빈 Linux에서 설치

xOC의 설치 원칙은 **Linux 설치 후 설치 프로그램 한 번 실행으로 선택한 기능의 설치와 검증을 마치는 것**이다. Docker·Python·커널 모듈 등의 준비도 설치기가 담당한다.

Ubuntu Server 26.04 LTS amd64 전용 VM에서 저장소 또는 별도로 받은 `install.sh`를 실행한다. 스크립트만 받은 경우 소스도 자동 다운로드한다.

```bash
sudo bash install.sh
```

**현재 개발 버전의 설치 범위는 공통 관리 화면 + platform + 방화벽 + IPS + WAF + SIEM 백엔드·웹 관제 + 호스트 관측 도구 + 통신 검증용 타깃이다.** 웹 관제를 포함하면 최소 8 GiB RAM을 요구하며 실제 검증 VM은 16 GiB다. `--without siem-ui`로 웹 관제만 제외하거나 `--without siem`으로 SIEM 전체를 제외할 수 있다. 콘솔·포털까지 완성된 Core 전체 설치를 뜻하지 않는다. [웹 관제 구성·WAF 예외·검증](docs/development/SIEM-WEB.md)

설치 후 `sudo xoc platform credentials`로 `https://VM주소/core/`의 초기 관리자 계정을 확인하고 첫 로그인에서 비밀번호를 변경한다. 이 관리 화면은 SIEM 제외 시에도 유지된다. SIEM은 자체 Wazuh 계정을 사용하며, Core 역할을 SIEM에 자동 적용하는 SSO는 포함하지 않는다. [공통 보안과 권한](docs/development/COMMON-SECURITY.md)

`sudo xoc siem credentials`로 HTTPS 주소와 생성된 관리자 비밀번호를 확인한다. 기본 주소는 `https://VM주소/siem/`이며 `--public-host siem.example.test`로 DNS 이름을 지정할 수 있다. 설치기가 만든 로컬 CA(`/etc/xocrange/ca.crt`)는 접속 PC에 한 번 신뢰 등록해야 브라우저 인증서 경고가 없어진다. 인증서와 비밀번호는 재설치 시 유지한다.

설치기는 필요한 패키지를 설치하고 Docker와 containerd의 데이터 경로를 함께 구성한다. 기동 후 실제 차단·우회 방지·출처 보존·장애 복구 검사에 실패하면 비정상 종료하며 완료 상태를 기록하지 않는다. [설치 동작·선택 옵션·재실행](docs/development/INSTALLER.md)

## 개발 CLI 사용

개발 CLI는 Python 3.10 이상을 사용한다. 저장소 루트에서 실행한다.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'

xoc catalog
xoc doctor
xoc plan
python -m pytest -q
```

이미 의존성이 설치된 개발 환경에서는 `./bin/xoc`로도 실행할 수 있다. 다른 위치에서 실행할 때는 `xoc --root /path/to/xocrange plan`처럼 소스 디렉토리를 지정한다. wheel에는 CLI·스키마가 들어가며, 배포 구성은 체크아웃의 `components/`·`presets/`에서 읽는다.

설치 계획 파일은 명시적으로 요청한 새 디렉토리에만 저장한다. 아래 명령은 컨테이너를 기동하지 않는다.

```bash
xoc plan --output bootstrap-demo
docker compose -f .local/plans/bootstrap-demo/compose.yaml config --quiet

# 테스트용 확장 패키지의 의존성·조립 확인
xoc plan --allow-fixtures --include fixture-echo
```

`xoc plan --preset community-security`는 현재 `component_not_ready`로 종료한다. 해당 프리셋의 실제 구성요소 이식이 끝나면 사용한다. `doctor`의 성공은 호스트 자원·Docker daemon·실제 통신 경로 검증을 뜻하지 않는다.

## 보안 경로 실험 구성

새 검증 호스트는 **Ubuntu Server 26.04 LTS x86_64 전용 VM**을 기준으로 한다. 아래 계획 생성은 Docker를 실행하지 않는다. `--allow-experimental`은 정식 배포 전 실험 구성을 선택한다는 명시적 표시이며, 새 환경마다 실제 수용 검사를 실행한다.

```bash
xoc plan --preset security-path --allow-experimental \
  --allow-fixtures --include fixture-security-probe --output security-lab
xoc lab check --plan security-lab
```

실제 `lab up/start/verify/down`은 [전용 VM 실행 절차](docs/development/SECURITY-PATH-LAB.md)를 따른다. fw·ips·web에는 호스트 포트를 게시하지 않고 내부 테스트 클라이언트로 경로를 검증한다. 설치된 타깃만 WAF에 등록한다. 현재 IPS 룰은 동작 검증용 표식 룰이며 일반 공격 탐지 룰셋 구축은 후속 작업이다.

## C1 로그 정규화 예제

```bash
xoc events normalize \
  --source suricata \
  --input tests/fixtures/events/suricata-alert.json \
  --tenant-id community --range-id range-01 --source-id ips-01 \
  --evidence-ref fixture://eve/record-001 \
  --observed-at 2026-11-07T03:35:00Z > /tmp/xoc-events.json

xoc events validate --input /tmp/xoc-events.json
```

출력은 이벤트 JSON 배열이다. 원본의 tenant/range 주장은 사용하지 않으며, 요청·응답 본문과 인증 헤더를 출력에 복사하지 않는다. 이 명령은 오프라인 변환용이다. 설치된 로컬 수집기는 고정된 수집원 등록부와 관리자 권한으로 동작한다. 관리자는 내부 Manager API를 사용하는 `xoc agents enroll/list`로 Wazuh 에이전트를 등록·조회할 수 있다. 현재 에이전트 수집 포트는 내부망에 한정되며, Windows 번들의 티어 경계는 정본 계획을 따른다.

## 설치된 SIEM 확인

```bash
sudo xoc siem status
sudo xoc siem credentials
sudo xoc siem query --source suricata --confirmed --limit 10
sudo xoc siem query --source sysmon --confirmed --limit 10
sudo xoc siem retry --source auditd
```

`--confirmed`는 실제 Wazuh 분석 결과를 확인한 이벤트만 조회한다. 원본은 관리자 전용 저장소에 보관하며 `evidence.ref`로 연결된다. 정상 HTTP 403을 보안 장비 차단으로 오인하지 않으며, ModSecurity 요청과 탐지 메시지는 별도 이벤트로 구분한다. [8종 매핑·수집·운영 제한](docs/development/SIEM.md)

## 개발 문서

- [공통 인증·권한·감사](docs/development/COMMON-SECURITY.md) · [에이전트와 Windows 번들](docs/development/AGENTS-AND-WINDOWS.md)
- [현재 로드맵 상태](docs/development/ROADMAP-STATUS.md) · [kt66 규칙 이식 범위](docs/development/KT66-RULE-DISPOSITION.md)
- [SIEM 백엔드와 8종 디코더](docs/development/SIEM.md)
- [SIEM 웹 관제와 WAF Rule 예외](docs/development/SIEM-WEB.md) · [정식 Wazuh 연동 범위](docs/development/WAZUH-NATIVE.md)
- [첫 구현 결과와 다음 작업](docs/development/IMPLEMENTATION-01.md)
- [보안 경로 분리 결과와 검증 대기 항목](docs/development/IMPLEMENTATION-02.md)
- [한 번 실행 설치기](docs/development/INSTALLER.md) · [설치기 구현·검증 상태](docs/development/IMPLEMENTATION-03.md)
- [실제 Ubuntu VM 검증 기록](docs/development/VM-VALIDATION-2026-11-07.md)
- [Ubuntu 26.04 VM 구성·실행 절차](docs/development/SECURITY-PATH-LAB.md)
- [C1 v0.1/v0.2 계약과 소스별 매핑](docs/contracts/C1-EVENT.md)
- [설치 manifest·CLI 사용법](docs/development/PLANNER.md)
- [CI 템플릿과 활성화 상태](docs/development/ci/README.md)
- [Core 제품 경계](docs/adr/0001-core-boundaries.md) · [구현 구조](docs/adr/0002-contracts-and-planner.md)
- [착수 준비 기록](docs/development/READINESS.md) · [소스 기준선](docs/provenance/source-baseline-2026-11-07.json)
- [전체 계획과 WBS 이미지](DEVELOPMENT-PLAN.md)

Core는 보안 로그·운영 감사·수동 실습·선택형 장비 콘솔을 담당한다. 플랫폼 채점·대전·AI 근무자는 유료 모듈 책임이다. 기존 kt66 및 콘솔 코드는 출처·변경·배포 권리를 검토한 기능 단위로 이식한다. 구체적인 배포 라이선스는 검토 중이며, 이 저장소의 문서가 기존 코드의 라이선스를 변경하지 않는다.

로고는 계획 저장소 README에 등록된 원본을 그대로 사용했다. [출처와 SHA-256](assets/branding/provenance.json)을 함께 보관한다.
