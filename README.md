<p align="center">
  <img src="assets/branding/xoc-range-logo.png" alt="xOC Range" width="720">
</p>

# xOC Range Core · Community

선택한 기능으로 구성하는 보안 운영 실습 환경. Core의 공통 계약 위에 Live Fire·Joint Force 모듈을 연결한다.

## 설치 후 접속 · 계정 확인

설치한 **xOC 서버의 터미널**에서 아래 명령으로 주소와 관리자 초기 접속 정보를 확인한다. Windows PC에서는 먼저 `ssh 사용자명@서버IP`로 서버에 접속하면 된다.

| 구분 | 브라우저 접속 주소 | 계정·초기 비밀번호 확인 명령 |
|---|---|---|
| **Core 관리 · 데이터센터** | `https://서버IP/core/` | `sudo xoc platform credentials` — 관리자 계정 `admin` |
| **SIEM · Wazuh** | `https://서버IP/siem/` | `sudo xoc siem credentials` — Core와 별도 계정 |

```bash
# Core 관리자 접속 정보
sudo xoc platform credentials

# SIEM 관리자 접속 정보
sudo xoc siem credentials
```

예를 들어 서버 IP가 `192.168.0.74`이면 **[Core 로그인](https://192.168.0.74/core/)** 및 **[SIEM 로그인](https://192.168.0.74/siem/)**으로 접속한다. `--public-host`에 도메인을 지정했다면 명령에 표시되는 주소를 사용한다.

처음 로그인하면 Core 초기 비밀번호를 변경해야 한다. 이후에는 변경한 비밀번호를 사용한다. 위 명령은 UI에서 변경한 비밀번호를 조회하거나 초기화하지 않는다. 고정 공용 비밀번호는 없으며 실제 비밀번호는 README나 Git에 기록하지 않는다. 로컬 인증서를 사용하는 경우 설치된 서버의 `/etc/xocrange/ca.crt`를 접속 PC에서 신뢰 등록한다.

**개발 초기 단계:** Ubuntu 26.04 VM에서 자동 설치와 fw·IPS·WAF의 실제 통신·차단을 검증했다. 공통 관리 로그인·역할·세션·감사와 8종 보안 로그의 C1 정규화·원본 보관·Wazuh Manager/API·Indexer·전용 Dashboard와 C1 통합 검색을 연결했다. 운영 장비 형태의 FW·IPS·WAF 콘솔 초안을 연결했다. 층별 데이터센터 시각화·운영 개요·NOC 2층·번들 자료실을 연결했다. 전체 Community 배포본은 개발 중이다. `bootstrap`은 설치 기반 확인용 health 서비스다.

## 지금 실행할 수 있는 것

| 기능 | 현재 구현 |
|---|---|
| C1 이벤트 계약 | v0.2 JSON Schema, nftables·Suricata·ModSecurity·osquery·Sysmon·auditd·Apache access/error 정규화 |
| SIEM 백엔드 | 8종 원본 직접 분석과 C1 독립 전송, 원본 SHA-256, 처리 확인·재전송, Wazuh Manager/API·기본/보완 규칙, 원본 경보·증거 연결 |
| SIEM 웹 관제 | Wazuh Indexer + 전용 Dashboard, 8종 통합 검색·차트·필터, HTTPS 인증, 범위를 제한한 WAF Rule 예외 |
| 공통 보안 | `/core/` 관리 화면, 관리자·운영자·조회자 역할, 서버 세션·CSRF, 장비 쓰기 정책·변경 감사 |
| 장비 콘솔 초안 | FORWARD 필터 정책, 객체·NAT, IPS/WAF 규칙, 실제 설정 검증·적용·복원, 별도 전체 규칙 탭 |
| 데이터센터 시각화 | kt66 층·설비 디자인 계승, 랙 → 장비 목록 → 상태·설명·웹 콘솔·SSH 명령 복사, 티어별 비활성 공간 |
| 설치 계획 | manifest 검증, 의존성·충돌·포트 검사, Compose·입력 해시 생성 |
| 구성 진단 | `xoc doctor`: 로컬 구성과 Docker CLI 존재 확인 |
| 구성요소 목록 | 필수 platform + 선택 기능; 준비된 기능과 계획 단계 구분 |
| 확장 경계 | Ed25519 C7 서명·기관·티어·모듈·구매 권한 검증, 키 없는 Community |
| 보안 경로 실험 | fw DNAT·Suricata NFQUEUE·WAF, 선택 타깃 등록, 전용 VM 검사·기동·검증 명령 |
| 단일 실행 설치기 | OS 검사 → 의존성 설치 → 모듈 구성 → 빌드·기동 → 통신 검사 → 부팅 서비스 등록; 실제 VM에서 실행 완료 |

## 빈 Linux에서 설치

xOC의 설치 원칙은 **Linux 설치 후 설치 프로그램 한 번 실행으로 선택한 기능의 설치와 검증을 마치는 것**이다. Docker·Python·커널 모듈 등의 준비도 설치기가 담당한다.

Ubuntu Server 26.04 LTS amd64 전용 VM에서 저장소 또는 별도로 받은 `install.sh`를 실행한다. 스크립트만 받은 경우 소스도 자동 다운로드한다.

```bash
sudo bash install.sh
```

**현재 개발 버전의 설치 범위는 공통 관리 화면 + 데이터센터·운영 개요·NOC 2층·자료실 + 장비 콘솔 3종 + platform + 방화벽 + IPS + WAF + SIEM 백엔드·웹 관제 + 호스트 관측 도구 + 통신 검증용 타깃이다.** 웹 관제를 포함하면 최소 8 GiB RAM을 요구하며 실제 검증 VM은 16 GiB다. `--without siem-ui`로 웹 관제만 제외하거나 `--without siem`으로 SIEM 전체를 제외할 수 있다. `--without portal`, `--without noc`, `--without academy-reader`로 각 화면을 제외할 수 있다. 모듈 설치·제거와 백업·업데이트·복구 명령을 제공한다. 실제 입문 타깃과 전체 출시 검증은 후속 단계다. [운영 개요·NOC·자료실](docs/development/WORKSPACES.md) [웹 관제 구성·WAF 예외·검증](docs/development/SIEM-WEB.md)

설치 후 `sudo xoc platform credentials`로 `https://VM주소/core/`의 초기 관리자 계정을 확인하고 첫 로그인에서 비밀번호를 변경한다. 이 관리 화면은 SIEM 제외 시에도 유지된다. SIEM은 자체 Wazuh 계정을 사용하며, Core 역할을 SIEM에 자동 적용하는 SSO는 포함하지 않는다. [공통 보안과 권한](docs/development/COMMON-SECURITY.md)

로그인 후 `/core/#datacenter`에서 데이터센터 전체와 2층 내부를 볼 수 있다. 2층에서 **랙 → 장비**를 선택하면 현재 상태·장비 설명·웹 콘솔 링크와 복사 가능한 SSH/장비 셸 명령이 나온다. Linux 계정과 SSH 포트는 접속 패널에서 지정한다. Core의 운영 기능은 2F에서 제공한다. **메인 화면에는 데이터센터만 크게 표시하고, 6층을 열면 콘텐츠 카탈로그가 먼저 나온다.** 현재 Core 번들은 여러 콘텐츠 중 이용 가능한 카드 하나다. admin은 나머지 회색 층도 클릭해 확대 디자인을 볼 수 있다. 7F에서 **공간 디자인 / 화면 구성**을 전환하면 콘텐츠 카탈로그와 미션 대시보드를 확인할 수 있다. 일반 사용자의 상용 층 잠금은 유지하며, 관리자 미리보기의 훈련 실행 버튼도 비활성이다. 각 층의 헬멧·점프슈트 아바타는 직무·직급별 디자인이며 에이전트 실행은 연결하지 않았다. 기관별 유료 콘텐츠·공방전 권한과 Joint Force 학생 회사 실행은 후속 상용 모듈 범위다. [공간 구성과 권한 경계](docs/development/DATACENTER.md)

장비 콘솔은 `/core/#fw/policies`, `/core/#ips/policies`, `/core/#waf/policies`에서 사용한다. `--without console-fw`·`console-ips`·`console-waf`로 각각 제외할 수 있으며 기존 정책은 유지한다. 적용하려면 관리자가 **접근 제어 → 쓰기 허용**을 설정한다. [콘솔 초안과 적용 범위](docs/development/DEVICE-CONSOLES.md)

`sudo xoc siem credentials`로 HTTPS 주소와 생성된 관리자 비밀번호를 확인한다. 기본 주소는 `https://VM주소/siem/`이며 `--public-host siem.example.test`로 DNS 이름을 지정할 수 있다. 설치기가 만든 로컬 CA(`/etc/xocrange/ca.crt`)는 접속 PC에 한 번 신뢰 등록해야 브라우저 인증서 경고가 없어진다. 인증서와 비밀번호는 재설치 시 유지한다.

설치기는 필요한 패키지를 설치하고 Docker와 containerd의 데이터 경로를 함께 구성한다. 기동 후 실제 차단·우회 방지·출처 보존·장애 복구 검사에 실패하면 비정상 종료하며 완료 상태를 기록하지 않는다. [설치 동작·선택 옵션·재실행](docs/development/INSTALLER.md)

## 아카데미와 실습 기록

Core 로그인 후 데이터센터 **6층** 또는 왼쪽 **아카데미**를 연다. 직접 주소는 `https://서버주소/core/#academy`다. 카탈로그에는 실제 교육 트랙 23개와 Core 번들 1개를 표시한다. 현재 번들만 이용 가능하며 미설치 콘텐츠는 회색으로 표시하고 클릭할 수 없다. 콘텐츠 선택 → 강좌 → 차시 순서로 열고, 공개 교재 1–339쪽, 36개 차시의 **교재·해설과 실습 노트를 같은 화면**에서 본다. 목차는 상단 버튼으로 열고, 교재 본문은 큰 글씨로, 그림은 적정 크기로 표시한다. 그림을 클릭하면 원본을 볼 수 있다.

아카데미는 **차시당 한 편의 실습 노트**다. 글·제목·명령·전체 출력·여러 캡처를 블로그처럼 순서대로 배치한다. 입력 후 자동 임시 저장되며, **지금 저장 / 작성 완료**로 수정 이력도 남긴다. 재접속하면 이어 쓸 수 있고 기존 미션 기록은 보존한다. 현황은 층 내부에서만 표시한다. 6층의 공간 보기에는 콘텐츠 목록과 내 학습 기록이, 7층에는 실제 시나리오·미션이 표시된다. 메인으로 돌아가면 현황은 숨겨진다. 왼쪽 데이터센터 메뉴와 다시 로그인한 데이터센터는 항상 건물 전체에서 시작한다. 디스플레이의 강좌나 시나리오를 누르면 해당 콘텐츠가 열린다.

Live Fire는 모든 미션을 **학습자 시도 → 시스템 반응 → 학습자의 해석**으로 작성한다. 작성 내용은 자동 임시 저장되며, **미션 등록**으로 세 항목과 캡처의 수정 이력을 남긴다. 미션 이동·재접속 후 이어 쓸 수 있고 **나의 기록**에서 등록 당시 내용을 조회한다. 시스템 반응에는 긴 로그와 여러 캡처를 기록할 수 있다. 등록은 기록 보관이며 AI 점수·리더보드는 훈련 엔진 연결 후 제공한다.


강좌는 **웹 침해 대응 8개 + 리눅스·네트워크 침해 대응 7개**, 총 15개 Live Fire 시나리오와 연결된다. 각 시나리오는 Red 2·Blue 3·Purple 2, 총 7개 미션/100점이다. `#academy/scenarios` 및 관리자 7층 화면에서 105개 미션을 미리 볼 수 있다. [시나리오 목록·정답·채점 규격](https://github.com/mrgrit/xocrange_contents/tree/main/battle-scenarios)

콘텐츠는 별도 모듈 저장소 [xocrange_contents](https://github.com/mrgrit/xocrange_contents)에서 관리한다. Core에는 본문을 중복 저장하지 않으며, `content-lock.json`으로 지정한 커밋·파일 해시를 검증해 설치 프로그램이 자동으로 내려받는다. `--without academy-reader`이면 다운로드와 설치를 생략한다. tw2 형식의 YAML에 상세 기준 답안·부분점수·동등 답안·오답 사례를 작성했고, Core 화면에는 정답을 제외한 콘텐츠만 제공한다. 실제 공방전 실행과 AI 채점은 Live Fire의 tw2 엔진 통합 단계이며, 현재 Core에서 실행하지 않는다. 교재와 실습 환경 정합성 검토는 후속 작업이다. [화면과 저장 구조](docs/development/ACADEMY.md)

공방전은 **미션별 초안 → 등록 → 채점** 흐름으로 설계한다. 혼자 훈련하거나 교수자가 리그를 개설해 학생이 참가할 수 있도록 [개인 훈련·리그 설계](docs/development/LIVE-FIRE-LEAGUES.md)를 작성했다. 이번에는 설계만 반영했으며 리그 생성·실행 기능은 아직 제공하지 않는다.

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

SIEM의 `observation`은 Sysmon·osquery의 행위 관측 기록이다. 프로세스 실행·네트워크 연결·프로세스 목록 변화가 여기에 포함되며, 이 분류 자체가 공격 탐지를 뜻하지는 않는다. Core 기본 Sysmon 정책은 실행·연결을 수집하고, 양이 많은 프로세스 종료(EventID 5)는 수집하지 않는다. 로컬 증거는 기본 1일, Wazuh 회전 로그는 2일, 검색 인덱스는 7일 보관한다. `sudo xoc siem status`의 `storage`에서 DB 사용량·할당량·디스크 여유를 확인할 수 있다. [수집량과 보관 정책](docs/development/SIEM.md#보존과-복구-설정)

## 구성 변경과 백업

```bash
sudo xoc module list
sudo xoc module add noc
sudo xoc module remove noc
sudo xoc backup create /var/lib/xocrange/backups/manual-001
sudo xoc backup verify /var/lib/xocrange/backups/manual-001
sudo xoc update --source /절대경로/새소스
```

변경 중에는 서비스를 정지해 복구 지점을 만들고, 새 구성 검증에 실패하면 이전 설치로 복원한다. 백업에는 비밀번호·계정·실습 로그가 포함되므로 비공개로 보관한다. [복원·중단 복구·운영 명령](docs/development/OPERATIONS.md) · [C7 상용 권한 계약](docs/contracts/C7-ENTITLEMENTS.md) · [의존성·배포 경계](docs/development/DEPENDENCIES.md)

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

콘텐츠 개발·오프라인 설치·버전 갱신: [독립 콘텐츠 모듈](docs/development/CONTENT-MODULES.md). 소스에서 테스트하거나 아카데미 설치 계획을 만들 때는 먼저 `python3 scripts/fetch-contents.py`를 실행한다.
