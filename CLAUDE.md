# CLAUDE.md — xOC Range Core

xOC Range(본문 호칭 `xoc`)의 Core/Community 구현 저장소. kt66을 상용 플랫폼으로 재구성한다.

## 정본 계획 (작업 전 반드시 확인)

계획 정본은 별도 저장소 `mrgrit/xocrange_plan`이다(로컬: `../xocrange_plan`). 이 저장소의 문서는 진행 기록이며 정본의 티어·모듈 경계를 바꾸지 않는다.

- `docs/CORE-KICKOFF.md` — Core 범위, K01~K12 작업, G0/G1 게이트 (가장 중요)
- `docs/PACKAGING.md` — 계약 C1~C7, `module.yaml`, 조립·엔타이틀먼트
- `docs/MODULES.md`, `docs/TIERS.md` — Core vs 유료 모듈(M1~M19) vs 콘텐츠 팩 경계
- `docs/NAMING.md` — 표기 규칙
- 진행 상태: 이 저장소의 `docs/development/ROADMAP-STATUS.md`, 경계 결정: `docs/adr/`

## 지켜야 할 설계 규칙

- **Core에 유료 기능을 넣지 않는다.** Assessor·채점·대전 실행(M15), AI 근무자·LLM 호출·모델·GPU(M5/M7/M9), 시설·주입기(M4)는 Core 이미지·Compose·Dockerfile·entrypoint 어디에도 포함하지 않는다. Core는 기록 저장까지만, 채점은 하지 않는다. Core 화면에 정답을 노출하지 않는다.
- **계약으로만 연결한다.** 모듈 간 직접 호출 대신 C1~C7 계약(`src/xocrange/contracts/`)을 쓴다. 계약 변경 시 버전과 호환성 검사를 같이 고친다.
- C1 이벤트의 `tenant_id`/`range_id`는 서버 측 수집원 등록에서만 온다. 원본 입력의 값을 신뢰하지 않는다.
- C7: Community는 키 없이 동작한다. 저장소에는 검증 공개키만 둔다. 개인 서명키·테스트 키를 배포 빌드에서 신뢰하지 않는다.
- 상태·비밀·백업·생성물은 소스와 분리한다(`/etc/xocrange`, `/var/lib/xocrange`). 비밀번호·토큰·PAT를 파일·커밋·로그에 남기지 않는다.
- 표기: 브랜드는 `xOC Range`, 본문·CLI·경로는 `xoc`/`xocrange`. `XOC`·`X-OC` 금지. 사용자 화면에 `kt66` 노출 금지(내부 코드명만 허용).
- kt66 코드는 통째로 복사하지 않는다. 기능 단위로 이식하고 출처를 `docs/provenance/`에 남긴다.

## 개발 명령

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -e '.[test]'
python3 scripts/verify-contents.py     # contents/(Community 번들)가 module.json과 일치하는지 확인 — 콘텐츠 수정 뒤 manifest 재생성
python -m pytest -q --ignore=tests/browser   # 단위·계약 테스트 (약 2~3분)
./bin/xoc catalog | doctor | plan
```

- 테스트는 `tests/conftest.py`에서 바이트코드 생성을 끈다. 컴포넌트 빌드 컨텍스트에 `__pycache__`가 생기면 planner가 `untracked_build_input`으로 거부한다. 수동으로 컴포넌트 코드를 import했다면 `find components -name __pycache__ -exec rm -rf {} +`.
- 빌드 컨텍스트에 파일을 추가하면 해당 component manifest의 선언 파일 목록도 같이 고친다.
- `tests/browser/`는 Playwright·실제 설치본 필요, `tests/integration/`은 설치된 VM에서 root로 실행하는 수용 검사다.

## 설치본(이 VM) 다루기

- 설치: `sudo bash install.sh` (Ubuntu 26.04 amd64 전용). 설치본은 `/opt/xocrange/releases/<hash>` + `current` 링크, 런타임 상태는 `/var/lib/xocrange`, 설정·비밀은 `/etc/xocrange`.
- 상태: `sudo xoc siem status`, `sudo xoc doctor`, `systemctl status xocrange-core xocrange-collector xocrange-osquery`.
- 소스 갱신 반영: `sudo xoc update --source <절대경로>` (설치 전 백업 생성 → 실패 시 자동 복원). 운영 설치본을 직접 수정하지 않는다.
- 디스크: SIEM DB(`/var/lib/xocrange/siem/events.sqlite3`)는 incremental auto-vacuum으로 정리 때마다 빈 페이지를 반환한다. 실제 사용량은 `xoc siem status`의 `storage.used_bytes`로 본다. 설치 전 백업(`/var/lib/xocrange/backups`)은 자동 삭제되지 않으므로 주기적으로 최신 1개만 남긴다.

## 작업 방식

- 큰 변경 전 정본 계획의 해당 K 작업·게이트를 확인하고, 완료 후 `ROADMAP-STATUS.md`와 관련 검증 문서를 갱신한다.
- 검증하지 않은 것을 완료로 쓰지 않는다. 문서에 "실행 검증"과 "코드 존재"를 구분한다.
- 커밋 메시지는 기존 스타일(`fix(siem): ...`, `feat(core): ...`)을 따른다.
