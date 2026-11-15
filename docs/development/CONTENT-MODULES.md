# 콘텐츠 모듈

[ADR 0009](../adr/0009-community-content-in-core.md): **Community 번들은 이 저장소의 `contents/`**, **유료 콘텐츠 팩은 비공개 [mrgrit/xocrange_contents](https://github.com/mrgrit/xocrange_contents)**에 둔다. Core는 리더·API·권한·학습 기록·설치 연결을 관리하고, 교재·그림·미션·정답·배점·과목·카탈로그 제목·시작 가이드는 콘텐츠 모듈 형식으로 관리한다.

## 구성

| 경로 | 내용 | 설치 |
|---|---|---|
| `contents/module.json` | 모듈 ID `community-academy`, 배포 파일마다 경로와 SHA-256 | 검증 기준 |
| `contents/academy/`, `battle-scenarios/`, `catalog/`, `guides/` | 배포 파일(매니페스트 검증 대상) | 릴리스·플랫폼 볼륨 |
| `contents/scripts/`, `provenance/`, `README.md`, `NOTICE`, `requirements.txt` | 작성 도구·출처(매니페스트 대상 아님) | 릴리스 소스 사본에만 포함, 실행·학습자 노출 없음 |

## 설치와 검증

`sudo bash install.sh`는 아카데미를 선택하면 `scripts/verify-contents.py`로 `contents/`가 `module.json`과 정확히 일치하는지 확인한다. 다운로드는 없다. `--without academy-reader`이면 생략한다. 매니페스트에 없는 파일, 누락·변경된 파일, 심볼릭 링크, 경로 이탈, 크기 초과를 거부한다.

불변 릴리스는 소스 사본이므로 `contents/` 전체(작성 도구 포함)가 들어가고 모든 파일의 해시가 릴리스 매니페스트에 남는다. 설치 계획에는 `module.json` 해시를 기록한다. 작성 도구는 설치본에서 실행되지 않는다. `academy-reader`를 선택했을 때만 학습자용 교재·미리보기·카탈로그를 플랫폼의 읽기 전용 설정 볼륨에 복사한다. 교관용 YAML의 정답과 채점 기준은 학습자 API나 정적 웹 경로에 내보내지 않는다. 학습 노트·첨부·제출은 별도의 기존 DB에 보존한다.

```bash
python3 scripts/verify-contents.py
python3 -m pytest -q
```

## 콘텐츠 수정 순서

1. `contents/` 아래 교재·시나리오를 수정한다. 기존 강좌·차시·미션 ID를 다른 주제에 재사용하지 않는다.
2. `pip install -r contents/requirements.txt`(PyYAML) 후:
   ```bash
   python3 -B contents/scripts/content-module.py validate
   python3 -B contents/scripts/content-module.py sync-preview   # 시나리오를 고쳤을 때
   python3 -B contents/scripts/content-module.py manifest
   ```
3. `python3 scripts/verify-contents.py`와 시험을 통과한 뒤 Core 변경과 함께 커밋한다.
4. Live Fire Range Control이 같은 시나리오를 쓰면 그쪽 `range-control/deploy/content-lock.json`의 커밋과 매니페스트 해시를 갱신한다.

## 유료 콘텐츠 팩

`xocrange_contents`는 같은 모듈 형식(매니페스트·파일별 해시)을 쓰는 유료 팩 저장소다. Core는 이 저장소를 읽지 않는다. 기관 구매 권한(C7)과 팩 전달·설치는 후속 구현 범위다.

## 이력

2026-11-10~11-14에는 콘텐츠를 별도 저장소의 고정 커밋에서 내려받았다(`content-lock.json`, `scripts/fetch-contents.py`). 그 경로의 실제 VM 검증은 [검증 기록](../provenance/content-module-acceptance.json)에 남아 있다. 2026-11-15 ADR 0009로 번들을 Core에 옮겼다(콘텐츠 커밋 `7cae1e1`, 매니페스트 `d439026d…`, 배포 파일 360개).
