# ADR 0009: Community 번들 콘텐츠는 Core에, 유료 콘텐츠 팩은 xocrange_contents에

- 상태: 소유자 결정, 2026-11-15
- 바꾸는 것: 2026-11-10의 "콘텐츠는 별도 저장소 `mrgrit/xocrange_contents`에서 내려받는다"([독립 콘텐츠 모듈](../development/CONTENT-MODULES.md) 이전 판, `content-lock.json`)
- 관계: 정본 `xocrange_plan`의 PACKAGING §5·MODULES "콘텐츠 팩"은 판매 단위의 분리를 말한다. 이 ADR은 무료 번들의 **보관 위치**만 정하며, 유료 콘텐츠 팩이 플랫폼과 분리되어 따로 판매된다는 원칙(D7)은 그대로다.

## 배경

`xocrange_contents`는 비공개 저장소다. Core 설치 프로그램은 그 저장소의 고정 커밋을 GitHub에서 내려받았으므로, Core를 공개해도 비공개 콘텐츠 저장소 때문에 아카데미 설치가 실패한다(오프라인 `--archive`만 동작). 동시에 유료 콘텐츠를 둘 비공개 저장소가 필요했다.

## 결정

1. **Community 번들**(공개 승인된 교재 1–339쪽 36개 차시·96개 기록 미션, 연계 공방전 15개 시나리오·105개 미션, 카탈로그 제목 23개, 시작 가이드)은 Core 저장소 `contents/`에 함께 관리한다. 원래 콘텐츠 모듈 형식(`module.json` 매니페스트, 파일별 SHA-256, 작성 도구 `contents/scripts/`)은 그대로 둔다.
2. 설치·설치 계획은 `contents/`가 `module.json`과 정확히 일치할 때만 진행한다(`scripts/verify-contents.py`, `xocrange.content_module.verify`). 다운로드·콘텐츠 잠금 파일은 없앤다. 매니페스트에 없는 파일, 누락·변경된 파일, 링크, 크기 초과는 거부한다. 작성 자료(`README.md`·`NOTICE`·`requirements.txt`·`provenance/`·`scripts/`)는 검사 대상 밖이며 설치되지 않는다.
3. **유료 콘텐츠 팩**은 비공개 `mrgrit/xocrange_contents`에 둔다. Core는 그 저장소를 읽지 않는다. 유료 팩의 전달·권한 확인은 C7 엔타이틀먼트와 함께 별도로 구현한다.
4. Live Fire Range Control은 Community 시나리오를 Core 저장소의 고정 커밋 `contents/`에서, 유료 시나리오를 `xocrange_contents`에서 같은 해시 검증으로 가져온다.

## 결과

- Core 저장소가 공개되면 네트워크 없이도 아카데미가 설치된다. 저장소 크기는 약 16 MB 늘어난다.
- 교관용 YAML의 기준 답안·검사 정의는 Core와 함께 공개된다. 이는 이전부터 "공개 Git 자료"로 정한 범위와 같다. Core의 학습자 API·정적 경로는 여전히 정답과 채점 기준을 내보내지 않는다. 공개된 검사 정의는 결정론 판정을 우회하는 단서가 될 수 있으므로, 평가 비중이 큰 시나리오는 유료 팩으로 둔다.
- Community 콘텐츠의 수정은 Core 커밋으로 남는다. 콘텐츠 ID 재사용 금지 규칙은 그대로다.
