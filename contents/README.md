# xOC Range Community 콘텐츠 번들

Core와 함께 제공하는 무료 교재·실습·공방전 콘텐츠입니다([ADR 0009](../docs/adr/0009-community-content-in-core.md)). 시스템 코드와 화면, 학습 기록 DB는 저장소의 나머지 부분이 맡습니다. 유료 콘텐츠 팩은 별도 비공개 저장소에서 제공합니다.

| 경로 | 내용 |
|---|---|
| `academy/` | 교재, 차시별 설명과 실습, 이미지, 원본 매핑, 학습자용 공방전 미리보기 |
| `battle-scenarios/` | 교관용 시나리오, Red·Blue·Purple 미션, 정답, 해설, 배점, 의미 평가 기준 |
| `catalog/` | 콘텐츠 목록과 과목 메타데이터 |
| `guides/` | Core 시작 가이드 |
| `scripts/` | 콘텐츠 가져오기·검증·학습자 미리보기 생성 도구 |
| `provenance/` | 원본 출처와 검증 기록 |

현재 공개 번들은 **시스템 침투와 SIEM 분석**입니다. 승인 범위는 PPT **1–339페이지**, 36개 차시, 96개 기록 미션이며, 연계 공방전은 2개 과목·15개 시나리오·105개 미션입니다. 추가 교육 트랙 23개는 카탈로그 제목만 등록되어 있습니다.

Core 설치 프로그램은 이 폴더가 `module.json`의 파일별 해시와 정확히 일치할 때만 설치합니다. `--without academy-reader`를 선택하면 설치를 생략합니다.

강좌·차시·미션 ID는 학습 기록 연결 키입니다. 기존 ID를 다른 주제에 재사용하지 않습니다. 학습자가 작성한 노트·첨부·제출·점수·기관 구매 권한은 이 폴더에 넣지 않습니다.

아카데미는 교재와 실습 노트를 함께 보여 줍니다. 학생은 실습 과정의 텍스트와 여러 캡처를 기록하고 중간 저장할 수 있습니다. Live Fire는 모든 미션에 **학습자 시도 → 시스템 반응 → 학습자의 해석** 세 항목을 작성하고 한 묶음으로 등록합니다. 원본 로그와 여러 캡처를 기록할 수 있으며 초안과 등록 이력은 시스템 DB에서 보관합니다. 개인 훈련과 교수자 리그, AI 채점의 실행 기능은 시스템 쪽 후속 구현 범위입니다.

## 콘텐츠 변경

```bash
python3 -B contents/scripts/content-module.py validate
python3 -B contents/scripts/content-module.py sync-preview
python3 -B contents/scripts/content-module.py manifest
```

YAML 검증에는 PyYAML이 필요합니다(`requirements.txt`). 수정한 뒤 `python3 scripts/verify-contents.py`로 매니페스트 일치를 확인하고 Core 변경과 함께 커밋합니다. Live Fire Range Control이 쓰는 시나리오를 바꿨다면 그쪽 콘텐츠 잠금도 갱신합니다.

[공방전 작성 규칙](battle-scenarios/README.md)을 따릅니다. 교재·해설·실환경 결과의 정합성 검증은 아직 후속 작업입니다. 공개 범위 밖 PPT 원본·발표자 노트·340페이지 이후 자료는 포함하지 않습니다. 교관용 정답은 Core와 함께 공개되는 자료이며, Core의 학습자 API는 정답과 채점 기준을 응답하지 않습니다.
