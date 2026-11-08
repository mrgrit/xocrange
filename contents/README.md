# 콘텐츠 패키지

`tw2/contents`의 강좌 단위 파일 구성을 이어받아, 설명·실습·이미지와 원본 매핑을 각각 관리한다. 실행 코드와 학습자가 제출한 내용은 여기에 넣지 않는다.

```text
contents/
  academy/
    wazuh-threat-hunting/
      course.json                  # 강좌·차시 목록, 버전, 공개 범위, 자산 해시
      source-map.json              # PPT 페이지 ↔ REV01 절 매핑
      lessons/
        case-01/
          lesson.json             # 페이지 순서와 교재 블록
          explanation.json        # 해당 차시 해설
          missions.json           # 미션 ID, 지시문, 근거 페이지
      assets/<sha256>.png          # 선언한 교재/해설 이미지
```

강좌 ID·차시 ID·미션 ID는 학습 기록의 연결 키다. 제목과 내용은 고쳐도 기존 ID를 다른 주제에 재사용하지 않는다. 실습 기록은 제출 당시 콘텐츠 버전과 제목을 함께 저장한다. 파일 구성 변경은 `course.json`의 버전을 올리고 원본 매핑을 함께 수정한다.

현재 번들은 **PPT 1–339페이지**, 36개 차시, 96개 기록 미션이다. 원본 PPTX·발표자 노트·340페이지 이후 자료와 연결되지 않은 원고는 배포하지 않는다. 관련 REV01 절만 가져왔으며, 교재와 해설의 정합성·명령·환경·검색 결과 대조는 후속 작업이다. 제품명은 xOC Range로 정리했다. 캡처 안의 원래 제품명과 실행 결과는 원본 이미지에 남아 있다.

추출 재실행은 새 출력 디렉터리에서 수행한다. 입력 원본은 저장소 밖 또는 무시되는 `.local/`에 둔다.

```bash
python3 scripts/import-academy-bundle.py \
  --pptx /private/source.pptx \
  --manuscript /private/book/manuscript/REV01 \
  --output /private/review-bundle
```

설치 계획 작성 시 선언 파일·해시·페이지 경계·자산 크기·경로를 검사한다. `academy-reader`를 선택했을 때만 읽기 전용 콘텐츠 볼륨으로 복사한다. Core는 명시적으로 무료인 번들만 제공한다. 기관 구매 콘텐츠와 공방전, Live Fire AI 채점·분석·피드백은 C7 상용 제공자에서 연결할 후속 범위다.

화면·기록 API·DB·제한·검증: [아카데미 구현](../docs/development/ACADEMY.md).
