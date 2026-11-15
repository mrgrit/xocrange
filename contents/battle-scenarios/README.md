# xOC Range Live Fire 콘텐츠

기존 1–339쪽의 36개 차시를 **2개 과목, 15개 시나리오, 105개 미션**으로 재구성했다. 시나리오마다 Red 2개, Blue 3개, Purple 2개이며 모든 미션에 학습자 시도·시스템 반응·학습자의 해석 세 항목을 작성한다. 교재 읽기와 기록 연습은 6F 아카데미, 역할별 공방전은 Live Fire에 연결한다.

| 과목 | ID | 시나리오 | 연결 차시 |
|---|---|---|---|
| 웹 침해 대응 | xoc-web-01 | 탐색 요청에서 공격 출발점 찾기 | 시작하기 4개·웹 기초·04·05 |
| 웹 침해 대응 | xoc-web-02 | SQL 인젝션과 200 응답의 함정 | 01·11 |
| 웹 침해 대응 | xoc-web-03 | XSS 입력과 브라우저 실행 구분 | 02 |
| 웹 침해 대응 | xoc-web-04 | 파일 경로 탐색과 LFI 차단 | 03 |
| 웹 침해 대응 | xoc-web-05 | 로그인 실패와 관리자 경로 노출 | 06·14 |
| 웹 침해 대응 | xoc-web-06 | 업로드 흔적과 OS 명령 실행 분석 | 07·10 |
| 웹 침해 대응 | xoc-web-07 | Log4Shell·Shellshock 탐지와 실행 증거 | 08·09 |
| 웹 침해 대응 | xoc-web-08 | 오류·HTTP 메서드·긴 URL 분류 | 12·13·15 |
| 리눅스·네트워크 침해 대응 | xoc-host-01 | SSH 실패와 존재하지 않는 계정 구분 | 리눅스 기초·16·17 |
| 리눅스·네트워크 침해 대응 | xoc-host-02 | 인증 실패 뒤 성공과 root 로그인 조사 | 18·19 |
| 리눅스·네트워크 침해 대응 | xoc-host-03 | sudo 사용과 계정 변경의 책임 추적 | 20·21 |
| 리눅스·네트워크 침해 대응 | xoc-host-04 | 계정 파일과 SSH 키 변경 추적 | 22·23 |
| 리눅스·네트워크 침해 대응 | xoc-host-05 | 예약 작업과 다운로드 실행 연결 | 24·26 |
| 리눅스·네트워크 침해 대응 | xoc-host-06 | 바이너리 무결성과 로그 변경의 증거 보존 | 27·28 |
| 리눅스·네트워크 침해 대응 | xoc-host-07 | 네트워크 도구·수신 포트·방화벽 대응 | 25·29·30 |

## 파일과 작성 규칙

`xoc-*.yaml`이 편집 정본이다. 각 파일에 초보자용 상황 설명, 어디에서 무엇을 실행할지 순서, 세 항목의 미션 기록, 힌트, 정답·해설·동등 답안·배점·부분점수·오답 사례가 들어 있다. 전체 36개 차시는 한 시나리오에 한 번씩 주 연결되며 원본 페이지는 339쪽을 넘지 않는다.

- `red_missions`: 공격/관측 재현 2개, 20+15점.
- `blue_missions`: 검색식 1개, 증거 한 줄, 대응안 1개가 각각 15점. 이어 Purple 판정·인계 보고가 각각 10점.
- `submission`: `fields: 3`, `type: report`. `sections`는 `input`, `output`, `interpretation` 순서이며 각 항목은 필수다. 자동 임시 저장은 일부 입력도 허용한다. 등록할 때 세 항목을 검증하며 시스템 반응은 텍스트 또는 첨부 증거로 남긴다.
- `reference_answer`: 답안과 상세 해설, 동등한 표현, 흔한 오해.
- `rubric`: 기준별 만점·부분점수·0점 조건. 합계는 미션 배점과 동일하다.
- `evaluation_cases`: 만점·오답·빈 답·부분 답의 평가 사례. 실제 AI 평가 결과를 뜻하지 않는다.
- `verify.semantic`: tw2가 읽는 `intent`, `success_criteria`, `acceptable_methods`, `negative_signs`를 사용한다. 채점자 기준 답안과 세부 배점은 `acceptable_methods`에 함께 넣어 기존 엔진으로 실제 전달되게 한다.

미션별 답은 의미와 실제 증거를 비교하여 평가한다. 단순 키워드 일치, 강의의 예시 출력 복사, 다른 배틀의 흔적, 확인하지 않은 침해 성공 주장을 만점으로 처리하지 않는다. 정상적으로 차단된 공격을 공격 미수행과 혼동하지 않는다.

## tw2 호환

참고 정본: [tw2 contents/battle-scenarios](https://github.com/mrgrit/tw2/tree/324d91fb22fee2c76051d5e73b58aa7f82de3e4c/contents/battle-scenarios).

현재 tw2는 실행 side가 `red`/`blue`다. **Purple 미션은 `blue_missions`의 4·5번에 저장**하고 `learning_role: purple` 및 제목으로 구분한다. 별도 `purple_missions` 키를 만들면 기존 로더가 누락시키므로 사용하지 않는다. 기존 엔진 점수 표에서는 Red 35 / Blue 65이며, 학습 화면에서는 Blue 45 / Purple 20으로 나눠 보여 준다. 새 참가자 역할이나 엔진 코드는 이 저장소에서 추가하지 않는다.

`TUBEWAR_AUTO_SCORE=0`을 유지한다. 참고 엔진도 이것이 기본값이다. `verify.checks`의 경보는 채점에 참고할 문맥이며, 경보가 있다는 사실만으로 모든 Blue/Purple 미션에 점수를 주어서는 안 된다. 학생의 미션별 보고를 기존 `/battles/{id}/events` 의미 평가 경로에 전달한다. `input`은 `what_i_did`, `output`은 `what_happened`, `interpretation`은 `description`에 매핑한다. 원문을 잘라 보내지 않는다. 엔진의 길이 제한과 캡처 증거 전달은 정식 연결 시 어댑터에서 검증한다. 미션별 기준 답안·루브릭·합성 회귀 사례도 세 항목으로 구성한다. 합성 사건 자료는 실측 출력이 아니며 정답·루브릭과 함께 학습자용 JSON에서 제외한다.

지원 치환 변수는 tw2의 `{{TARGET_IP}}`, `{{WEB_ENTRY}}`, `{{ATTACKER_IP}}`뿐이다. `$XOC_TAG`는 학생이 터미널에서 설정하는 실습 태그이며 엔진 치환 변수가 아니다. 등록된 대상 VM과 외부 공격자 VM을 구별한다. `TARGET_IP`는 관리/Assessor 호스트 주소다. Linux SSH·포트 관측에는 교관이 별도로 지정한 `XOC_LINUX_IP`를 사용하며 미설정 시 셸이 실행을 거부한다. Red 증거 확인은 모든 시나리오에서 `opponent`, Blue/Purple은 `self` 인프라를 따른다. solo에서는 같은 인프라로 연결된다. 실습 web 셸 작업은 실습 인프라의 web VM/컨테이너에서 수행하며 xOC 관리 호스트를 대상으로 하지 않는다.

## 교관 준비와 현재 검증 범위

각 YAML의 `instructor_setup`에 계정·권한·가상 호스트·스냅샷·수집 조건이 있다. Core 통신 검증용 타깃은 DVWA, 인증 앱, 업로드 앱을 대신하지 않는다. `training.xoc.test/fixtures/hello-xoc.sh`는 교관이 `printf`만 수행하는 파일로 준비하고 해시를 제공해야 한다. cron·바이너리·로그 변경은 주석/사본으로 관측을 익히도록 작성했으며, 해당 조작만으로 악성 지속성이나 운영 원본 변조가 성공했다고 채점하지 않는다.

이번 검증은 콘텐츠 구조와 참조 엔진 계약이다. 각 공격의 실환경 재현, Assessor 연결, 실제 AI 모델의 채점 결과와 점수 보정은 Live Fire 인프라 통합 때 검증한다. `review_status: authored-awaiting-live-validation`은 이 상태를 표시한다. 콘텐츠를 수정했다고 자동으로 실습 검증 완료로 바꾸지 않는다.

## 편집 후 검증

```bash
python3 scripts/content-module.py sync-preview
python3 scripts/content-module.py validate
python3 scripts/content-module.py manifest
```

첫 명령은 검증 후 학습자용 `academy/wazuh-threat-hunting/scenarios.json`을 만든다. 정답·루브릭·채점자 메모·평가 사례는 학습자 카탈로그에서 제외한다. 이 파일은 직접 편집하지 않는다. 전체 YAML은 교관·개발용 Git 자료이며 시험 정답의 비밀 저장소로 취급하지 않는다.
