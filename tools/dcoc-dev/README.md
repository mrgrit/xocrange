# DCOC 화면 로컬 개발 서버

**설치 대상이 아니다.** `components/` 밖에 있으므로 어떤 구성요소의 빌드 입력에도 들어가지 않고, 설치·업데이트(`xoc update`)와 무관하다. DCOC 설비 운영 화면과 데이터센터 관제 지도를 설치 없이 다듬기 위한 도구다.

## 무엇을 하는가

- Core의 `page.html`과 정적 파일을 실제 경로(`/core/`, `/core/assets/<이름>`)로 내보낸다. 자산 이름은 `views.py`의 허용 목록을 요청마다 읽어 검사하므로, 새 파일을 목록에 넣지 않으면 여기서도 404가 난다.
- `/core/api/facility`, `/core/api/facility/requests`, `/core/api/datacenter[/floors/<층>]`는 Core의 `facility.py`·`datacenter.py`를 그대로 불러 실행한다. Django 대신 작은 대역(권한 표·라이선스·레지스트리)을 끼운다.
- 시설 상태는 같은 프로세스 안에서 실제로 도는 M4 시뮬레이터(`xocrange_livefire/modules/m4-facility`의 `Service`)가 만든다. 훈련 시작, 운영 조치, 장애 넣기, 배속 변경이 실제로 반영된다. 시뮬레이터 코드는 읽기만 한다.
- 세션·레지스트리는 레포의 구성요소 선언(`component.yaml`, `module.yaml`)과 권한 표로 만든 최소 고정값이다. 테스트 서버에 요청을 보내지 않는다.

## 실행

```powershell
python tools/dcoc-dev/server.py --port 8765 --state tools/dcoc-dev/.run   # 상태 폴더를 생략하면 임시 폴더
```

- 화면: <http://127.0.0.1:8765/core/#module/m4-facility> (DCOC), <http://127.0.0.1:8765/core/#datacenter> (관제 지도)
- 권한 운영 방식: 학생 계정은 운영자(operator), 강사는 관리자(admin) 역할로 만든다. 강사 도구(장애 넣기·되돌리기)는 관리자에게만 보이고 서버도 관리자 요청만 받는다(`facility.instruct`).
- 조작: <http://127.0.0.1:8765/dev> — 권한(관리자·운영자·조회자), 라이선스(유효·만료·없음), 강사 반 전체 장애(원인 숨김/공개) 흉내
- 필요: Python 3.12, `pyyaml`. 시뮬레이터 레포 위치가 다르면 `--livefire <경로>`.

## 화면 확인

```powershell
python tools/dcoc-dev/shoot.py <이름> <해시> [--size 1366x768] [--full] [--js "<식>"]   # 한 장 찍기
python tools/dcoc-dev/walkthrough.py [--size 1366x768]                                 # 한 흐름 점검 + 단계별 스크린샷
```

`walkthrough.py`는 관제 지도 → DCOC → 훈련 갤러리·브리핑·시작 → 경보 → 설비 클릭 → 조치 → 진행 막대 → 기록·SIEM 버튼 → 강사 도구 → 강사 숨김 장애 → 조회자 권한을 실제로 누르고 PASS/FAIL을 남긴다. 결과 그림은 `shots/`(git 제외)에 쌓인다.

`capture.py`는 테스트 서버 Core의 GET 응답을 저장된 브라우저 세션으로 한 번 받아 두는 도구다(POST 없음, 결과는 `captured/`, git 제외). 지금 서버는 레포 코드로 만든 고정값을 쓰므로 필수는 아니다.
