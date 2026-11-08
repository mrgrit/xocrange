# K09 운영 개요 · NOC 2층 · 자료실

Core 로그인 뒤 운영 개요에서 설치 서비스와 관리 화면을 확인한다. NOC는 Core의 **2F** 보안 운영실 하나를 제공한다. 두 개 층이나 전체 건물 시설 시뮬레이션을 뜻하지 않는다. 이전 콘솔의 스타일과 공통 인증을 사용하며, NAT·객체·IPS 목록은 사용자 피드백에 따라 커스텀 항목 관리 방식으로 유지한다.

## 선택 설치

`portal`, `noc`, `academy-reader`는 각각 `management`에 의존하는 선택 구성요소다. 단일 설치 프로그램에 기본 포함하며 `--without ID`로 개별 제외한다. 별도 서버·포트·계정은 추가하지 않는다. SIEM 또는 콘솔을 제외하면 해당 링크·자료와 요청도 제외한다. NOC·자료실 API는 해당 기능 제외 시 404를 반환한다. 공통 등록부 API는 management의 기능으로 유지한다. 자료실은 포털 없이도 사용 가능하다.

- 운영 개요: `/core/#portal` — 등록 서비스 검색, 구성요소·버전, 관리 화면 연결.
- NOC: `/core/#noc` — HTTPS → FW → IPS → WAF 논리 경로, 실습 타깃, 관리·분석 서비스, 장비 상세.
- 자료실: `/core/#academy` — Core 시작, 보안 경로, 정책 적용·복원, SIEM 조사 가이드. 설치 기능에 필요한 문서만 표시한다. 평가·진도·성적은 기록하지 않는다.
- 공통 인증: 기존 관리자·운영자·조회자 세션, 최초 비밀번호 변경, 세션 폐기와 CSRF 경계를 그대로 사용한다. SIEM은 별도 Wazuh 계정이며 새 탭으로 연다.

## C4 등록과 C5 자산

manifest의 선택적 `ui` 항목을 C4 0.1 계약으로 검증한다. ID·route 중복, 외부 URL, 다른 구성요소의 예약 route 점유를 설치 계획에서 거부한다. `permission`, `floor`, `order`, 제목·route와 소유 구성요소를 등록하며 API에서 역할에 맞게 필터링한다. Core는 2F와 일반 탐색 패널만 지원한다. 향후 모듈은 `/core/#module/<component-id>`의 기본 등록 정보 화면을 사용한다. 임의 HTML·JS 플러그인 실행은 허용하지 않는다. C7 상용 모듈 실행은 K10 범위다.

C5 0.1 자산은 검증된 Compose 서비스와 구성요소 소유권에서 만든다. 설치별 영구 UUID와 `component/service`로 안정된 asset ID를 생성한다. 재설치·선택 해제 후 재포함에도 ID를 유지하고, 다른 설치와는 구분된다. 현재 C1과 같은 `community/local` 범위를 사용하며 API의 tenant 입력은 받지 않는다. M13 discovery·전체 CMDB를 구현한 것은 아니다.

계획에는 등록 정보의 해시를 포함한다. 설치 때 `platform-config` 볼륨에 비밀값을 포함하지 않는 registry와 선택된 번들 자료를 생성한다. 웹 API는 계정 비밀번호·Docker 환경변수·마운트·컨테이너 로그를 노출하지 않는다.

## 관측 경계

호스트의 `xocrange-observer.timer`가 15초마다 고정된 프로젝트의 컨테이너 상태만 읽는다. 허용된 필드만 `platform-observation`에 원자적으로 기록한다. 관리 앱은 해당 볼륨을 **읽기 전용**으로 마운트하며 Docker 소켓·호스트 파일시스템에 접근하지 않는다. 상태는 로그인한 사용자만 조회한다.

실행 중은 **컨테이너 실행 상태**다. Docker healthcheck가 정의된 서비스에서 unhealthy/starting이면 점검 필요를 표시한다. 개별 엔진의 모든 기능, 보안 경로 통과, SIEM 수집 완전성을 대신하지 않는다. NOC 연결선은 구성된 경로이며 가짜 트래픽·온도·전력·활성 경보를 생성하지 않는다.

관측이 45초보다 오래되었거나 plan ID가 다르거나 파일을 읽을 수 없으면 전체 상태를 미확인으로 표시한다. 개별 서비스가 중지되면 중지됨, 컨테이너가 없으면 없음으로 표시한다. 페이지는 활성 상태에서 15초마다 갱신하고 입력 중에는 자동 갱신을 미룬다.

```sh
sudo systemctl status xocrange-observer.timer xocrange-observer.service
sudo systemctl start xocrange-observer.service
sudo journalctl -u xocrange-observer.service -n 30
```

기존 kt66 portal/NOC의 역할·표현 요구를 참고했으며 Docker 소켓, envsim, injector, AI 근무자와 동작 주입 API는 이식하지 않았다. [참고 출처](../provenance/k09-source.json). 기존 환경은 수정하지 않았다.

## 검증 범위

계약·인증·선택 설치·오래된 관측·자료 경로 검증은 `tests/test_registry.py`에 있다. 실환경에서는 브라우저, 중지/복구, observer 지연, 선택 해제/재포함을 추가 검증한다. 결과는 [K09 검증](K09-VALIDATION.md)에 기록한다. K05 실제 입문 타깃, K10 모듈 수명주기, K11 백업·복구·장기 부하 및 K12 RC는 별도다.
