# 설치 계획기 v0.1

현재 CLI는 로컬 패키지 검증과 Compose 생성까지 담당한다. 다운로드·설치·Docker 실행·제거·업데이트를 수행하지 않는다.

## 명령

```bash
xoc catalog
xoc doctor --preset bootstrap
xoc plan --preset bootstrap
xoc plan --include fixture-echo --allow-fixtures
xoc plan --output my-first-plan
```

`--include ID`, `--without ID`는 반복 지정할 수 있다. `--without`은 프리셋에서 선택 기능을 제거하지만 다른 선택 기능이 요구하면 실패한다. 필수 `platform`은 제거할 수 없다. `--include`와 `--without`에 같은 ID를 주면 실패한다. 모든 명령의 `--root`는 하위 명령 앞에 지정한다.

기본 `plan`은 JSON을 stdout에 출력하고 파일을 쓰지 않는다. `--output my-first-plan`은 `.local/plans/my-first-plan/compose.yaml`과 `plan.lock.json`을 만든다. 기존 디렉토리는 덮어쓰지 않는다. 오류는 stderr의 JSON, 종료 코드 2로 반환한다.

## 디렉토리와 manifest

| 위치 | 역할 |
|---|---|
| `components/<id>/component.yaml` | Core 필수/선택 구성요소, `kind: component` |
| `modules.d/<id>/module.yaml` | 별도 검토한 확장, `kind: module` |
| `tests/fixtures/modules/<id>/module.yaml` | 테스트 전용, `kind: fixture`; 명시적 허용 필요 |
| `presets/<name>.yaml` | 선택할 구성요소 목록 |
| `.local/plans/` | 생성 산출물, Git 제외 |

[platform 예제](../../components/platform/component.yaml)와 [manifest 스키마](../../src/xocrange/contracts/manifest.json)가 기준이다. schema version, ID, 버전, Core 범위, 준비 상태, 티어, 의존성·capability·충돌, 네트워크, 설정 키, C1 버전, Compose 경로, build 입력을 선언한다.

Core 버전 범위는 `>=0.1.0 <0.2.0` 같은 공백으로 구분한 비교식이며 prerelease·caret·OR 문법은 지원하지 않는다. `requires.components`는 자동 포함하고 위상 정렬한다. `requires.capabilities`는 선택 집합 안에서 충족되어야 하며 제공자를 임의 선택하지 않는다.

`planned` 구성요소는 카탈로그에만 표시한다. 실행 계획을 생성하려면 `ready`이고 유효한 Compose fragment가 있어야 한다. `ready`는 이 단계에서 조합 가능한 상태를 의미하며 릴리스 검증 완료 표시가 아니다. M1~M19, 상용 또는 상위 티어 선언은 C7 구현 전까지 거부한다.

## 조합 검사

중복 ID, 누락·순환 의존성, capability 부재, Core/C1 버전 불일치, 구성요소 간 충돌, 서비스명·전역 설정 키·호스트 포트 중복을 검사한다. wildcard 포트 바인딩도 보수적으로 충돌로 처리한다. 호스트에서 이미 사용 중인 포트는 아직 확인하지 않는다.

Compose는 [제한된 bootstrap 문법](../../src/xocrange/contracts/compose-fragment.json)만 받는다. non-root·read-only·capability 제거를 요구하며 host network, privileged, volume, env_file, `$` interpolation 등은 아직 허용하지 않는다. 이것은 Docker Compose 전체 문법의 대체물이 아니다. 향후 fw/netglue가 필요로 하는 권한은 K05에서 명시적인 네트워크 모델·테스트와 함께 확장한다.

경로는 패키지 내부로 제한하고 외부 symlink를 거부한다. build context 내부의 모든 파일은 manifest·Compose 또는 `build_inputs`로 기록되어야 한다. build context에는 symlink를 허용하지 않는다. manifest 검증은 임의 Dockerfile/이미지 실행의 안전성을 보증하지 않으므로 검토한 패키지에만 사용한다.

## 계획 파일의 의미

lock에는 Core 버전, 선택·제외·fixture 허용 여부, 사용한 입력 파일 SHA-256, Compose 해시, plan ID가 들어간다. Compose 해시를 계산할 때 build context를 저장소 상대 경로로 바꾸므로 같은 소스를 다른 디렉토리에 옮겨도 lock은 같다. 실제 생성한 Compose에는 실행을 위한 절대 build context를 쓴다. 생성 후 체크아웃을 옮기면 계획을 다시 만든다.

이미지 digest, Python 의존성, 호스트 자원, 실제 build 결과는 고정하지 않는다. 현재 lock은 입력 추적 자료이며 재현 가능한 릴리스나 서명 검증 자료가 아니다. apply 시 입력 재검증과 이미지 digest 고정은 후속 작업이다.

## bootstrap과 doctor

platform은 stdlib HTTP 서버의 `/healthz`만 제공한다. Compose의 host 포트는 `127.0.0.1:18080`, 내부 포트는 8080이다. 응답에는 `status=bootstrap`, `ready_for_training=false`가 들어간다. 인증·registry·감사·훈련 UI는 아직 없다.

`doctor`는 계획 검증 결과와 Docker CLI 파일 존재 여부를 반환한다. Docker daemon·Compose 플러그인 버전·포트 점유·자원·실제 통신은 `not-checked` 또는 후속 범위다. `configuration-valid`를 설치 가능 판정으로 사용하지 않는다.

## 참고

- [Docker Compose services 공식 문서](https://docs.docker.com/reference/compose-file/services/)
- [PyYAML 문서](https://pyyaml.org/wiki/PyYAMLDocumentation)

YAML은 SafeLoader 기반이며 중복 키·별칭·임의 객체 태그를 거부한다. 실제 Docker 문법 검증은 생성 파일에 대한 `docker compose … config --quiet`로 별도 수행한다.
