# Core CI 활성화 대기

[core-checks.yml](core-checks.yml)은 Python 3.10/3.12 테스트·Compose 설정 검사·wheel 빌드용 GitHub Actions 템플릿이다. 현재 위치에서는 자동 실행되지 않는다.

첫 소스 게시 때 사용한 PAT에는 `workflow` scope가 없어 GitHub가 `.github/workflows/core-checks.yml`의 최초 업로드를 거부했다. 코드와 로고·문서는 게시하고, CI 설정은 검토 가능한 이 디렉토리에 보관한다.

workflow 쓰기 권한이 있는 인증을 사용해 이 파일을 `.github/workflows/core-checks.yml`로 복사하여 커밋·푸시하면 활성화된다. 토큰을 저장소 파일에 기록하지 않는다. 활성화 후 Python 3.10/3.12 두 작업의 결과를 확인해야 한다.
