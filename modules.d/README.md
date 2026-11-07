# 선택 모듈 디렉토리

신뢰하고 검토한 패키지를 `<module-id>/module.yaml`과 Compose fragment로 배치한다. 현재 CLI는 로컬 manifest만 읽으며 다운로드·설치·Docker 실행을 수행하지 않는다.

`kind: module`, `minimum_tier: community`인 비상용 패키지는 계약 검사를 통과하면 조합할 수 있다. M1~M19, `commercial: true`, Live Fire/Joint Force 선언은 C7 구현 전까지 거부한다. 이 검사는 소스가 수정 가능한 Community 코드에서 상용 라이선스를 강제하는 보안 경계가 아니다.

테스트용 `fixture-echo`는 이 디렉토리와 분리했고 `--allow-fixtures`를 명시한 경우만 검색한다. 실제 확장 설치기는 서명·배포 권리·업데이트·제거·C7 검증을 추가로 구현해야 한다. manifest 검증만으로 임의 Dockerfile이나 이미지가 신뢰되는 것은 아니다.
