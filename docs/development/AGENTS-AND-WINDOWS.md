# 에이전트와 Windows 번들 경계

Core는 관리자 CLI의 `xoc agents list`와 `xoc agents enroll --name NAME --output PRIVATE_PATH`로 Wazuh 에이전트 등록·상태 조회를 제공한다. 실행할 설치 계획은 `--plan`으로 지정한다. 키는 root 소유 0700 디렉터리의 0600 파일에만 기록하며 출력·로그에 표시하지 않는다. 같은 이름의 재등록은 기존 ID와 키를 유지하고, 다른 키가 들어 있는 파일을 덮어쓰지 않는다.

Manager의 authd는 내부 API 등록 처리를 위해 실행한다. `remote_enrollment=no`로 네트워크 자동 등록을 끄고, 호스트에는 1514·1515·55000을 공개하지 않는다. 현재 수용 검증은 xoc VM 내부의 격리된 Ubuntu 26.04 에이전트 컨테이너와 Wazuh secure TCP 1514 통신을 대상으로 한다. 별도 물리 호스트나 Windows 실통신 검증은 포함하지 않는다. 외부 연결을 제공하는 모듈에는 허용 출발지·키 전달·폐기 정책이 추가로 필요하다.

`tests/integration/agent_transport.py`는 등록, 실제 SSH 로그의 원본 규칙 5710 탐지, 네트워크 단절 동안의 보관과 재연결 전송, 프로세스 재시작 후 동일 ID 유지, 호스트 포트 미게시와 테스트 계정·키 제거를 검사한다. 컨테이너에는 Docker socket·host PID·privileged 권한을 부여하지 않는다.

## kt66의 Windows 방식

원본 `endpoints/windows/setup.py`, `download.py`, `entrypoint.sh`, `oem/`를 읽어 확인했다. `dockurr/windows` 컨테이너가 `/dev/kvm`과 QEMU로 Windows 가상머신을 실행한다. Windows 프로그램을 Linux 컨테이너 프로세스로 직접 실행하는 구조는 아니다. 기존 기본 자원은 CPU 2개·RAM 4 GiB·디스크 64 GiB다. Microsoft 공식 평가판 ISO를 준비하고 OEM 스크립트로 게스트를 설정한다.

현재 xoc VM에서는 `/dev/kvm` 열기, KVM API 버전 12, 빈 VM 생성·해제 호출까지 성공했다. ISO 다운로드·Windows 설치·게스트 부팅·Windows 에이전트 탐지는 아직 실행하지 않았다. 상위 하이퍼바이저가 중첩 가상화를 허용해야 이 방식을 사용할 수 있다.

정본 [CORE-KICKOFF](https://github.com/mrgrit/xocrange_plan/blob/f548caa/docs/CORE-KICKOFF.md)는 Windows 번들을 후속 M6 범위로 둔다. K06/K07에서 Core 기본 설치에 Windows를 자동 추가하지 않는다. M6 착수 시 kt66의 방식을 재사용하되 공식 이미지 출처와 검증, 평가판 만료·권리 안내, KVM 검사, 격리망, 영속 디스크, unattended 설치와 에이전트 등록, 제거 시 디스크 보존 정책을 함께 구현한다. Windows를 선택했을 때 설치기가 필요한 QEMU/KVM·컨테이너 런타임을 준비하도록 설계한다.

에이전트 최초 등록 직후 중앙 설정 동기화가 logcollector를 재시작할 수 있다. 테스트 에이전트는 [Wazuh의 `only-future-events=no` 설정](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html#only-future-events)으로 중지 중 기록을 이어 읽도록 구성한다. 재시작 후 이전 이벤트가 중복 색인되지 않는지도 검사한다. 이 정책은 후속 실제 에이전트 패키지에도 포함할 요구사항이다.
