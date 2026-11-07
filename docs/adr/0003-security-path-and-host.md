# ADR-0003: 새 Core 검증 호스트와 보안 경로 분리

상태: 2026-11-07 사용자 결정과 진행 중인 구현 기준.

## 호스트 기준

새 Core 검증 VM은 Ubuntu Server 26.04 LTS x86_64를 사용한다. 기존 kt66의 Ubuntu 22.04 환경은 비교·복구 기준으로 유지한다. 26.04는 사용자가 선택한 검증 대상이며, 아직 Core 통합 테스트로 지원을 인증한 상태는 아니다.

호스트 OS와 컨테이너 이미지의 배포판·패키지 버전은 별도 항목으로 기록한다. 버전 변경 후 nftables, Suricata NFQUEUE, Docker 브리지, WAF 응답 경로와 출처 IP 보존을 검증한다. Docker가 공식 지원하는 호스트 버전이라는 사실만으로 이 보안 경로의 동작을 보증하지 않는다.

## 현재 확인한 기존 의존성

- web은 IPS와 7개 타깃에 필수 의존한다. 상용 타깃을 제거하려면 vhost·포트·랜딩 링크까지 선택 구성으로 바꿔야 한다.
- fw/ips/web 이미지와 entrypoint에 SSH, Wazuh agent, osquery, 장비 콘솔, 평가 수집 설정이 결합되어 있다.
- 기존 Suricata 실행은 `-i` 기반 수집이다. Core의 실제 IPS 차단 검증에는 별도의 inline 경로가 필요하다.
- netglue는 host network·privileged 컨테이너에서 호스트 sysctl을 바꾸고 DOCKER-USER 체인을 초기화한다. 기존 kt66 호스트에서 이 동작을 실행하지 않는다.

전체 33서비스의 선언과 Dockerfile 입력은 [의존성 목록](../provenance/security-path-inventory-2026-11-07.json)에 기록했다. 보안 경로 관련 30개 파일은 `.local/provenance/2026-11-07-security-path/`에 비공개로 보존했다. 이 목록은 출처 분석이며 기존 소스 전체를 Core로 복사했다는 의미가 아니다.

## 분리 구현 방향

Core의 fw·IPS·WAF를 독립된 프로세스 단위로 구성한다. SSH·콘솔·SIEM agent·평가 코드는 해당 선택 기능을 구현할 때 연결한다. 선택된 타깃만 WAF 설정에 등록하고, 타깃이 없어도 보안 경로의 기본 화면은 구성할 수 있게 한다.

첫 실행 구성은 격리된 VM에서 검증할 실험 단계로 표시한다. 호스트 네트워크 변경은 진단·적용·복구 범위를 명시해야 하며, 다른 스택의 방화벽 규칙을 초기화하는 코드를 이식하지 않는다. 실제 통신·차단·출처 보존 검증 전에는 훈련 가능한 Core 완료로 표시하지 않는다.

## 근거

- [Ubuntu Server 다운로드](https://ubuntu.com/download/server)
- [Ubuntu 지원 기간](https://ubuntu.com/about/release-cycle)
- [Docker Ubuntu 지원](https://docs.docker.com/engine/install/ubuntu/)
- [Suricata inline 구성](https://docs.suricata.io/en/suricata-7.0.15/setting-up-ipsinline-for-linux.html)
