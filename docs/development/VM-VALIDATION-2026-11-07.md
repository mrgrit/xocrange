# Ubuntu 26.04 VM 설치·보안 경로 검증

기준일: 2026-11-07. 초기 Linux만 설치된 전용 VM에서 설치기를 실행했고, 실제 환경에서 발견한 오류를 수정한 뒤 전체 설치와 수용 검사를 통과했다.

## 환경

- Ubuntu Server 26.04.1 LTS amd64, Linux 7.0.0-43-generic, VMware.
- 8 vCPU, RAM 16GB, 가상 디스크 300GB, root ext4/LVM 약 280GB.
- Python 3.14, Docker Engine 29.9.3, Compose 5.7.0, containerd 2.4.2.
- 기존 kt66와 분리한 전용 VM. 관리 접속은 중계 SSH 연결을 사용하며 공개 검증 기록에 관리용 주소·자격증명을 포함하지 않는다.

## 확인 결과

- Docker·Python 및 필요한 패키지의 자동 설치, Docker/containerd 데이터 경로 구성, 커널 모듈·브리지 전제 조건 준비 완료.
- platform·fw·IPS·WAF·검증 client/backend 6개 이미지 빌드와 기동 완료.
- 실제 수용 검사 15개 통과: platform health, 기본 화면·선택 타깃, 출처 IP와 위조 헤더 처리, fw/IPS 경유, 타 포트 차단, WAF/backend 우회 차단, WAF/IPS 표식 차단과 C1 증거, IPS 장애 차단·복구.
- 로컬 Python 3.10과 VM Python 3.14에서 테스트 122개 통과.
- 동일 소스로 설치기를 다시 실행해 종료 코드 0 확인. 소스·계획을 재사용했고 Docker/containerd 설정과 원래 설정 백업의 해시가 유지됐다.
- 사용자 요청으로 호스트명을 `xor`에서 `xoc`로 수정했다. `/etc/hosts`를 함께 맞추고 cloud-init이 새 호스트명을 유지하도록 설정했다.
- 실제 재부팅 후 호스트명 `xoc`, 서비스 6개 실행, systemd 자동 기동 성공을 확인했다. 부팅 이후 새로 생성된 증거로 수용 검사 15개가 다시 통과했음을 확인했다.
- VM의 `/var/lib/xocrange/last-install.json`에 실제 재부팅 검증을 기록했다. 게시된 호스트 포트는 없으며, 외부 포털은 후속 범위다.

버전·소스 해시·계획 ID·컨테이너 권한·부팅 후 검사 결과는 [검증 요약 JSON](../provenance/vm-acceptance-2026-11-07.json)에 보관한다. 원본 C1 증거와 설치 로그는 VM 및 로컬 비공개 작업 영역에 남긴다.

부팅 검증 후 유휴 상태의 6개 컨테이너 메모리 합계는 Docker 표시 기준 약 185MiB였다. OS·Docker daemon·페이지 캐시를 포함한 VM 전체 사용량이나 전체 Core 최소 사양이 아니며, 현재 IPS에는 검증용 룰만 설치되어 있다.

## 실제 환경에서 수정한 사항

1. Docker 기본 host/none 네트워크의 `IPAM.Config=null`을 빈 주소 목록으로 처리한다.
2. capability를 제한한 WAF 컨테이너에서 uid 0도 www-data 감사 로그를 읽을 수 없었다. 검증기는 로그 소유자인 uid/gid 33으로 읽으며 권한이나 파일 공개 범위를 넓히지 않는다.
3. Docker 내부망에만 연결한 platform의 호스트 포트는 게시되지 않았다. 불필요한 포트 선언을 제거하고 컨테이너 내부 health 검사를 수용 검사에 통합했다. 같은 종류의 무효한 계획은 `internal_port_publish`로 거부한다. [Moby 유지보수자 설명](https://github.com/moby/moby/discussions/53256)

## 완료 범위

이 결과는 experimental security-path의 설치·보안 경로에 대한 검증이다. 전체 Community, SIEM 영구 수집, 일반 공격 룰셋, 외부 포털·TLS, 동시 사용자 부하, 이미지·패키지 버전 고정은 별도 단계다. 최종 수정본을 다시 초기화된 OS에서 무수정 첫 실행한 시험은 아직 수행하지 않았다.
