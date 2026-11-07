# 빈 Ubuntu VM 자동 설치

상태: 실제 VM 자동 설치·통신 검증 통과. 재실행·재부팅을 포함한 상세 결과는 [VM 검증 기록](VM-VALIDATION-2026-11-07.md)을 따른다. 현재 실행 대상은 Ubuntu Server 26.04 LTS amd64 전용 VM이다.

## 사용자 진입점

저장소 또는 별도로 받은 설치 스크립트에서 실행한다. Docker, git, Python venv를 미리 설치할 필요가 없다. 설치 스크립트만 받은 경우 공개 저장소의 main을 다운로드하며 실제 사용한 소스를 해시로 고정한다.

```bash
sudo bash install.sh
```

현재는 개발 버전이라 위 실행이 experimental security-path를 선택한다. platform·fw·IPS·WAF와 무해한 검증용 client/backend를 설치한다. SIEM·콘솔·포털 등 계획 단계 기능은 포함하지 않으며, 전체 Community 완성본으로 성공을 표시하지 않는다.

현재 프로필의 실행 전 검사는 2 vCPU, RAM 약 4GB, 데이터 경로 여유 20GB 이상이다. 이는 전체 Core 최소 사양을 실측한 값이 아니다. 전체 개발을 위한 권장 예산은 8 vCPU·32GB RAM·OS 80GB + 데이터 300GB다.

## 자동 수행

1. Ubuntu 버전·아키텍처·전용 VM·자원·중복 설치 실행을 검사한다.
2. 타 프로젝트 컨테이너, 기존 비관리 Docker·containerd 데이터나 충돌 패키지가 있으면 삭제하지 않고 중단한다.
3. 기본 패키지, 해시로 식별한 소스 사본, 격리한 Python 실행 환경을 준비한다.
4. 선택 모듈의 manifest·의존성·권한·주소 정책을 검증한다. 미구현·상용 모듈은 기존 plan 정책에 따라 중단한다.
5. Docker 공식 apt 저장소와 Docker Engine·containerd·Compose·Buildx를 설치한다. 전체 OS 업그레이드는 하지 않는다.
6. Docker와 containerd의 데이터 경로를 함께 설정한다. 원래 설정은 별도로 보존한다.
7. br_netfilter·nfnetlink_queue를 로드하고 원래 bridge sysctl 값을 보존한 뒤 필요한 값을 적용한다. 호스트 방화벽 체인을 초기화하지 않는다.
8. 이미지를 빌드하고 검증 계획으로 기동한다.
9. 실제 통신·차단·우회 방지·출처 보존·C1 증거·IPS 중단/복구와 platform health를 확인한다.
10. systemd 서비스를 등록하고 시작한다. 이 경로에서도 수용 검증이 통과해야 완료 상태를 쓴다.

패키지 설치·이미지 빌드·검증 중 하나라도 실패하면 비정상 종료한다. 상태 파일에는 실패 단계와 로그 위치를 기록한다. 조사할 수 있도록 해당 프로젝트의 컨테이너·로그를 보존한다.

## 선택 옵션

```bash
# 호스트를 바꾸지 않고 작업 순서 확인
bash install.sh --dry-run

# 이미 마운트된 전용 데이터 공간 사용
sudo bash install.sh --data-dir /srv/xoc-data

# 설치 가능한 모듈 선택/제외. ID는 catalog에 등록된 것만 허용한다.
sudo bash install.sh --include <module-id> --without <optional-module-id>

# 별도로 받은 스크립트에서 특정 소스 커밋 설치
sudo bash install.sh --ref <40-character-commit-sha>
```

기본 데이터 경로는 `/var/lib/xocrange/data`다. Docker 데이터는 `docker/`, containerd 이미지·스냅샷은 `containerd/` 아래에 저장한다. 별도 디스크는 장치 확인 후 마운트된 경로를 선택하며, 이 버전의 설치기는 디스크를 포맷하지 않는다. `--data-dir` 변경으로 이미 설치한 데이터를 자동 이관하지 않는다.

`--without`으로 platform·security-path·검증용 probe를 제거하면 현재 프로필의 설치 완료 검사를 만족할 수 없어 거부한다. 다른 모듈은 준비된 상태와 의존성에 따라 선택한다.

## 설치 위치와 재실행

| 위치 | 내용 |
|---|---|
| `/opt/xocrange/releases/<source-hash>` | 비공개 로컬 상태를 제외한 소스 사본, 계획·수용 검증 결과 |
| `/opt/xocrange/venvs/<source-hash>` | 해당 소스의 Python 실행 환경 |
| `/opt/xocrange/current` | 마지막으로 설치에 성공한 소스 |
| `/var/lib/xocrange/last-install.json` | 마지막 실행 성공/실패, 로그·검증 증거 위치 |
| `/var/lib/xocrange/original-config/` | 설치 전 런타임 설정 |
| `/var/lib/xocrange/original-bridge-nf` | 설치 전 bridge sysctl 값 |
| `/var/log/xocrange/install-*.log` | 설치 실행 로그 |
| `/etc/systemd/system/xocrange-core.service` | 부팅 기동 및 검증 서비스 |

같은 소스로 다시 실행하면 소스 해시와 계획을 재사용하되 현재 파일이 변조됐으면 중단한다. 누락 패키지와 실행 단계를 다시 확인한다. 자동 전체 OS/Docker 버전 업그레이드, 디스크 초기화, Docker prune을 수행하지 않는다. 설치 도중 중단된 런타임은 이 설치기가 관리하던 VM에서만 재개한다.

새 소스로 실행하면 새 소스 사본·venv·계획을 만든다. 검증 실패 시 마지막 성공 소스 링크는 유지하지만 실행 중인 컨테이너와 호스트 설정을 자동 rollback하지는 않는다. 운영 업그레이드 지원을 주장하지 않는다.

## 상태 확인

```bash
sudo cat /var/lib/xocrange/last-install.json
sudo systemctl status xocrange-core.service
sudo journalctl -u xocrange-core.service --no-pager
sudo xoc catalog
```

현재 외부 사용자 포털과 게시된 호스트 포트는 없다. platform health는 컨테이너 내부의 `127.0.0.1:8080/healthz`에서 확인하고, 실습 경로는 내부 probe로 검증한다. 서비스 등록 성공은 실제 재부팅 검증과 구분하며 결과의 `reboot_verified`는 별도 검증 전까지 false다.

부팅 시 검증된 계획·로컬 이미지로 `lab start`를 실행하고 `lab verify`까지 통과해야 서비스 성공으로 표시한다. `lab start`는 `--no-build --pull never`를 사용한다. 종료는 해당 프로젝트의 `lab down`만 호출한다.

## 근거

- [Docker Ubuntu 설치](https://docs.docker.com/engine/install/ubuntu/): 공식 apt 저장소·패키지 구성.
- [Docker daemon 저장 위치](https://docs.docker.com/engine/daemon/): Docker data-root만 바꿔서는 containerd 이미지 저장 위치가 바뀌지 않는다.
- [ADR 0004](../adr/0004-single-command-installation.md): 설치 책임과 성공 조건.
