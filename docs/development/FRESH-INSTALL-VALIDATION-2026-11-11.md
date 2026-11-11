# 신규 설치 경로 수정 — 2026-11-11

개발 VM은 설치본을 반복 갱신하며 검증했기 때문에, 새 VM에서 `sudo bash install.sh`를 처음 실행할 때만 나타나는 결함이 남아 있었다. 별도 Ubuntu 26.04.1 VM(8 vCPU·16 GB, Docker Engine 29.9.3)의 첫 설치는 `boot-service` 단계에서 중단됐고, 이후 SIEM 웹(`/siem/`)이 HTTP 500을 반환했다.

## 원인과 변경

| 증상 | 원인 | 변경 |
|---|---|---|
| `siem` 컨테이너 종료: `Uninitialized Manager volume is not empty: var` → Dashboard 기동 중단 → `/siem/` 500(`DNS lookup failure for: dashboard`) | Compose가 `siem-var` 볼륨 안에 `/var/ossec/var/run` tmpfs를 마운트하므로 Docker가 새 볼륨에 빈 `run/` 마운트 지점을 먼저 만든다. bootstrap은 이를 기존 상태로 판단했다. | `components/siem/bootstrap.py`가 마운트 지점은 제외하고 기존 상태를 판단한다. 마커 없는 볼륨에 실제 파일이 있으면 계속 덮어쓰지 않고 중단한다. 회귀 테스트 2개 추가. |
| `siem-telemetry`의 `apt-get update` 실패: osquery 저장소 서명 검증 불가 | `umask 077`로 받은 osquery 키가 0600이라 apt의 비권한 `gpgv`(`_apt`)가 읽지 못한다. Docker 키는 이미 0644로 설정하고 있었다. | `scripts/install-telemetry.sh`가 키·소스 목록을 0644로 설정한다. |
| 위 실패 후 재실행 시 첫 `base-packages`에서 같은 apt 오류 | 이전 실행이 남긴 읽을 수 없는 키가 모든 `apt-get update`를 실패시킨다. | `install.sh`가 첫 apt 실행 전에 `/etc/apt/keyrings/xocrange-*.asc`를 0644로 복구한다. |
| HTTPS 요청의 `/`·`/siem`·`/core` 리다이렉트가 `http://`로 내려갔다가 다시 308로 HTTPS 복귀 | TLS는 ingress에서 끝나는데 관리 vhost의 `ServerName`에 스킴이 없었다. | `ServerName https://core.xoc.test`. 호스트·포트는 계속 클라이언트 `Host`를 따른다. |
| 사용자 체크아웃의 `contents/`가 root 전용(0700)으로 남아 일반 사용자의 `fetch-contents.py --verify-only`·테스트·삭제가 실패 | 설치기가 root·`umask 077`로 체크아웃 안에 콘텐츠를 받는다. | 받은 뒤 체크아웃 소유자에게 소유권을 돌려준다. |

## 검증

- 실패한 첫 설치가 남긴 VM에서 수정본으로 `sudo bash install.sh`를 재실행해 끝까지 완료했다. `siem-var` 볼륨은 빈 `run/`만 있는 상태였다. 보안 경로 15/15, 관리 6/6, SIEM 8/8, SIEM UI 52/52 수용 검사 통과. `xocrange-core`·collector·osquery·sysmon·auditd 활성, `xoc siem status`는 `ready`.
- 새 Manager 이미지로 새 볼륨과 같은 tmpfs 중첩 마운트를 만든 일회성 컨테이너에서 `run`이 마운트 지점으로 인식되고 `holds_state`가 거짓임을 확인했다.
- `/siem/`은 HTTPS 로그인 화면으로 연결되고, 리다이렉트는 모두 `https://`를 유지한다.
- 로컬 테스트 435개 통과(1개 skip).

Docker·호스트 설정이 이미 있는 VM에서의 재실행이므로, 아무것도 없는 VM에서의 전체 설치는 다음 신규 VM에서 다시 확인한다. 재부팅 검증은 하지 않았으며 설치기가 실행한 `systemctl enable --now xocrange-core.service`의 기동·검증 경로는 통과했다.
