# K05 실습 타깃 실검증 — 2026-11-11

대상: 개발 VM(Ubuntu 26.04, 16 GiB), 설치본을 `xoc update --source`로 갱신한 뒤 `xoc module add/remove`로 검증.

## 결과

| 항목 | 방법 | 결과 |
|---|---|---|
| Juice Shop 추가 | `sudo xoc module add target-juice` | 설치 트랜잭션·수용 검사 통과 |
| DVWA 추가 | `sudo xoc module add target-dvwa` | 통과 |
| 학습자 접속 | `curl --resolve juice.xoc.range:443:…` | Juice Shop 200, API 200 / DVWA `/login.php` 리다이렉트 유지(https·호스트 보존) |
| WAF 차단 | Juice Shop UNION SQLi, DVWA 명령 주입 | 둘 다 403 |
| SIEM 기록 | `xoc siem query --source modsecurity` | 942270·949110(blocked) 규칙 메시지와 트랜잭션 C1 이벤트, Wazuh 확인(110003) |
| 관리 화면 유지 | `https://<IP>/core/` | 200 (타깃 vhost는 관리 vhost 뒤에 배치) |
| 인증서 | ingress SAN | `xoc.range`, `*.xoc.range` 포함 |
| hosts 안내 | `sudo xoc platform targets` | `192.168.0.74 dvwa.xoc.range juice.xoc.range` |
| 개별 제거 | `sudo xoc module remove target-dvwa` | 컨테이너·vhost 0건, `dvwa.xoc.range`는 관리 vhost로 떨어져 `/core/`로 302, Juice Shop 유지, hosts 줄에서 제외 |
| 재추가 | `sudo xoc module add target-dvwa` | 통과 |
| 복구 지점 정리 | 각 트랜잭션 후 `/var/lib/xocrange/backups` | 최신 `before-install-*` 1개만 유지 |

## 남은 확인

- 서버 자신에서 보낸 요청이라 SIEM의 출처 IP는 Docker 게이트웨이(172.18.0.1)로 기록됐다. 외부 PC에서의 출처 IP 보존은 별도 확인이 필요하다.
- DVWA는 첫 사용 시 `setup.php`에서 DB 생성이 필요하다(upstream 동작).
- 신규 VM 기본 설치에 타깃을 포함할지는 결정하지 않았다. 현재는 선택 추가다.

## 검증 중 발견·수정한 결함

- SIEM UI 수용 검사의 sshd 프로브가 자신의 `docker exec` 명령줄 감사 기록과 함께 2건으로 잡혀 업데이트가 실패·자동 롤백됐다(롤백은 정상 동작). 프로브 전달 방식을 바꿔 해결(`f592e2c`).
- `sudo xoc update --source`가 소스 체크아웃에 root 소유 `scripts/__pycache__`를 남겼다(`490ef98`).
- 설치 전 복구 지점이 정리되지 않아 디스크가 차고 다음 변경이 `backup_space`로 거부됐다(`59aea99`).
- SIEM DB가 최고 사용량 크기를 유지해 백업이 커졌다. incremental auto-vacuum 도입, 기존 DB는 1회 VACUUM(38 GB → 6.1 GB)(`be47b2a`).
