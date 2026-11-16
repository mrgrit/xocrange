# Live Fire 학생 도메인 실행 검증 — 2026-11-16 (ADR 0011)

## 환경

| 역할 | 주소 | 비고 |
|---|---|---|
| Live Fire Range Control | 192.168.16.101 | 시험용 공급사 키(`vendor-e2e`)로 서명한 발급자 인증서(좌석 10) |
| 새 Core VM | 192.168.16.52 | Ubuntu 26.04, 4 vCPU·15 GiB·94 GB, 빈 VM, 같은 /25 대역 |
| 개발 VM | 192.168.16.100 | 서버 찾기·등록 거절 시험, 반 친구 이름 시험용 등록(Core에는 적용하지 않음) |

## 결과

| 항목 | 결과 |
|---|---|
| 서버 찾기 | 방송과 직접 지정 모두 응답(UDP 47321) |
| 등록 거절 | 틀린 코드·실제 사이트 도메인(`naver.com`)·신뢰하지 않는 공급사 키·이미 쓰는 도메인 모두 안내 문구와 함께 거절 |
| 새 VM 설치 | `install.sh --include target-dvwa --include target-juice --enroll-code … --lab-domain alice.lab --trust-vendor-key …`: 서버를 찾아 등록 → 라이선스 활성화 → 설치·수용 검사 통과(`INSTALL_EXIT=0`) |
| 라이선스 | `xoc license status`: `tier live-fire`, `domain alice.lab`, `issuer_id rc-livefire-dev` |
| 접속 | Core CA로 인증서 검증 성공(`ssl_verify_result 0`). `https://dvwa.alice.lab/` → DVWA 로그인, `https://juice.alice.lab/` → OWASP Juice Shop, `https://alice.lab/` → `/core/`, `dvwa.xoc.range`도 그대로 동작 |
| 인증서 | 웹 입구 인증서 SAN에 `alice.lab`·`*.alice.lab`. 새 CA에 이름 제한(`xoc.range`, `lab`, `test`, `internal`, `home.arpa`, 내부 이름) |
| 반 목록 | 새 VM `/etc/hosts` 관리 블록에 `192.168.16.52 alice.lab dvwa.alice.lab juice.alice.lab`. 시험용 `bob.lab` 등록 후 다음 동기화에서 `bob.lab` 줄이 추가되고 `dvwa.bob.lab`이 192.168.16.100으로 해석·접속됨. 회수하면 다음 동기화에서 빠짐 |
| 화면 | Range Control "Core 등록"에 발급자 인증서·코드 사용 수·등록된 Core(도메인·주소·마지막 연결) 표시 |

## 고친 결함

- 서버 찾기 응답기가 root 전용 폴더의 설정을 읽지 못함 → 공개 정보만 담은 파일을 읽을 수 있는 위치로 옮김(Live Fire 24e10df).
- 설치 프로그램이 작업 잠금을 쥔 채 `xoc license trust`를 불러 `operation_busy` → 같은 함수를 직접 호출. 등록 결과를 받자마자 보관해, 이후 단계가 실패해도 다시 실행하면 재등록 없이 활성화(Core 4eb3219).

## 남은 일

- 판정기 모듈(`m15-assessor`)을 새 VM에 설치하고 `/etc/xocrange/livefire/credentials`로 연결하는 것은 유료 모듈 배포(L17) 뒤에 확인한다.
- 정식 배포에는 공급사 공개키를 Core에 넣어 `--trust-vendor-key` 없이 동작하게 한다.
- `/etc/xocrange`가 root 전용이라 `/etc/xocrange/ca.crt`(0644)를 일반 사용자가 읽지 못한다(이번 변경 전부터). 학생에게 CA를 나눠 주는 방법을 정한다.
