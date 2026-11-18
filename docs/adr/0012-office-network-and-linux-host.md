# ADR 0012: 업무망과 리눅스 실습 호스트

상태: 채택·구현(2026-11-18). 두 번째 Core(192.168.16.51, `bob.lab`)에서 실행 검증했다(아래 "실행 검증").

## 배경

Community 번들의 교재 16~30번 사례와 호스트 공방전 7개는 SSH로 들어가는 리눅스 호스트, 그 호스트의
`/var/log/auth.log`, 그 호스트의 Wazuh 에이전트를 전제한다. 현재 Core 실습망(ext·pipe·dmz·int)에는
그런 호스트가 없다([조사](../development/CONTENT-INFRA-AUDIT-2026-11-18.md)).

소유자 결정(2026-11-18): Windows 자체는 Core에 넣지 않지만, 내부 근무자의 PC가 놓이는 망은 Core에
있어야 한다. 실습 호스트는 그 망에 둔다.

## 이전 인프라(kt66 `9b3efed`)에서 확인한 것

| 항목 | kt66 |
|---|---|
| 근무자 PC 망 | `user` 존 10.20.70.0/24, IPS의 다리 10.20.70.1(FW → IPS 아래). `docker-compose.yaml`, `endpoints/user-network.sh` |
| 그 망의 장비 | Windows 평가판 엔드포인트 10.20.70.10(선택 설치) |
| 망 정책(IPS) | 업무망 → Manager 1514·1515, DNS, NTP, 메일, WAF 80·443 허용. 공격자 → Windows 3389 허용. 업무망으로 들어오는 나머지와 업무망 → 다른 사설 대역은 차단. 인터넷 53·80·443은 FW에서 주소 변환 |
| 점프 호스트(bastion) | 업무망이 아니라 `ext` 10.20.30.201, 호스트 포트 2204 → 22. sshd·rsyslog·Wazuh 에이전트·auditd·osquery |

## 결정

1. **업무망 `office`(화면 표기 "업무망") 10.20.70.0/24를 security-path에 추가한다.** kt66 `user` 존과 같은
   대역·위치(IPS의 세 번째 다리 10.20.70.1)다. Core에서 `user`는 이미 호스트 접속용 망 이름이라 쓰지
   않는다. 실습 호스트 모듈을 설치하지 않아도 망과 2F 화면의 스위치는 있다.
2. **리눅스 실습 호스트 컴포넌트를 Core(Community)로 추가한다.** 업무망 10.20.70.21(10.20.70.10은 M6
   Windows 자리로 남긴다). sshd, rsyslog(`auth.log`), sudo, cron, Wazuh 에이전트를 갖춘다. 기본 설치에
   포함하고 `--without`으로 뺄 수 있다.
3. **IPS 정책은 kt66 `user-network.sh`를 기능 단위로 옮긴다.** 업무망 → WAF(8080), 업무망 → Manager
   1514만 허용하고 업무망 → 그 밖의 실습망은 차단한다. 외부 → 실습 호스트 SSH는 FW와 IPS를 모두
   거친다(FW 기록, Suricata 검사).
4. **M6(Windows)은 그대로 유료 모듈이다.** 설치하면 같은 업무망에 들어온다.

kt66과 다른 점: kt66의 bastion은 `ext`에 있었다. Core는 소유자 결정에 따라 실습 호스트를 업무망에 둔다.

## 구현

- 망: security-path에 `office` 10.20.70.0/24, IPS 다리 10.20.70.1. 2F 화면에 다섯 번째 스위치.
- 업무용 PC: 컴포넌트 `office-pc`, 호스트 이름 `office-pc01`, 10.20.70.21. 실습 계정 `student`
  (비밀번호는 설치마다 무작위, `sudo xoc platform credentials`). 세션은 NET_ADMIN 없이 돈다.
- 들어오는 길: 호스트 2222 → 진입점 → 방화벽 DNAT → IPS(검사) → PC의 22.
- 나가는 길: 웹 방화벽 8080(검사), Manager 에이전트 포트 1514, 공격 실습 단말의 실습 포트
  ([ADR 0013](0013-practice-attack-terminal.md))뿐이다.
- Manager 도달: Manager에 DMZ 주소 10.20.32.100(kt66의 SIEM 주소)을 주고, IPS가 업무망 → 그 주소의
  1514만 넘기며 출발지를 바꾼다. Manager의 다른 포트는 내부망에만 있다.
- 에이전트: `auth.log`·`syslog` 수집, 파일 무결성(`/etc`·`/home`·`/var/spool/cron`은 변경 내용 포함),
  열린 포트 주기 수집. 반복 SSH 실패(규칙 5712·5763)에는 180초 차단(Active Response).

## 실행 검증 (2026-11-18, 192.168.16.51, Core 437ef36a 릴리스)

외부 공격자 VM(192.168.16.99)에서 `ssh -p 2222`로 시도했다.

| 항목 | 결과 |
|---|---|
| 없는 계정 1회 | `auth.log` `Invalid user`, 경보 5710 |
| 틀린 암호 3회 | 경보 5760 ×3, 5503 ×3 |
| 맞는 암호 | 로그인, 경보 5715, 세션 5501 |
| `sudo -n id` | root, 경보 5402·5403 |
| 경보의 에이전트 | `agent.name: office-pc01`(21건), `wazuh-alerts-4.x-*` |
| 방화벽 기록 | `[xoc-fw] ACCEPT … DST=10.20.70.21 … DPT=22`, 계수기 `forwarded_office` 증가 |
| PC에서 웹 방화벽 | `http://10.20.32.80:8080/` 200 |
| PC에서 내부망 직접 | 연결 불가 |
| PC에서 Manager API(55000) | 연결 불가 |
| `sudo ip link add` | `Operation not permitted`(NET_ADMIN 없음) |
| 2F 망 정보 | `office 10.20.70.0/24 [ips, office-pc]`, DMZ에 `siem` 추가 |

알려진 한계: 2222로 들어온 접속의 출발지는 PC에 진입점 주소(10.20.30.20)로 보인다. 실제 주소가
필요한 실습은 공격 실습 단말에서 한다(ADR 0013).

검증 중 찾아 고친 것: 되돌려진 설치가 남긴 옛 에이전트 키 때문에 PC가 Manager에 붙지 못했다. PC가
놓인 키를 주기적으로 대조해 바뀌면 에이전트를 다시 시작한다. 아직 검증하지 않은 것: 보강한 에이전트
설정(변경 내용, 열린 포트, 180초 차단)과 Windows(M6)의 같은 망 연결.

## 영향

교재의 `bastion`·`192.168.0.x`·`ccc` 표현은 구현 뒤 새 호스트 이름과 학생 도메인으로 바꾸고, 차시별로
실제 Core에서 명령·검색식을 실행해 맞춘다.
