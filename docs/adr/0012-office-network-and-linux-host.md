# ADR 0012: 업무망과 리눅스 실습 호스트

상태: 제안(2026-11-18). 구현·실행 검증 전이다.

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

## 결정(안)

1. **업무망 `office`(화면 표기 "업무망") 10.20.70.0/24를 security-path에 추가한다.** kt66 `user` 존과 같은
   대역·위치(IPS의 세 번째 다리 10.20.70.1)다. Core에서 `user`는 이미 호스트 접속용 망 이름이라 쓰지
   않는다. 실습 호스트 모듈을 설치하지 않아도 망과 2F 화면의 스위치는 있다.
2. **리눅스 실습 호스트 컴포넌트를 Core(Community)로 추가한다.** 업무망 10.20.70.21(10.20.70.10은 M6
   Windows 자리로 남긴다). sshd, rsyslog(`auth.log`), sudo, cron, Wazuh 에이전트를 갖춘다. 기본 설치에
   포함하고 `--without`으로 뺄 수 있다.
3. **IPS 정책은 kt66 `user-network.sh`를 기능 단위로 옮긴다.** 업무망 → WAF(8080·8443), 업무망 → Manager
   1514만 허용하고 업무망 → 그 밖의 실습망은 차단한다. 외부 → 실습 호스트 SSH는 FW와 IPS를 모두
   거친다(FW 기록, Suricata 검사).
4. **M6(Windows)은 그대로 유료 모듈이다.** 설치하면 같은 업무망에 들어온다.

kt66과 다른 점: kt66의 bastion은 `ext`에 있었다. Core는 소유자 결정에 따라 실습 호스트를 업무망에 둔다.

## 구현 전에 풀어야 할 것

- **외부 SSH의 출발지 주소 보존.** 지금 호스트 진입은 HAProxy(HTTP는 헤더로 출발지를 전달)다. SSH는
  헤더가 없으므로 `auth.log`·FW·IPS 기록에 실제 출발지가 남으려면 주소 변환 방식의 진입이 필요하다.
- **Manager 도달 경로.** Core의 Manager는 `int`에만 있고 WAF는 패킷을 전달하지 않는다. 업무망의
  에이전트가 1514에 닿을 경로(Manager의 망 다리 또는 전용 중계)를 정해야 한다.
- 정책 검사(`network_policy.py`), 계약(`security-compose-fragment.json`), 2F 망 화면(스위치 5대),
  설치 수용 검사(업무망에서 `int` 직접 접근 불가), 수집원 등록을 같이 고친다.

## 영향

교재의 `bastion`·`192.168.0.x`·`ccc` 표현은 구현 뒤 새 호스트 이름과 학생 도메인으로 바꾸고, 차시별로
실제 Core에서 명령·검색식을 실행해 맞춘다.
