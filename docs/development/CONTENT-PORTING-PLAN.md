# 번들 콘텐츠를 현재 Core 기준으로 옮기기 — 조사 결과와 계획 (2026-11-18)

Community 번들(`contents/academy/wazuh-threat-hunting`, 36차시)의 본문·명령·검색식·그림이 전제하는
환경을 차시별로 뽑아 현재 Core(데모 Core 192.168.16.52, Core fc2881b)와 대조했다. 조사는 읽기 전용이며
공격 트래픽은 보내지 않았다. 규칙 존재와 필드 존재는 실제 Manager·Indexer에 물어 확인했다.
콘텐츠는 아직 고치지 않았다. 앞선 기록: [차이 조사](CONTENT-INFRA-AUDIT-2026-11-18.md),
[ADR 0012](../adr/0012-office-network-and-linux-host.md).

## 1. 콘텐츠의 구조

- 원본은 둘이다: 구글 슬라이드(339쪽, `lesson.json`의 슬라이드)와 원고 저장소
  `mrgrit/hack_ir_with_wazuh_book_1` 커밋 `7232660`(`explanation.json`의 절). `source-map.json`의
  `adaptation`은 "제품 이름만 교체, 기술 내용 대조는 보류"다.
- 분량: 슬라이드 본문 약 30만 자, 원고 본문 약 16만 자, 본문 그림 84장 외에 슬라이드 캡처가 따로 있다.
- 본문은 이전 환경에서 실행한 결과(시각·주소·건수·캡처)를 싣고 있다. 이름 치환만으로는 맞지 않는다.
- 한 차시 안에서도 슬라이드와 원고가 서로 다른 세대의 이전 환경을 쓴다(슬라이드: 공격자 터미널과
  `*.ccc.com`, 원고: Windows 브라우저와 `*.xocrange.lab`). 같은 사례에 다른 명령을 싣는 차시도 있다.

## 2. 그대로 맞는 것

- 교재가 쓰는 Wazuh 기본 규칙은 현재 Manager(4.14)에 모두 있다(웹 31xxx, sshd 57xx, sudo 54xx,
  계정 59xx, syscheck 55x 등 확인한 것 전부).
- 웹 접근 경보의 필드 `data.srcip`·`data.url`·`data.id`·`data.protocol`은 그대로다. HTTP는 실제
  출발지 주소가 남는다.
- 이름만 바꾸면 되는 차시: 20(sudo), 21(계정 변경), 24(cron).

## 3. 차이와 처리 방향

"Core"는 Core에 넣는다는 뜻, "교재"는 본문을 고친다는 뜻이다. 소유자 확인이 필요한 항목은 따로 표시했다.

| # | 교재의 전제 | 현재 Core | 걸린 차시 | 방향 |
|---|---|---|---|---|
| 1 | 장비별 Wazuh 에이전트(`agent.name: web`·`bastion`·`fw`·`ips`·호스트) | 모든 경보가 `agent.name: xoc-manager`. 출처는 `location`의 끝(`/apache-access` 등) | 전부 | 교재: 웹은 `location: *apache-access`, 호스트 사례는 `agent.name: "office-pc01"` |
| 2 | SSH로 들어가는 리눅스 호스트 `bastion`, 계정 `ccc` | 없음 → 업무용 PC `office-pc01`, 계정 `student`(ADR 0012, 구현, 실행 검증 중) | 시작하기, 16~30 | Core + 교재 |
| 3 | 실습망 안의 공격자 단말(hydra·sqlmap·nikto·gobuster·dirb) | 실습망 안에 없음. 외부 공격자 VM에는 curl·nmap·nc뿐 | 01, 04, 06, 14, 16~18, 25, 26, 30 | **Core(확인 필요)**: 외부망에 실습용 공격 단말 |
| 4 | SSH 경보의 `data.srcip`가 공격자의 실제 주소 | 2222 진입 경로는 진입점 주소(10.20.30.20) 하나 | 16~19 | 3번의 공격 단말에서 접속하면 실제 주소가 남는다 |
| 5 | 받은 로그 전체가 `wazuh-archives-*`에 있다 | 인덱스가 비어 있다(전 기간 0건). Core는 아카이브를 색인하지 않는다 | 시작하기 4, 03, 05~08, 10, 12, 13, 30 | **Core(확인 필요)**: 에이전트가 보낸 로그의 아카이브 색인. 아니면 교재를 `xoc-events-*`로 |
| 6 | Juice Shop은 탐지 전용(공격이 통과해 200) | DVWA·Juice Shop 모두 차단 모드 | 09, 11, 12, 15 | **Core(확인 필요)**: 타깃별 WAF 모드. 아니면 11번 재설계 |
| 7 | 반복 실패 시 Active Response가 180초 차단 | Manager에 Active Response 없음, PC에 iptables 없음 | 16(17·18 언급) | Core: 업무용 PC 대상 `firewall-drop` |
| 8 | 파일 무결성 경보에 변경 내용(`syscheck.diff`)과 변경자 | 업무용 PC 에이전트에 `report_changes` 없음. 변경자(whodata)는 컨테이너에서 auditd가 필요 | 22, 23, 24, 28 | Core: `report_changes`·감시 경로 추가. 변경자는 교재에서 뺀다 |
| 9 | 명령 실행 기록(auditd execve, 공격 단말 명령 기록 규칙 100260·100261) | 호스트 auditd에 execve 규칙 없음. 실행 기록은 Sysmon 경보(111201)뿐 | 25, 26, 29, 07 | 교재: Sysmon 경보 기준으로. 실행 검증 필요 |
| 10 | 업무 호스트에서 공격자 쪽 포트(4444·8000)로 나감 | 업무용 PC는 웹 방화벽과 Manager로만 나간다 | 25, 26 | Core: 3번의 공격 단말로 가는 지정 포트만 허용 |
| 11 | WAF 감사 기록에 요청 줄·헤더(`data.request.request_line`) | 감사 기록은 경보(119670~119672)이고 요청 줄·헤더가 없다 | 02, 03, 10, 13 | 교재: `data.audit_data.*`와 접근 로그로. 요청 줄 기록 추가는 보류 |
| 12 | 웹셸 사례: 웹 루트 무결성, VirusTotal, ClamAV | 없음 | 07 | 교재: 재설계 |
| 13 | 분석 화면은 Windows에서 연다, `:5601` | 브라우저에서 `https://<Core>/siem/` | 대부분 | 교재 |
| 14 | 모든 로그 시각은 한국 시간 | Core 접근 로그는 UTC | 시작하기 | 교재 |
| 15 | Windows·메일·DNS·NTP·시설 이벤트 규칙(119660~119663) | 없음 | 시작하기(infrastructure) | 교재: 현재 구성으로 다시 쓴다 |

### 원본 자체의 오류(환경과 무관, 같이 고친다)

- 21번 슬라이드: 규칙 5904를 "사용자 삭제"로 적었다. 삭제는 5903, 5904는 사용자 변경.
- 12번 슬라이드: 규칙 31152~31154를 "5xx 다발"로 적었다. 실제는 SQLi·XSS 반복. 원고의 31161~31163이 맞다.
- 01번: 규칙 31161을 "반복 SQLi"로 설명한다. Manager에서는 "501 오류 다발"이다.
- 이름 치환이 깨뜨린 실행 값: `data.alert.signature:xOC Range*`, `github.com/mrgrit/xOC Range`.
- 본문에 이전 환경의 계정·비밀번호가 실려 있다(`admin / SecretPassword` 등). 지운다.

### 그림

- 본문 그림 84장 가운데 화면 캡처는 이전 환경 것이다. 웹 사례 01~08에서만 72장 중 63장.
- 슬라이드의 "공격 실행" 장은 공격자 터미널 캡처라 글자로 고칠 수 없다(01~15에서 확인).
- 도식 3장과 캡처 여러 장에 내부 코드명 `kt66`이 보인다(`kt66 VM`, `kt66-host`, `kt66-update`).
  화면에 내부 코드명을 쓰지 않는다는 규칙에 어긋난다. 전부 다시 만든다.

## 4. 확인하지 못한 것

- 교재의 공격 요청이 현재 Core에서 받는 응답(트래픽을 보내지 않았다). 웹 공방전 Red 16개만 실행했다.
- 방화벽(nftables) 기록이 SIEM 경보로 가는지: 최근 7일 경보 0건. 수집원 상태는 `ready`다.
- Ubuntu 26.04의 Rust coreutils에서 `/usr/bin/yes`가 링크인지(27번 실습의 전제).
- Core 화면(SIEM)이 내는 요청이 접근 로그 경보로 잡혀 5xx·메서드 검색을 오염시키는 정도.
- 업무용 PC의 실제 동작 전부(두 번째 Core에 설치 중).

## 5. 순서

1. 업무용 PC 실행 검증(SSH → 방화벽·IPS 기록 → `agent.name: office-pc01` 경보).
2. 업무용 PC 보강(8번, 7번): 감시 경로·변경 내용·도구·Active Response.
3. 소유자 확인 항목(3·5·6번) 결정 → Core 반영.
4. 차시 전환: 차시마다 현재 Core에서 명령·검색식을 실행하고 본문·결과값을 고친다. 순서는
   시작하기 6차시 → 호스트 16~24 → 웹 01~15 → 25~30. 고친 구역은 `mapping_status`를 바꿔 표시한다.
5. 그림: 화면 캡처를 현재 Core에서 다시 찍고, 도식을 다시 그린다.
6. 무료 공방전 15개를 같은 방식으로 맞춘다. 유료 팩(307개)은 그 뒤다.

수정은 번들의 JSON에 한다. 원본(슬라이드·원고 저장소)에서 다시 가져오면 덮어써지므로, 가져오기
도구를 다시 돌리지 않는다는 점을 `source-map.json`에 적는다.

차시별 상세 목록: [content-ledger/](content-ledger/) (A 시작하기, B 웹 01~08, C 웹 09~15, D 호스트 16~23, E 호스트·네트워크 24~30).

## 6. 전환 기록

차시를 옮길 때마다 여기에 적는다. "본문"은 명령·검색식·설명·결과값, "그림"은 화면 캡처와 도식이다.
구역의 `mapping_status`: `pending-review`(손대지 않음) → `text-ported`(본문 전환, 그림은 이전 것) →
`ported`(그림까지 교체).

| 차시 | 본문 | 그림 | 실행한 Core | 비고 |
|---|---|---|---|---|
| 20 sudo 권한 사용 | 전환(2026-11-19) | 이전 환경 캡처 6장 그대로 | 192.168.16.51·52, Joint Force 라이선스 | 공격 실습 단말 → `ssh -p 2222 student@10.20.30.1` → `id`·`sudo -l`·`sudo -i id`·`sudo cat /etc/shadow`. 경보 5402(`COMMAND=/bin/bash --login -c id`, `/usr/bin/cat /etc/shadow`), `agent.name: office-pc01`. 원본과 다른 점: 5403은 그 PC에서 그 계정의 첫 sudo 한 번에만 난다. 슬라이드 243·244의 "3 hits"는 캡처와 함께 고친다 |

전환에 쓰는 도구: `contents/scripts/replace-asset.py`(그림 한 장을 새 PNG로 교체하고 참조·목록을 맞춘다).

