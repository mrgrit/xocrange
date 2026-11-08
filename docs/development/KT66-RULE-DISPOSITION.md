# kt66 규칙 이식 범위

2026-11-07의 원본 `~/work/kt66`를 읽기 전용으로 검토했다. Git 기준점은 `b179231073b25fb797b9c6443da393d02cc12340`이다. 원본의 기존 수정 파일과 실행 환경은 변경하지 않았다. 검토한 파일의 해시는 [규칙 출처 목록](../provenance/kt66-rule-review.json)에 기록한다.

| 원본 규칙 묶음 | Core 처리 | 검증 / 후속 조건 |
|---|---|---|
| Wazuh 기본 SSH·audit·Suricata·Apache | 4.14.10 기본 규칙 유지 | 4.10/4.14.10 실제 엔진 입력 비교 및 실제 Linux 에이전트 SSH 이벤트 |
| ModSecurity JSON | Core native decoder/rule로 연결 | 차단·일반 403·detection-only·인용 문자열·AHZ 누락 필드를 구분 |
| Linux Sysmon·osquery·nftables | C1과 독립적인 native 입력·증거 연결 | 8종 실수집, archive 처리 receipt, 탐지 경보 색인 |
| `cmdlog-*` 100260/100261 | 자동 이식 보류 | PROMPT_COMMAND·Assessor의 command_ran 이벤트에 종속. K08/SSH 훈련 연결 시 원천과 함께 도입; auditd/Sysmon과 의미가 같다고 간주하지 않음 |
| `bastion-audit-*` 100200~100218 | Core에서 제외 | AI mission/lifecycle 기능 경계. 해당 후속 모듈에서 원천과 규칙을 함께 검증 |
| `kt66-events-*` 119660~119663 | Core에서 제외 | envsim/instructor 원천과 M4/M15 기능 경계 |
| `hollaex-honeypot-*` 119680~119686 | 미선택 타깃 규칙으로 보류 | 해당 실습 타깃 모듈 도입 때 입력·탐지 대조 필요 |

이는 전체 kt66 운영 로그의 탐지 동등성 인증이 아니다. Core에서 현재 선택한 원천과 실행 가능한 규칙을 검증하고, 미선택 기능은 누락으로 숨기지 않고 모듈 경계에 배정한다. 기존 SSH 기본 계정·고정 암호·무제한 자동 등록 설정을 새 Core에 복사하지 않는다.
