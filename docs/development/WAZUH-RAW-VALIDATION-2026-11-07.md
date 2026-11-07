# 원본 분석·전체 SIEM 선택 검증 — 2026-11-07

검증 대상은 Ubuntu Server 26.04.1 amd64, 8 vCPU·16 GiB RAM·300 GiB 디스크의 전용 VM과 Wazuh Manager/Indexer/Dashboard 4.14.10이다. 기존 kt66 호스트는 읽기 전용으로 참고했다. 설치 소스 SHA-256은 `9ee0b08d8c0d7e688c598831c651319419dc312af88b5dd4fbf0a606c929b923`이다.

이전 native 기반 통합의 209개 단위 검사·48개 HTTPS 검사는 [이전 기록](WAZUH-NATIVE-VALIDATION-2026-11-07.md)에 그대로 남긴다. 이번 증분은 8종 원본의 독립 분석과 전체 SIEM 선택 회귀다. 전체 kt66 기능/운영 규칙 동등성이나 Community 출시 판정이 아니다.

## 원본 분석 검증

| 항목 | 결과 |
|---|---|
| 개발 호스트 Python 3.10 / VM Python 3.14 | 각각 단위 검사 240개 통과 |
| 실제 엔진 비교 | kt66 4.10.0 / 후보 4.14.10, 각각 25개 입력, 총 50개 기대 결과 통과 |
| 보안 경로 | fw→IPS→WAF 실제 통신·차단·장애 복구 15개 통과 |
| 실제 새 C1 이벤트 | 8종 모두 Wazuh 확인 |
| 실제 새 원본 입력 | 8종 모두 Manager archive의 입력 ID·frame hash·decoder 확인 |
| HTTPS/API/WAF | 52개 통과; 그중 원본 Suricata·WAF·Sysmon·Apache error 경보의 증거 연결/색인 4개 추가 |
| 실제 원본 재전송 | 4종 재분석 receipt와 수집 cursor 진행 확인, 첫 경보 byte/hash 보존 및 고유 검색 문서 4개 유지 |

비교 harness는 운영 데이터·포트 없이 network=none 컨테이너에서 실제 DB·analysisd를 실행했다. 이미지 digest와 kt66 검토 파일 hash는 [출처](../provenance/wazuh-raw-sources.json), 입력별 decoder·rule·level·주요 필드는 [비교 JSON](../provenance/wazuh-raw-rule-comparison-2026-11-07.json)에 기록한다. 후보 Sysmon EventID 1/3/11은 Linux 관측 규칙이며 Windows 공격 탐지 규칙의 동등성을 뜻하지 않는다.

## 검증 중 수정한 문제

- nftables의 RFC3339 소수점 시각에서 Wazuh predecoder가 `program_name=ernel`로 처리하는 경우를 실로그에서 발견했다. 프로그램명과 검토된 방화벽 prefix를 함께 검사하는 decoder를 추가했고 소수점 유무·ACCEPT/DROP을 실제 엔진에서 대조했다.
- ModSecurity AHZ 로그에는 `response.status`가 없었다. audit 메시지 시작의 실제 intervention과 enforcing 모드를 검사해 차단을 식별한다. 애플리케이션 403·본문·경고에 인용된 `Access denied`·detection-only는 차단으로 오인하지 않는다. kt66의 119670/119671/119672 번호와 level 3/5/7을 유지한다.
- Apache access의 기존 최소 JSON은 stock URI 기반 탐지에 필요한 정보를 생략했다. common access와 request ID를 사용해 stock web 규칙을 복원하고, C1에서는 계속 URL/query를 제외한다. ModSecurity의 헤더/본문 수집 범위는 늘리지 않았다.
- 초기 512건 전송은 재설치 중 쌓인 Sysmon 원본 처리에 부족했다. 최대 4,096건/8 MiB로 조정해 약 1만 7천 건의 분석 대기를 최신 수 초 분량까지 해소했다. 형식 오류·누락 decoder는 정상 처리로 표시하지 않는다. 중복된 decoder 오류 receipt가 다른 입력 처리를 막지 않는 회귀도 추가했다.
- 기존 증거를 삭제하지 않고 신규 수집 중단 기준을 4→8 GiB로 올렸다. 이 값은 전체 디스크 상한 또는 운영 규모 용량 보장이 아니다.

## 선택 수명주기

SIEM 전체 제외 13개·제외 상태 재설치 14개·재포함 18개 검사가 통과했다. 24개 원본/C1, 24개 Wazuh 경보, 8종 native 처리 receipt, 두 CA·자격 증명, saved search와 역할 없는 API 사용자를 대조한다. 별도의 감사 watch로 xOC 소유 규칙과 일반 OS 감사 규칙의 경계를 검사한다.

두 차례의 제외 상태 검사에서 원본 734,355건·C1 735,340건·Wazuh 경보 396,935건·native 입력 76,325건이 동일했다. 제외 중 OS auditd와 별도 감사 watch는 유지됐고, xOC의 세 watch 및 collector/osquery/Sysmon은 해제됐다. 재포함 후 새 보안 경로 15개·8종 C1/native 입력·HTTPS 52개를 다시 검사했으며 모든 보존 대조가 통과했다.

Indexer 중단/복구도 통과했다. 장애 중 Wazuh 확인이 계속됐고, C1 100개·전체 Wazuh 경보 표본 100개·원본 분석 경보 표본 100개가 재기동 후 각각 중복 없이 검색됐다. 두 경보 표본은 일부 겹칠 수 있으므로 합산하지 않는다.

실제 재부팅 후 boot ID 변경과 자동 기동을 확인했고, 보존 검사 16개·새 보안 경로 15개·8종 C1/native 입력·HTTPS 52개가 다시 통과했다. 브라우저 검사 15개도 통과했으며 인증된 HTTP 오류는 0건이었다. 로고·C1 검색·Wazuh 홈·서버 상태·Threat Hunting 화면을 확인했다.

검증용 saved search·역할 없는 Manager API 사용자·임시 감사 watch만 정리했다. 기존 증거·계정·CA·볼륨은 유지했다. 최종 수집 상태는 `ready`, 파싱 격리와 native decoder 오류는 0건, 색인 대기는 0건이었다. 계속 발생하는 입력의 분석 대기는 당시 275건/최장 1초였다. 전체 실행 결과는 [검증 JSON](../provenance/wazuh-raw-acceptance-2026-11-07.json)에 남긴다.

## 남은 범위

외부 에이전트 등록·Windows 실수집, 전체 kt66 운영 규칙/로그 동등성, 고급 규칙 편집·설정 요청의 WAF 회귀, 플랫폼 공통 인증/권한, 장기 부하·소스 로그/archives 보존·디스크 고갈 복구는 로드맵의 다음 수용 조건이다. 원본/native 검색에 민감한 값이 포함될 수 있으므로 현재 관리자 전용 범위를 유지한다. CI는 기존 비활성 템플릿 상태다.
