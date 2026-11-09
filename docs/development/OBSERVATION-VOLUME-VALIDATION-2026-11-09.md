# Observation 수집량 조정 — 2026-11-09

`observation`은 Sysmon·osquery가 수집하는 일반 행위 기록이다. 공격 판정과는 별개이며, 실행·연결·프로세스 목록 변화 등을 분석에 활용한다. xoc VM에서 Sysmon 프로세스 종료(EventID 5)가 과다 발생하여 기본 호스트 정책을 조정했다.

## 원인과 변경

기존 XML은 프로세스 생성·네트워크 연결만 명시하고 종료 필터를 생략했다. 실제로는 종료 기록도 발생했고, 조사한 최근 1만 건 중 7,240건이 종료 기록이었다. Docker·Compose·runc 등 반복 실행되는 프로세스에서 많은 기록이 발생했다.

`components/siem/sysmon.xml`에 빈 `<ProcessTerminate onmatch="include"/>`를 추가했다. [Microsoft 설정 예제](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#configuration-files)의 종료 수집 비활성화 방식이다. 프로세스 실행(EventID 1)·네트워크 연결(EventID 3)은 계속 수집한다. Docker나 셸 실행 전체를 제외하지 않았으며 Wazuh 탐지 규칙은 변경하지 않았다. 종료 시점 추적이 필요한 별도 정책에서는 EventID 5를 활성화할 수 있고 디코더 지원도 유지한다.

VM의 기존 `/etc/xocrange/sysmon.xml`이 저장소의 이전 기본 파일과 일치하는지 확인하고, root 전용 복사본을 만든 뒤 `sysmon -c`로 적용했다. 애플리케이션 재설치 없이 호스트 센서 정책을 갱신했으며 기존 불변 release는 유지했다. 신규 설치에는 수정된 기본 파일이 설치된다. 소스 파일과 활성 호스트 정책의 SHA-256이 일치한다.

## 실제 VM 검증

| 항목 | 적용 전 120초 | 적용 후 120초 |
|---|---:|---:|
| 전체 C1 이벤트 | 5,339 | 1,411 |
| 초당 이벤트 | 44.492 | 11.758 |
| Sysmon 종료 EventID 5 | 3,970 | 0 |
| Sysmon 실행 EventID 1 | 1,023 | 1,018 |
| Sysmon 연결 EventID 3 | 110 | 136 |

전체 이벤트 수는 73.57% 감소했다. 서로 다른 두 시간 구간의 개발 VM 측정치이며, 장기 처리량이나 저장 용량 보장 수치는 아니다. 부하 검증 트래픽은 이 비교 구간이 끝난 뒤 생성했다.

- 실제 신규 이벤트: nftables·Suricata·ModSecurity·osquery·Sysmon·auditd·Apache access/error 8종 C1 확인 및 독립 native 디코딩 모두 통과.
- Indexer: 검증 시작 이후의 Sysmon EventID 1·3 문서를 실제 검색 저장소에서 각각 확인.
- 로컬 회귀: telemetry·retention·native input·native alerts 관련 86개 테스트 통과.
- 적용 후 센서·수집기·Wazuh·Indexer·보관 상태 모두 ready, 격리 기록 0건.

집계·검증 결과와 정책 hash는 [수락 증거](../provenance/observation-volume-acceptance.json)에 기록한다. 원본 로그 본문과 인증 정보는 포함하지 않는다.

## 저장 공간

수용 검사 시 파일시스템 여유는 약 42.5 GiB, SQLite 할당량은 약 37.8 GiB였다. 조사 시 설치 전 복구 지점도 약 68.5 GiB를 차지했다. 현재 로그나 백업을 삭제하지 않았다.

기존 보관 정책은 로컬 DB 1일·Manager 회전 로그 2일·검색 인덱스 7일이다. 미분석·미색인 증거는 기간만으로 삭제하지 않는다. VM에 기존 설정된 신규 수집 예산 48 GiB·DB 한도 64 GiB는 그대로 유지했다. 신규 설치 기본값 24/32 GiB와 구분한다.

기존 누적분은 각 계층의 보관 정책에 따라 순차 정리된다. SQLite는 해제한 페이지를 재사용하므로 DB 파일이 즉시 작아지지는 않는다. 보관 정책은 모든 로그 볼륨과 백업을 합친 디스크 상한이 아니며, 이후 용량 판단에서는 `xoc siem status`의 사용량·할당량·파일시스템 여유와 백업 용량을 함께 확인한다.
