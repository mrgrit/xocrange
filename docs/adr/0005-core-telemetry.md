# ADR-0005: Core의 8종 관측과 Wazuh 분석 경계

2026-11-07 사용자가 nftables, Suricata, ModSecurity, osquery, Sysmon, auditd, Apache access/error의 SIEM 디코딩을 Core 요구사항으로 지정했다. 기존 계획의 M17 중 기본 관측·디코딩을 Community에 포함한다. Atomic Red Team 실행·평가·자동 공격은 이 변경에 포함하지 않는다.

`siem` 선택 시 Wazuh 4.14.10 분석 엔진과 전용 VM의 osquery·Sysmon for Linux·auditd 수집을 설치한다. 원격 등록 API, Wazuh Indexer/Dashboard, 웹 인증·관제 화면은 이번 백엔드와 별개다. 이 단계는 K06의 수집·디코딩 부분이며 Community 완성판이 아니다.

일반 확장 모듈의 권한 정책은 유지한다. 내장 security-path는 장비별 로그 볼륨만, 내장 siem은 자체 로그 볼륨·큐 tmpfs와 분석 엔진에 필요한 CHOWN/DAC_OVERRIDE/SETUID/SETGID/SYS_CHROOT만 허용한다. privileged·호스트 네트워크·Docker socket 마운트는 없다. Wazuh API·등록·자동 대응 daemon과 외부 포트는 열지 않는다.

관리자 권한의 로컬 수집기가 Docker가 관리하는 로그 볼륨의 소유 프로젝트·역할을 확인하고 직접 읽는다. 볼륨 이름+파일 inode+세대+offset으로 재처리를 식별하므로 컨테이너 교체가 로그 전체 재수집을 일으키지 않는다. 호스트 도구는 전용 VM에만 설치하며 kt66 개발 호스트에는 설치하지 않는다.

SQLite WAL/FULL 트랜잭션으로 원본·정규화·offset·outbox를 보관한다. Wazuh queue 전송 확인과 실제 분석 확인을 구분한다. 전송은 at-least-once이며 장애 경계에서 Wazuh alerts 파일에 같은 event ID가 반복될 수 있다. 검색 저장소는 event ID로 중복을 제거한다. 완전한 exactly-once 또는 다중 테넌트 인증을 주장하지 않는다.

상위 계획의 근거는 [PACKAGING C1](https://github.com/mrgrit/xocrange_plan/blob/main/docs/PACKAGING.md), [WORKPLAN P0/P3](https://github.com/mrgrit/xocrange_plan/blob/main/docs/WORKPLAN.md)이다. 이 ADR은 이번 사용자 요구에 따른 Core/M17 경계 조정 기록이다.
