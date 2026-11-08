# K10 · K11 실행 검증

정본은 [CORE-KICKOFF@f548caa](https://github.com/mrgrit/xocrange_plan/blob/f548caa/docs/CORE-KICKOFF.md)다. 이 단계에서 C7와 모듈 수명주기, 일관된 백업·업데이트·복원, 운영 자원 관측과 의존성 기록을 구현했다. Community 전체 RC 판정은 K12에서 수행한다.

## K10 구현

- C7 오프라인 Ed25519 서명 검증, 기관·range·티어·Core 버전·모듈 버전과 콘텐츠/시나리오 구매 범위 검사.
- 유효 기간이 지난 상용 권한은 읽기·내보내기·중지에 한정한다. Core 기능은 별도로 유지한다. 공개 저장소에 서명 개인키나 자동 신뢰키를 넣지 않는다.
- 선택 모듈 추가·제거·재설치와 업데이트 시 기존 선택 옵션·계정·설정·볼륨 보존. 필수 구성요소 제거와 종속성 파괴를 거부한다.
- 부팅 시 현재 권한을 다시 검사하고 허용되지 않은 상용 모듈의 실행을 중지한다. API에서도 선택 상태와 권한을 검사한다.
- 검증용 외부 fixture의 설치 → up → 제거 → up → 재설치 → 제거를 실제 VM에서 실행했다. 상태 API·메뉴·컨테이너·계정/정책 유지, C1 형식 검증까지 포함한 33개 검사를 통과했다. 이 최소 VM에는 SIEM이 없으므로 fixture의 Manager 수신을 검증한 것으로 세지 않는다.

## K11 구현

- 공통 작업 잠금, 정지한 일관 상태의 백업, SHA-256·파일 크기·경로 검사, 정확한 이미지 ID 보존과 portable image archive.
- 복원 전 복구 지점 보관, 실패 상태 별도 보관, 원본 수집 커서·압축 파일 및 Sysmon journal 위치 재연결.
- 설치 실패 시 마지막 검증본으로 자동 복원. 새 VM에서는 `install.sh --restore BACKUP` 한 번으로 런타임 설치와 복원을 수행한다.
- 원천 로그 회전과 읽기 위치/열린 파일 확인 후 보존 기한 삭제, journal 용량 제한, SIEM 수집 상태와 저장 예산.
- 설치 소스·OS·패키지·컨테이너 패키지·이미지 ID/digest의 실제 목록 생성. Python 의존성 버전/해시와 기본 이미지 digest 고정.
- Ubuntu 자동 패키지 갱신과의 APT lock 충돌은 해당 작업을 종료하거나 lock 파일을 지우지 않고 기다린다. 다른 패키지 오류는 숨기지 않고 실패로 처리한다.

## 실제 VM 실행

| 대상 | 실행과 확인 |
|---|---|
| 빈 Ubuntu 26.04.1 LTS / 2 vCPU / 4 GiB | Docker가 없는 상태에서 `install.sh --without siem` 한 번으로 설치. 보안 경로 15개·관리 입구 6개 확인 |
| 최소 VM 모듈 수명주기 | 33개 검사: 실제 외부 fixture 추가·제거·재설치, 의도한 업데이트 수락 실패 후 계정·정책·릴리스 복구 |
| 최소 VM portable 백업 | 11개 검사: 백업 검증, 변조 거부, 실제 정책 DB 변경 후 복원, 이미지·계정·설정 및 복원 전 복구 지점 |
| 두 번째 빈 VM / 2 vCPU / 4 GiB | `install.sh --without siem --restore BACKUP`. 서로 다른 machine ID, 계정/역할/정책, FW·IPS·웹 로그의 기존 바이트, 이미지 ID, HTTPS 로그인 등 11개 검사 |
| 최소 VM 단기 부하 | 120초, 초당 2요청, 240/240 정상 응답. 최대 사용 RAM 약 901 MiB, 최대 관측 CPU 3%. 보장 사양이나 최대 처리량 측정은 아님 |

백업·계정·원본 로그는 private 검증 디렉터리에 보관한다. 공개 증거에는 검사 결과와 비밀이 없는 요약만 넣는다. 빈 VM 검증용 공식 Ubuntu cloud image의 SHA-256을 확인했으며 사용자가 디스크 이미지를 수동으로 만들거나 Docker를 설치할 필요는 없다.

## 발견하여 수정한 문제

1. Wazuh 4.14.10의 legacy firewall writer는 포트가 없는 ICMP 기록을 JSON archive 전에 탈락시켰다. `analysisd.log_fw=0`으로 legacy writer만 비활성화하여 nftables ICMP 원본을 Manager archive와 C1으로 확인했다. 임의 포트나 탐지 제외를 추가하지 않았다.
2. 약 20 GiB로 늘어난 evidence DB에서 상태 집계와 보존 작업이 payload 테이블을 반복 탐색했다. 상태·보존·원천별 검색 인덱스를 추가하고 설치 중 수집기 시작 전에 스키마를 갱신한다. 수락 검사는 원천별 최근 수신을 조회한다.
3. Docker/containerd가 이름이 바뀐 이전 이미지를 정리하여 복구 이미지가 사라질 수 있었다. 검증본 이미지 ID마다 전용 보존 태그를 유지한다.
4. 복원 뒤 gzip의 inode가 바뀌면 이미 처리한 archive를 다시 읽을 수 있었다. 논리 파일명과 완료 위치를 함께 백업·복원한다.
5. Ubuntu `apt-daily`의 lists lock은 dpkg lock 대기 옵션과 별개였다. 설치 전반에 bounded retry를 적용했다.

## 범위와 후속 게이트

Core 배포 라이선스와 프로젝트 자산의 최종 배포 권리 결정은 ADR0001에 따라 RC에서 명시해야 한다. 외부 Windows 에이전트·M6 실행, 실제 Juice Shop/DVWA 선택 타깃, 모든 kt66 장비 프로파일과 장기간 동시 운영 검증, 상용 콘텐츠/AI 제공자는 이 결과로 완료 처리하지 않는다. 최소 구성의 단기 자원 수치는 SIEM 포함 구성의 권장 사양으로 사용하지 않는다.

실행 명령과 장애 복구: [OPERATIONS](OPERATIONS.md). 권한 계약: [C7](../contracts/C7-ENTITLEMENTS.md). 의존성: [DEPENDENCIES](DEPENDENCIES.md).
