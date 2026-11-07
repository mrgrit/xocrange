# 보안 경로 분리 · 두 번째 구현

기준일: 2026-11-07. 범위는 K01 보존 확장, K02 의존성 분석, K04 계획기 확장과 K05 실험 구성을 준비하는 단계다. 실제 VM 패킷 경로 검증은 대기 중이다.

## 완료한 작업

| 항목 | 결과 |
|---|---|
| 기존 구성 조사 | kt66 33서비스의 의존성·이미지 입력·마운트·네트워크·환경변수 이름, 웹 프록시 연결 65개 |
| 보존 확장 | 보안 경로 관련 30개 파일을 `.local/`에 원본 바이트·해시로 보존 |
| 실행 단위 분리 | fw/ips/web Dockerfile·entrypoint·규칙·WAF 설정을 별도 구성 |
| IPS 경로 | 기존 수집 실행과 구분하여 양방향 NFQUEUE 경로 및 검증용 drop 룰 작성 |
| 선택 타깃 | manifest의 `http_targets`로 현재 선택한 backend만 WAF vhost·링크·시작 의존성에 반영 |
| 권한·주소 검사 | 장비별 capability, 고정 경로, IPAM·정적 IP 충돌과 주소 유효성 검사 |
| 실험 명령 | `lab check/up/verify/down`, 입력 무결성·전용 VM 검사·C1 증거 기반 검증 |
| 호스트 기준 | 사용자 결정에 따라 Ubuntu Server 26.04 LTS x86_64 |

기존 source 분석에서 장비 이미지에 결합된 SSH·콘솔·Wazuh·osquery·평가 수집을 확인했다. 이번 Core 실행 파일은 필요한 경로 동작을 별도 작성했고, 기존 GUI/AI/평가 코드를 통째로 복사하지 않았다. 원본 스냅샷은 공개 파일 집합에 포함하지 않는다.

## 로컬 검증

- **103개 테스트 통과**: 기존 C1·CLI·설치 검사와 신규 선택 타깃·권한·IP·VM 실행 방어 검사.
- 기본 보안 경로 및 fixture를 포함한 Compose의 Docker 문법 검사 통과.
- entrypoint의 Bash 구문과 Python 파일 구문 확인.
- wheel 빌드 및 별도 venv 설치 후 보안 경로 계획 생성 확인.
- 현재 개발 환경에서 `lab check`가 실행 조건 미충족을 반환함을 확인. Docker daemon 작업이나 호스트 네트워크 변경은 수행하지 않았다.

## 실제 검증 대기

현재 세션에서는 Docker daemon에 접근할 수 없고 별도 VM 접속 정보가 아직 없다. 따라서 **Ubuntu 26.04 이미지 빌드, 실제 Apache/Suricata/nftables 기동, 차단·우회·출처 보존 검증은 아직 수행하지 않았다.** 작성된 Dockerfile과 검증 코드가 존재한다는 사실을 통합 검증 통과로 간주하지 않는다.

`security-path`는 `experimental`이고 `--allow-experimental` 없이는 계획을 생성하지 않는다. `community-security` 전체는 SIEM·콘솔·UI 등 계획 단계 기능이 남아 있어 계속 설치 완료 대상으로 표시하지 않는다. CI 역시 `workflow` 권한 확보 전까지 비활성 템플릿 상태다.

## 다음 실행

새 VM에서 [실행 절차](SECURITY-PATH-LAB.md)에 따라 빌드·통신 검증을 수행하고 실패를 수정한다. 검증 결과를 받은 뒤 해당 상태와 측정값을 기록한다. 이후 K06의 지속 수집·원본 보관·중복 제거·SIEM 저장으로 연결한다.
