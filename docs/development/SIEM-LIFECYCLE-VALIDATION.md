# SIEM 재설치·재부팅·장애 검증

[검증 도구](../../tests/integration/siem_lifecycle.py)는 설치된 SIEM 구성의 데이터 보존을 확인한다. 정식 Manager가 포함된 릴리스에서는 원본 Wazuh 경보와 Manager API 사용자도 대조한다. 전체 Wazuh 기능의 호환 검증을 대신하지 않으므로 [로드맵 상태](ROADMAP-STATUS.md)와 [통합 범위](WAZUH-NATIVE.md)를 함께 본다.

제품 사용자는 `install.sh` 한 번으로 설치한다. 아래는 개발·배포 수용 검사를 위한 절차이며 Docker나 pytest를 제품 사용자에게 별도로 설치하도록 요구하지 않는다. 테스트 스크립트는 설치 소스 스냅샷에서 제외되므로 개발 체크아웃에서 실행한다.

## 준비와 기준 상태

xOC 설치기가 관리하는 Ubuntu 26.04 전용 VM에서 관리자 권한으로 실행한다. 현재 설치가 성공했고 SIEM UI가 선택되어 있어야 하며, 다른 프로젝트가 실행 중이면 거부한다. 설치기의 실행 잠금을 함께 사용하므로 설치 진행 중에는 테스트가 시작되지 않는다.

아래 명령은 해당 개발 체크아웃의 루트에서 root 셸로 실행한다. `xoc_test_python`은 현재 설치된 release의 실행 환경이다. 새로운 run ID를 사용하면 이전 검증 증거를 보존할 수 있다.

```bash
xoc_release=$(readlink -f /opt/xocrange/current)
xoc_test_python=/opt/xocrange/venvs/${xoc_release##*/}/bin/python
"$xoc_test_python" tests/integration/siem_lifecycle.py checkpoint \
  --run siem-20261107 --isolated-vm
```

checkpoint는 8종마다 Wazuh 확인·색인이 끝난 이벤트 3개, 총 24개를 선택한다. 원본 byte의 SHA-256, C1 문서 hash, 검색 저장소의 일치·중복 여부를 확인한 뒤 자격 증명·CA hash, 현재 boot ID, 설치 실행 기록과 전용 saved search를 기록한다. 원본 내용과 비밀번호 자체를 checkpoint에 복사하지 않는다.

정식 Manager 구성에서는 8종에 연결된 원본 Wazuh 경보 24개도 별도로 기록한다. Manager CA·자격 증명 hash를 보관하고 역할 없는 전용 API 사용자를 만들어 RBAC DB 보존을 확인한다. 이 사용자의 임의 비밀번호는 출력하거나 저장하지 않는다.

상태는 `/var/lib/xocrange/validation/siem-lifecycle/`의 0700 디렉토리와 0600 파일에 저장한다. 같은 이름의 checkpoint는 덮어쓰지 않는다. hash·증거 ID도 관리자 전용으로 취급하며 공개 보고서에는 일치 여부와 개수만 담는다.

## 같은 소스로 재설치

checkpoint와 같은 설치 소스로 재실행한다. 테스트 파일만 추가된 체크아웃은 설치 소스 해시가 달라지지 않는다. README·런타임 소스가 달라진 경우에는 다른 릴리스이므로 이 검사의 대상이 아니다.

```bash
bash install.sh
"$xoc_test_python" tests/integration/siem_lifecycle.py verify \
  --run siem-20261107 --after reinstall --isolated-vm
```

다른 설치 실행 기록이 없으면 실패한다. 실제 보안 경로 15개·8종 새 이벤트·HTTPS/WAF 수용 검사를 다시 실행하고 수집기 상태 회복을 기다린다. 그 후 비밀번호·CA·사용자 saved object·24개 원본·C1·검색 문서와 중복 여부를 대조한다. 이전 설치가 남긴 성공 JSON만으로 통과하지 않는다.

## 실제 재부팅

재부팅은 검증자가 별도로 실행한다. 테스트 도구가 임의로 재부팅하지 않는다. SSH 연결이 돌아온 뒤 개발 체크아웃에서 같은 변수를 다시 설정하고 실행한다.

```bash
# 검증용 VM에서 실행
systemctl reboot

# 재접속 후 개발 체크아웃으로 이동하고 실행
xoc_release=$(readlink -f /opt/xocrange/current)
xoc_test_python=/opt/xocrange/venvs/${xoc_release##*/}/bin/python
"$xoc_test_python" tests/integration/siem_lifecycle.py verify \
  --run siem-20261107 --after reboot --isolated-vm
```

boot ID가 달라져야 재부팅 검증으로 인정한다. 재설치와 동일한 실제 검사를 반복하며 Core와 collector 서비스의 기동도 확인한다. 아직 색인 중인 데이터는 성공 처리하지 않고, 기본 240초 안에 수집 상태가 회복되지 않으면 실패를 기록한다. 장기 누적 복구는 `--timeout`을 최대 900초까지 명시할 수 있다.

## Indexer 중단과 복구

이 검사는 Indexer를 일시 중단하므로 웹 검색이 잠시 불가능해진다. 건강한 Indexer에서 시작하며 해당 설치의 Indexer만 중단·시작한다.

```bash
"$xoc_test_python" tests/integration/siem_lifecycle.py outage \
  --run siem-20261107 --isolated-vm
```

실제 수집이 지속되는 동안 Wazuh 분석을 마치고 색인 대기 중인 이벤트 100건과 Indexer 오류 상태를 확인한다. 재기동 후 100건이 검색되고 중복이 없어야 통과한다. 검사 오류가 나도 `finally`에서 재기동을 시도한다. Docker 자체 장애로 복구 명령이 실패할 경우 결과는 실패이며 별도 운영 복구가 필요하다.

정식 Manager 구성에서는 원본 경보도 100개가 대기했다가 각각 한 번씩 검색되는지 별도로 검사한다.

## 결과와 정리

보고서는 run ID·작업·시각별로 새 파일에 기록한다. 실패 보고서도 남긴다. 재설치·재부팅을 성공했다고 선언하려면 해당 동작의 `status=passed`가 있어야 한다. 브라우저 회귀는 [별도 도구](../../tests/browser/siem.py)로 실행한다.

```bash
"$xoc_test_python" tests/integration/siem_lifecycle.py cleanup \
  --run siem-20261107 --isolated-vm
```

정리는 checkpoint에 기록된 테스트용 saved search와 전용 Manager API 사용자만 삭제한다. 사용자 ID와 전용 이름이 현재 API 응답과 일치해야 삭제한다. 원본·C1·검색 색인·설치 계정·CA·볼륨·checkpoint·보고서는 보존한다. 다른 릴리스나 프로젝트의 checkpoint는 정리에 사용할 수 없다.
