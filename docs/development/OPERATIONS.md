# 설치 구성 변경·백업·복구

Ubuntu 26.04 amd64 전용 VM에서 실행한다. 모든 변경 명령은 설치·백업·복구 공통 잠금을 사용한다. 작업 중 두 번째 변경은 거부된다. 설치기는 선택한 구성의 검증까지 끝나야 새 릴리스를 현재 버전으로 기록한다.

## 모듈과 업데이트

```bash
sudo xoc module list
sudo xoc module add noc --preview
sudo xoc module add noc
sudo xoc module add --package /절대경로/모듈패키지 --preview
sudo xoc module add --package /절대경로/모듈패키지
sudo xoc module remove noc
sudo xoc update --source /절대경로/새소스 --preview
sudo xoc update --source /절대경로/새소스
```

패키지는 `module.yaml`, Compose, manifest에 명시한 빌드 입력으로 구성한다. 심볼릭 링크·미등록 파일·128 MiB 초과 패키지는 받지 않는다. 의존 기능이 남아 있으면 제거를 거부한다. platform·security-path·management와 현재 수용 검사용 fixture는 필수다. 제거한 모듈의 데이터 볼륨은 보존하며, 메뉴·API 등록·컨테이너는 선택 구성에서 빠진다. 재포함하면 보존한 설정과 데이터를 사용한다.

업데이트는 기존 선택 구성을 유지한다. 다운로드·소스/의존성 검사를 거친 뒤 서비스를 정지하고 일관된 복구 지점을 만든다. 빌드·기동·실제 통신 검사 중 실패하면 이전 설정·DB·이미지·서비스로 복원한다. 실패한 시도의 로그는 `last-attempt.json`과 설치 로그에 남는다. 복원 직전의 변경 데이터는 `/var/lib/xocrange/failed-state/`에 보존한다. 설치·업데이트·모듈 변경이 성공하면 이번 작업의 복구 지점(`backups/before-install-*`) 하나만 남기고 이전 설치 전 복구 지점을 삭제한다. 미완료 작업 저널이 가리키는 복구 지점과 `xoc backup create`로 만든 수동 백업은 삭제하지 않는다.

## 백업

```bash
sudo xoc backup create /var/lib/xocrange/backups/manual-001
sudo xoc backup verify /var/lib/xocrange/backups/manual-001
sudo xoc backup restore /var/lib/xocrange/backups/manual-001
```

새 디렉토리를 지정한다. 기본 백업에는 소스·Python 실행 환경·공통 계정 DB·장비 설정·SIEM 증거 DB·Wazuh/Indexer 데이터·설치한 이미지가 포함된다. 암호·키·기관 데이터도 들어가므로 디렉토리 0700, 파일 0600으로 보관한다. 공개 저장소에 올리지 않는다. 백업 동안 서비스가 중지되고 끝나면 기존 활성 서비스를 재기동한다. 시간과 추가 디스크는 실제 저장 데이터에 비례한다.

복원은 모든 파일의 크기·SHA-256·아카이브 경로를 검증한 뒤 실행한다. 기본 복원은 현재 상태도 먼저 백업한다. 다른 호스트로 옮길 때에는 백업 전체 디렉토리를 소유자 root와 권한을 유지해 복사하고, 원래와 같은 데이터 경로로 설치한다.

```bash
sudo bash install.sh --data-dir /var/lib/xocrange/data --restore /보관위치/백업
```

`--data-dir`에는 백업 manifest의 `installation.data_directory` 값을 사용한다. 복원 후 관리 주소·인증서는 백업 당시 값이다. 네트워크 주소를 바꿨다면 해당 주소로 `install.sh --public-host 새주소`를 다시 실행한다. OS 전체 이미지나 임의 호스트 파일을 복구하는 도구는 아니다. OS·Docker 패키지의 다운그레이드는 수행하지 않는다.

중단 또는 전원 장애 후에는 다음 명령으로 저장된 복구 지점을 재실행한다.

```bash
sudo xoc recover
sudo systemctl status xocrange-core xocrange-collector
sudo xoc siem status
```

`/var/lib/xocrange/install-operation.json` 및 `restore-operation.json`에 작업 단계와 복구 지점이 남는다. 완료되지 않은 백업은 복구 지점으로 인정하지 않는다. 공간 부족은 서비스 정지 전 검사하며, 백업 도중 쓰기 실패가 나도 기존 서비스를 재기동한다.

## 이미지·로그·용량

각 계획의 `images.lock.json`과 `compose.images.yaml`은 실제 빌드한 이미지 ID를 고정한다. 재부팅은 이 이미지만 사용한다. 이전 버전은 내용 해시별 `xocrange-retained/*` 태그로 보존하여 새 빌드의 태그 교체 후에도 복구할 수 있다. 자동 이미지 정리는 하지 않는다. 복구 지점과 관련 이미지를 삭제하기 전에 별도 보관본을 확인한다.

`/var/lib/xocrange/release-inventory.json`에는 소스 해시·이미지 ID/digest·호스트 및 컨테이너 패키지 버전이 기록된다. 기반 이미지와 Python 의존성은 digest/해시로 고정한다. 배포판 APT 저장소의 패키지는 빌드 시점에 따라 달라질 수 있다. 동일 실행 이미지 복원에는 이미지 포함 백업을 사용한다.

원천 로그는 크기 기준으로 회전한다. 24시간이 지난 파일도 수집기가 끝까지 읽지 않았거나 프로세스가 열고 있으면 지우지 않는다. journald에는 2 GiB 상한·2 GiB 여유 공간·7일 보존을 설정한다. SIEM DB·색인의 별도 보존 예산과 미확인 증거 보존 정책은 [SIEM](SIEM.md)을 따른다. 장애가 지속되면 용량 부족 전에 경보와 백업을 확인해야 한다.

측정 도구: `sudo python3 scripts/measure-appliance.py --seconds 3600 --load --output /비공개경로/resources.json`. 실제 자원 측정과 새 VM 수용 결과는 [K10·K11 검증](K10-K11-VALIDATION.md)에 기록한다.
