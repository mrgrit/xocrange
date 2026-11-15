# xOC Range Core Community 사용자 안내

교수자·운영자가 xOC Range Core를 설치하고 수업에 쓰기 위한 안내다. 개발·검증 기록은 [docs/development](development/)에 있다.

## 1. 준비

| 항목 | 요구 사항 |
|---|---|
| 운영체제 | Ubuntu Server 26.04 LTS, amd64. xOC만 쓰는 **전용 VM 또는 서버** |
| CPU | 2 vCPU 이상(설치 사전 검사 기준). 수업용 권장은 [9절](#9-권장-사양) |
| 메모리 | SIEM 대시보드 포함 8 GiB 이상, `--without siem-ui`이면 4 GiB 이상 |
| 디스크 | 데이터 경로 여유 20 GB 이상. SIEM을 쓰면 [9절](#9-권장-사양)의 디스크 권장치를 따른다 |
| 네트워크 | 설치 중 인터넷 접속(패키지·이미지 다운로드. 아카데미 콘텐츠는 소스에 포함). 학습자 PC에서 서버의 443/80 포트 접속 |

다른 Docker 컨테이너나 서비스가 이미 돌고 있는 서버에는 설치하지 않는다. 설치기는 남의 컨테이너·데이터를 지우지 않고 중단한다.

## 2. 설치

```bash
git clone https://github.com/mrgrit/xocrange.git
cd xocrange
sudo bash install.sh
```

Docker를 포함한 필요한 패키지를 설치기가 설치하고, 설치한 뒤 실제 통신·차단·로그 수집을 검사한다. 새 VM에서 7~10분 걸린다. 검사가 하나라도 실패하면 비정상 종료하고 실패 단계와 로그 위치(`/var/log/xocrange/install-*.log`)를 보여 준다.

기본 설치에 포함되는 것:

- 보안 경로: 방화벽(nftables) → IPS(Suricata) → WAF(Apache·ModSecurity) → 검증용 타깃
- 장비 콘솔 3종(방화벽·IPS·WAF), Core 관리 화면, 데이터센터·운영 개요·NOC 2층
- SIEM: 8종 로그 수집, Wazuh 분석, 대시보드(Wazuh Dashboard, 검색·시각화)
- 호스트 로그 수집(엔드포인트 모니터링): osquery·Sysmon·auditd
- 아카데미(교재·실습 노트)

자주 쓰는 설치 옵션:

```bash
sudo bash install.sh --public-host xoc.school.example   # 브라우저에서 쓸 DNS 이름 또는 IP
sudo bash install.sh --without siem-ui                  # 메모리가 작을 때: SIEM 대시보드만 제외
sudo bash install.sh --data-dir /srv/xoc-data           # 미리 마운트한 별도 데이터 디스크
bash install.sh --dry-run                               # 바꾸지 않고 작업 순서만 확인
```

## 3. 처음 접속

서버 터미널에서 접속 정보를 확인한다.

```bash
sudo xoc platform credentials    # Core 관리 화면: https://서버주소/core/  (계정 admin)
sudo xoc siem credentials        # SIEM 대시보드: https://서버주소/siem/  (Core와 별도 계정)
```

1. 브라우저에서 `https://서버주소/core/`를 연다.
2. 처음 로그인하면 초기 비밀번호를 바꿔야 한다. 바꾼 비밀번호는 위 명령으로 다시 볼 수 없으니 따로 보관한다.
3. **관리자 계정을 하나 더 만든다**(사용자 관리). 비밀번호 재설정 명령이 아직 없어서, 관리자 비밀번호를 잊으면 다른 관리자가 바꿔 줘야 한다.

인증서 경고를 없애려면 서버의 `/etc/xocrange/ca.crt`를 학습자·교수자 PC에 "신뢰할 수 있는 루트 인증 기관"으로 한 번 등록한다.

계정 역할은 관리자(전체), 운영자(장비 정책 미리보기·적용), 조회자(보기만)다. 로그인은 계정마다 15분 동안 **실패 10회**까지 허용한다. 넘으면 그 계정은 15분 뒤에 다시 로그인할 수 있다. 성공한 로그인은 세지 않는다.

## 4. 수업에서 쓰기

| 하고 싶은 것 | 위치 |
|---|---|
| 전체 구성과 장비 상태 보기 | Core → 데이터센터(2층에서 랙 → 장비) |
| 방화벽·IPS·WAF 정책 보기·바꾸기 | Core → 장비 콘솔(`#fw`, `#ips`, `#waf`). 적용하려면 관리자가 **접근 제어 → 쓰기 허용**을 켠다 |
| 공격·차단 로그 분석 | SIEM 대시보드(`/siem/`) 또는 `sudo xoc siem query --source suricata --confirmed` |
| 교재와 실습 노트 | Core → 아카데미(6층). 차시마다 실습 노트가 자동 저장된다 |

장비 정책 변경은 미리보기 → 적용 순서이며, 모든 변경이 감사 기록에 남고 이전 상태로 되돌릴 수 있다.

### 실습 타깃 추가 (Juice Shop · DVWA)

```bash
sudo xoc module add target-juice
sudo xoc module add target-dvwa
sudo xoc platform targets        # 학습자 PC hosts 파일에 넣을 한 줄
```

학습자 PC의 hosts 파일(또는 기관 내부 DNS)에 출력된 줄(`서버IP juice.xoc.range dvwa.xoc.range`)을 넣고 `https://juice.xoc.range/`로 접속한다. 요청은 모두 방화벽 → IPS → WAF를 지나며 SIEM에 기록된다.

### 수업 전 초기화

이전 수업의 경보가 새 분석에 섞이지 않도록 수업 전에 SIEM과 장비 로그를 비운다.

```bash
sudo xoc siem clear          # 지울 양만 보여 준다
sudo xoc siem clear --yes    # 실제로 지운다
```

SIEM 수집 이벤트·검색 색인·Wazuh 경보·방화벽/IPS/WAF 로그를 지운다. 계정·장비 정책·감사 기록·학습자 실습 노트·대시보드는 남는다. **되돌릴 수 없으므로** 남겨야 할 기록이 있으면 먼저 백업한다.

## 5. 상태 확인

```bash
sudo xoc siem status                                        # "status": "ready"이면 정상
systemctl status xocrange-core xocrange-collector           # 서비스 상태
sudo xoc lab verify --plan "$(sudo python3 -c "import json;print(json.load(open('/var/lib/xocrange/last-install.json'))['plan'])")" --isolated-vm
```

`xoc siem status`의 `degraded`는 수집이 밀리거나, 손상된 입력이 격리됐거나, 센서가 멈춘 상태다. `sources`에서 `ready`가 아닌 항목을 본다.

| 표시 | 뜻과 조치 |
|---|---|
| `disk_reserve` | 디스크 여유가 2 GiB 미만이라 수집을 멈췄다. 공간을 확보하면 멈춘 동안의 로그까지 이어서 수집한다 |
| `logging_suspended`(sensor-auditd) | 디스크가 찼을 때 auditd가 기록을 멈췄다. 공간이 돌아오면 1~2분 안에 자동으로 다시 시작한다. 멈춘 동안의 감사 기록은 남지 않는다 |
| `quarantined` 증가 | 해석할 수 없는 입력(예: 디스크가 찬 순간 잘린 로그 줄)을 원본째 격리했다. 보존 기간(1일)이 지나면 사라진다 |
| `lagging`(host-sysmon) | 호스트 로그(Sysmon)가 많아 2분 이상 뒤처졌다. 대개 저절로 따라잡는다 |

## 6. 백업·업데이트·복구

```bash
sudo xoc backup create /var/lib/xocrange/backups/before-semester
sudo xoc backup verify /var/lib/xocrange/backups/before-semester
sudo xoc backup restore /var/lib/xocrange/backups/before-semester

cd ~/xocrange && git pull
sudo xoc update --source "$PWD"     # 실패하면 이전 상태로 자동 복원
sudo xoc recover                    # 정전·중단 뒤 남은 작업 정리
```

백업에는 비밀번호·키·로그가 들어 있으니 root만 읽을 수 있게 보관하고 외부에 올리지 않는다. 업데이트는 서비스를 잠시 멈추고 복구 지점을 만든 뒤 진행하며, 검사에 실패하면 이전 설정·데이터·이미지로 되돌린다.

업데이트·재설치의 복구 지점은 `/var/lib/xocrange/backups/before-install-<시각>-<번호>`에 생기며 설치 상태 전체(주로 SIEM DB)를 복사하므로 SIEM DB 크기만큼 디스크를 쓴다. 성공하면 방금 만든 것 하나만 남기고 이전 복구 지점은 자동으로 지운다. `xoc backup create`로 직접 만든 백업(다른 이름)은 지우지 않으므로 필요 없어진 것은 직접 정리한다(`sudo du -sh /var/lib/xocrange/backups/*`).

2026-11-15 이전 개발 버전을 `git clone`으로 설치했다면 아카데미 콘텐츠를 내려받던 `contents/` 폴더가 저장소에 새로 포함된 같은 경로와 겹쳐 `git pull`이 멈춘다. `mv contents ../contents.old` 후 `git pull`, `python3 scripts/verify-contents.py`로 확인하고 업데이트한다. 저장소 파일을 직접 고친 적이 있으면 먼저 `git stash`로 보관한다.

## 7. 문제 해결

| 증상 | 확인 |
|---|---|
| 설치 실패 | 출력된 단계와 `/var/log/xocrange/install-*.log`, `sudo cat /var/lib/xocrange/last-install.json` |
| 접속 안 됨 | 서버 IP·방화벽(443/80), `--public-host` 값, `systemctl status xocrange-core` |
| 브라우저 인증서 경고 | `/etc/xocrange/ca.crt`를 PC에 신뢰 등록 |
| 로그인 거부(잠시 후 다시) | 실패 10회로 15분 잠김. 기다리거나 다른 관리자가 비밀번호를 바꿔 준다 |
| 타깃 주소가 열리지 않음 | 학습자 PC hosts 파일, `sudo xoc platform targets` 출력 |
| SIEM에 로그가 안 보임 | `sudo xoc siem status`의 `sources`, 디스크 여유(`df -h`) |

## 8. 지원 범위와 제한

- 단일 서버·단일 기관용이다. 여러 반을 서로 격리하는 다중 사용자 기능, 공방전·자동 채점, AI 에이전트는 Community에 없다(유료 모듈 범위).
- Core 화면은 정답을 보여 주지 않고 채점하지 않는다. 실습 노트는 기록으로만 보관한다.
- SSH 실습(`ssh-lab`)과 platform만 설치하는 `bootstrap` 단독 구성은 이번 RC에 없다.
- 관리자 비밀번호 재설정 명령이 없다(관리자 2명 이상 권장).
- 학습자 타깃 이름(`*.xoc.range`)은 공개 DNS가 아니라 hosts 파일·기관 DNS로 쓴다.

## 9. 권장 사양

| 구성 | 측정 근거 | 권장 |
|---|---|---|
| SIEM 제외 최소 구성 | 2 vCPU·4 GiB 빈 VM 설치·검증, RAM 사용 약 0.9 GiB | 2 vCPU·4 GiB·디스크 40 GB |
| 기본 구성(SIEM·대시보드 포함) | 8 vCPU·15 GiB 새 VM에서 설치·재부팅·수용 검사 통과. 초당 2건 요청 15분: 메모리 최대 5.2 GiB, CPU 최대 3.2%(약 0.26코어) | 4 vCPU·16 GiB·디스크 100 GB 이상 |
| 기본 구성 24시간 연속 운영 | 메모리 최대 6.0 GiB(평탄), 수집 지연 최대 9초, SIEM 저장 최대 17.6 GiB(DB 1일·회전 로그 2일·인덱스 7일 보존). [기록](development/LONGRUN-2026-11-14.md) | 디스크 100 GB 이상, 최소 60 GB |

메모리 8 GiB에서도 설치·동작은 하지만 여유가 작다. 이미지 빌드와 업데이트 때 CPU를 많이 쓰므로 4 vCPU를 권장한다. 디스크 100 GB는 SIEM DB가 기본 상한(32 GiB)까지 차고 업데이트 때 같은 크기의 복구 지점이 생기는 경우까지 수용한다. 60 GB로 운영하면 `/var/lib/xocrange/siem/retention.json`의 `database_bytes`를 낮춘다([보존 설정](development/SIEM.md#보존과-복구-설정)). 24시간 측정은 다수 학습자 동시 사용 부하가 아니다.

## 10. 라이선스

xOC Range Core는 [PolyForm Noncommercial 1.0.0](../LICENSE)과 [교육용 추가 허락](../LICENSE-EDUCATION.md)으로 배포한다. 학교·대학의 수업·실습·교내 훈련과 개인 학습은 무료다. 상업 용도는 별도 상용 라이선스가 필요하다. 서드파티 구성요소는 각자의 라이선스를 따른다([NOTICE](../NOTICE)).
