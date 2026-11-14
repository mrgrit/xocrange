# 의존성·권리·배포 경계

검토 기준일: 2026-11-08. 이 목록은 구성과 출처 기록이다. Core 자체의 배포 라이선스는 [ADR 0001](../adr/0001-core-boundaries.md)에 따라 명시적인 출시 결정으로 남긴다. 전체 제품을 하나의 라이선스로 다시 표시하지 않는다.

| 구성 | 공급·고정 방식 | 출처 / 라이선스 확인 위치 |
|---|---|---|
| Ubuntu 26.04·Linux·nftables·auditd | 기반 이미지 digest, 호스트 설치 버전 기록 | 설치 패키지 `/usr/share/doc/*/copyright`; [Ubuntu 소스](https://launchpad.net/ubuntu) |
| Suricata | Ubuntu 패키지, 실제 버전 inventory | [OISF LICENSE](https://github.com/OISF/suricata/blob/main/LICENSE)와 패키지 copyright |
| Apache HTTP Server·ModSecurity·OWASP CRS | Ubuntu 패키지, 실제 버전 inventory | 패키지 copyright와 [Apache](https://httpd.apache.org/), [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity), [CRS](https://github.com/coreruleset/coreruleset) |
| Wazuh Manager/API | 4.14.10, 이미지 digest | [Wazuh LICENSE](https://github.com/wazuh/wazuh/blob/v4.14.10/LICENSE); 구성 라이브러리별 고지 유지 |
| Wazuh Indexer·Dashboard | 4.14.10, 각각 이미지 digest | [Indexer](https://github.com/wazuh/wazuh-indexer), [Dashboard](https://github.com/wazuh/wazuh-dashboard), 이미지 내부 LICENSE/NOTICE |
| osquery·Sysmon Linux | 공식 설치 공급원, 버전 inventory | [osquery](https://github.com/osquery/osquery), [SysmonForLinux](https://github.com/microsoft/SysmonForLinux); 설치 패키지 라이선스 |
| HAProxy | 3.2-alpine 기반 digest | [HAProxy](https://www.haproxy.org/), 이미지 내부 배포판 패키지 고지 |
| Python·OpenSSL·Django·Gunicorn·Pillow | 기반 이미지 digest, Python 정확한 버전·배포 파일 SHA-256 | `requirements.lock`, `components/platform/requirements.lock`, 설치 dist-info/LICENSE 및 OS 패키지 copyright |
| Docker Engine·Compose·containerd | Docker 공식 Ubuntu 저장소, 설치 버전 inventory | [Docker](https://github.com/docker), 설치 패키지 고지 |
| OWASP Juice Shop (`target-juice`) | `bkimminich/juice-shop:v20.3.0` 이미지 digest, 수정 없이 사용 | [MIT](https://github.com/juice-shop/juice-shop/blob/master/LICENSE); 이미지 내부 고지 유지 |
| DVWA (`target-dvwa`) | `vulnerables/web-dvwa` 이미지 digest, 수정 없이 사용 | [GPL-3.0](https://github.com/digininja/DVWA/blob/master/COPYING.txt); 별도 컨테이너 단순 집합, 이미지 내부 고지 유지 |
| xOC 실행 환경 Python 패키지 | `requirements.lock` 해시 고정 | attrs·jsonschema·jsonschema-specifications·PyYAML·referencing·rpds-py·pip: MIT, bcrypt: Apache-2.0 |
| 플랫폼 Python 패키지 | `components/platform/requirements.lock` 해시 고정 | Django·asgiref·sqlparse: BSD-3-Clause, gunicorn: MIT, Pillow: MIT-CMU |
| Wazuh 색인 템플릿(`components/siem-ui/wazuh-template.json`) | 상류 파일을 바꾸지 않고 포함 | GPL-2.0, Wazuh, Inc.; [원문](../licenses/WAZUH-GPL-2.0.txt), `docs/provenance/wazuh-native-sources.json`. PolyForm 적용 대상 아님 |
| kt66·콘솔 생성기·로고·공간 SVG | 선별 코드와 변경본, 출처별 SHA-256 | `docs/provenance/` 및 `assets/branding/provenance.json`; 소유자가 Core와 같은 조건으로 배포 허락(2026-11-14, NOTICE) |

현재 번들은 Core 사용 가이드 4종과 소유자가 공개 범위를 지정한 PPT 1–339쪽 및 해당 REV01 해설이다. 출처와 범위는 `contents/academy/wazuh-threat-hunting/source-map.json`에 기록한다. Pillow 12.3.0은 설치 배포물의 MIT-CMU 고지와 포함 코덱의 개별 고지를 유지한다. 유료 교재·시나리오, Windows 설치/평가판 이미지, 발급 개인키, 레지스트리 암호를 포함하지 않는다. tw2는 기능과 구조 참조이며 저장소 전체를 배포하지 않는다. 새 콘텐츠 번들은 별도 출처·공개 범위 manifest를 갖춰 추가한다.

`NOTICE`를 설치 소스에 포함한다. 설치기는 선택된 이미지의 ID·RepoDigests, 기반 FROM digest, 호스트/컨테이너 패키지와 Python 버전을 `/var/lib/xocrange/release-inventory.json`에 기록한다. 라이선스 원문은 upstream 이미지·패키지의 원래 위치에 유지한다. 외부 배포를 위한 전체 소스 제공·고지 묶음과 프로젝트 자산 권리 확정은 K12 출시 게이트에서 대조한다.

## RC 라이선스 대조 (2026-11-14)

새 VM 설치본의 `release-inventory.json`과 위 표를 대조했다.

- 기반 이미지 9개(Juice Shop, HAProxy, Python 3.12 alpine/slim, Ubuntu 26.04, DVWA, Wazuh Manager/Indexer/Dashboard 4.14.10) 모두 표에 있다.
- Python 패키지: xOC 실행 환경 9개, 플랫폼 이미지 5개의 라이선스를 설치 메타데이터로 확인했다. 모두 허용형(MIT·Apache-2.0·BSD-3-Clause·MIT-CMU)이다.
- copyleft 구성요소(Linux·nftables·Suricata·Wazuh·DVWA)는 상류 이미지·배포판 패키지를 별도 컨테이너로 쓰고, 이미지를 배포하지 않고 설치 서버에서 공개된 Dockerfile로 빌드한다. 상류 코드 변경은 Wazuh Dashboard의 TLS 검증 한 줄뿐이며 Dockerfile과 provenance에 공개돼 있다.
- 저장소에 그대로 포함한 서드파티 파일은 Wazuh 색인 템플릿 하나(GPL-2.0, 원문 동봉)이며 NOTICE에 따로 적었다.
- 설치본 inventory의 `distribution_license`가 결정 전 값(`pending-explicit-release-decision`)으로 남던 것을 결정한 라이선스로 고쳤다.

컨테이너 안 배포판 패키지(수백 개)의 개별 고지는 각 이미지의 `/usr/share/doc/*/copyright`(Ubuntu·Debian)와 RPM 메타데이터(Wazuh Dashboard, Amazon Linux)에 상류 그대로 남아 있다.

APT의 변경 가능한 패키지 저장소까지 동결하지는 않는다. 소스에서 재빌드한 이미지의 동일성을 주장하지 않으며, 실행된 이미지의 동일한 복구는 보존한 이미지 ID와 이미지 포함 백업으로 확인한다.
