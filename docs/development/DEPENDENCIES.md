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
| kt66·콘솔 생성기·로고·공간 SVG | 선별 코드와 변경본, 출처별 SHA-256 | `docs/provenance/` 및 `assets/branding/provenance.json`; 프로젝트 자산의 배포 권리 확인은 RC 게이트 |

현재 번들은 Core 사용 가이드 4종과 소유자가 공개 범위를 지정한 PPT 1–339쪽 및 해당 REV01 해설이다. 출처와 범위는 `contents/academy/wazuh-threat-hunting/source-map.json`에 기록한다. Pillow 12.3.0은 설치 배포물의 MIT-CMU 고지와 포함 코덱의 개별 고지를 유지한다. 유료 교재·시나리오, Windows 설치/평가판 이미지, 발급 개인키, 레지스트리 암호를 포함하지 않는다. tw2는 기능과 구조 참조이며 저장소 전체를 배포하지 않는다. 새 콘텐츠 번들은 별도 출처·공개 범위 manifest를 갖춰 추가한다.

`NOTICE`를 설치 소스에 포함한다. 설치기는 선택된 이미지의 ID·RepoDigests, 기반 FROM digest, 호스트/컨테이너 패키지와 Python 버전을 `/var/lib/xocrange/release-inventory.json`에 기록한다. 라이선스 원문은 upstream 이미지·패키지의 원래 위치에 유지한다. 외부 배포를 위한 전체 소스 제공·고지 묶음과 프로젝트 자산 권리 확정은 K12 출시 게이트에서 대조한다.

APT의 변경 가능한 패키지 저장소까지 동결하지는 않는다. 소스에서 재빌드한 이미지의 동일성을 주장하지 않으며, 실행된 이미지의 동일한 복구는 보존한 이미지 ID와 이미지 포함 백업으로 확인한다.
