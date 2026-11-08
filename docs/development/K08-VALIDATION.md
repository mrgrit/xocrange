# K08 콘솔 초안 검증 · 2026-11-08

사용자 요청에 따라 기존 교육용 콘솔을 운영 화면으로 정리했다. 방화벽은 FORWARD 필터 정책을 기본으로, 주소·서비스 객체·NAT·전체 규칙·이벤트·변경 이력을 각각 탭으로 분리했다. IPS/WAF도 같은 탐색 구조와 오른쪽 편집 패널을 사용한다. 기존 규칙 생성기를 재사용하며 실제 장비 검증·적용·복원까지 연결했다.

검증 소스 SHA-256은 `c9dcc1f784e21f39d31bbb7b925227cbd39488db0218bee39842eeff1c87696e`이다. [공개 실행 결과](../provenance/k08-console-acceptance.json)에 파일별 해시·검사 결과를 기록한다. 비밀번호·검토 토큰·세션 쿠키는 포함하지 않는다.

| 검증 | 결과 |
|---|---|
| 단위·계약·CLI·권한·입력/버전/복원 | 개발 호스트 301개, Ubuntu 26.04 VM 301개 통과 |
| 설치·보안 경로 | 실제 nftables→Suricata→ModSecurity 15개 통과 |
| 공통 관리·SIEM | 관리 설치 검사 6개, 새 C1 8종/native receipt 8종, SIEM HTTPS/WAF/검색 52개 통과 |
| 장비 콘솔 실통신 | 실제 정책 적용·트래픽 차단·관리 경로·인증된 Wazuh Manager 조회·복원·문법 오류·쓰기 잠금·변조/오래된 검토 거부 등 51개 통과 |
| 실제 컨테이너 재시작 | 비어 있지 않은 3종 정책·버전·세션 보존, 재시작 후 IPS/WAF 차단, 정상 트래픽·후속 검증·시험 정책 제거 16개 통과 |
| 실제 브라우저 | 기본 FORWARD 화면·전체 규칙 탭 분리·3개 편집기·실제 configtest·관리 화면·세션·모바일 overflow 검사 19개 통과 |
| 기존 Wazuh 편집 회귀 | native 규칙 CRUD·설정 검증·logtest·잘못된 XML 보존·익명/다른 필드 차단 17개 통과 |

장비 차단 시험 중에도 Core 세션과 Wazuh Manager 상태 조회가 유지됐다. WAF 탐지 패턴의 XSS 문자열과 IPS/WAF의 SQLi·경로 탐색·명령 문자열은 검토할 수 있으며, 정책 이름의 공격 문자열은 계속 차단된다. 예외는 실제 관측한 CRS ID와 정확한 preview 경로·JSON 탐지 필드에만 적용했다.

검증 과정에서 nftables의 닫는 괄호 줄 구분, Ubuntu 26.04의 `suricatasc` 소켓 위치 인자, Suricata content 안의 세미콜론 표현을 수정했다. 잘못된 실제 엔진 문법은 실행 중인 정책을 바꾸지 않고 거부했다. 시험용 정책과 미적용 검토는 제거했고, 장비 쓰기 잠금은 원래대로 복구했다. 감사·변경 이력은 보존했다.

최종 상태에서 collector는 ready, 재시작 0회, 입력/분석 격리와 native 입력 오류 0건이었다. 새 로그는 계속 수집 중이며 가장 오래된 대기는 7초였다.

## 실제 화면

화면은 위 VM의 실제 로그인과 장비 응답으로 촬영했다. 편집/검토 화면의 입력은 적용 전 초안이며, 예시 정책을 실행 중인 것처럼 표시하지 않는다.

- [방화벽 기본 화면](../images/k08/firewall.png)
- [방화벽 정책 편집](../images/k08/firewall-editor.png) · [변경 검토](../images/k08/review.png)
- [IPS 편집](../images/k08/ips-editor.png) · [WAF 편집](../images/k08/waf-editor.png)
- [모바일 화면](../images/k08/mobile.png)

## 범위

이번 결과는 사용자 피드백을 받을 K08 초안이다. 관리 경로와 시스템 기본 정책을 보호하는 고정 장비 프로파일이며, 임의 INPUT/OUTPUT·시스템 체인 편집은 제공하지 않는다. 콘솔 선택 해제 시 영속 정책 마운트 유지와 API 제외는 계획 검사로 검증했다. 전체 모듈 제거/실패 복원과 장기 동시 부하는 K10/K11에서 추가 검증한다. 이번 보존 시험은 장비/관리 컨테이너 재시작이며 새로운 호스트 전체 재부팅 시험으로 표현하지 않는다.

실행 도구: `pytest`, `tests/integration/device_console.py`, `tests/integration/console_restart.py`, `tests/integration/siem_advanced.py`, `tests/browser/platform_browser.py`와 설치기 기본 검사. 통합 검증은 전용 VM의 실제 정책·서비스를 변경하므로 해당 테스트 VM에서 실행한다.
