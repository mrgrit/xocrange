# ADR 0006: 선택형 SIEM 웹 관제와 필드 단위 WAF 예외

- 상태: 실험 구현, 2026-11-07
- 선행: [ADR 0005](0005-core-telemetry.md)

## 문제

Core의 8종 C1 이벤트는 로컬에서 Wazuh 디코딩을 확인할 수 있지만 브라우저 검색과 시각화가 필요하다. 기존 kt66에서는 Dashboard의 정상 검색·필드 목록이 ModSecurity CRS에 차단됐고, 프록시 HTTPS 정보가 잘못 전달되면 로그인 쿠키도 동작하지 않았다.

## 결정

`siem-ui`를 별도 선택 구성요소로 둔다. Wazuh 4.14.10 분석기·Indexer와 Indexer 내부 OpenSearch 버전에 맞는 OpenSearch Dashboards 2.19.6을 사용한다. C1을 검색하는 Core 화면이며 Wazuh 에이전트 관리 플러그인을 포함하지 않는다.

브라우저는 HAProxy에서 TLS를 종료하고 nftables → Suricata NFQUEUE → Apache/ModSecurity를 통과한다. WAF 이후 Dashboard와 Indexer 구간은 다시 CA·서버 이름을 검증하는 TLS를 쓴다. IPS가 복호화된 HTTP를 검사할 수 있게 하며, PROXY 프로토콜을 TLS 앞에 삽입해 발생했던 Suricata 파서 오류를 해소한다.

기본 공개 포트는 80/443뿐이다. 설치마다 비밀번호·CA를 생성하고 자격 증명과 키는 관리자 전용 파일·읽기 전용 설정 볼륨에 보관한다. 전달된 클라이언트 출처는 Ingress가 덮어쓰고 WAF는 지정된 Ingress만 신뢰한다.

오탐은 실제 CRS Rule ID와 요청 경로·메서드·필드로 좁힌 예외로 해결한다. 검색 전체 또는 Rule engine을 끄지 않는다. 알려진 검색 강조 크기, index-pattern 필드 목록, C1 파일 경로 검색에만 예외를 둔다. JSON 파서를 명시적으로 활성화하고 다른 필드·경로·메서드의 차단도 검사한다. 상세 매트릭스는 [SIEM 웹 관제](../development/SIEM-WEB.md)에 기록한다.

Wazuh 확인을 받은 C1만 안정된 이벤트 ID로 색인한다. 부분 실패는 개별 문서 확인 후 재전송하며 미색인 원본은 보존한다. 매핑 또는 Indexer 저장소 식별자가 바뀌면 보존한 C1을 다시 색인한다. 기존 saved object는 덮어쓰지 않아 재설치 시 사용자 편집을 유지한다.

## 결과와 제한

설치 한 번으로 웹 관제까지 구성하며 웹 관제만 제외할 수 있다. 설치 완료는 실제 보안 경로·8종 디코딩·HTTPS 로그인 및 검색 수용 검사 통과를 요구한다. 브라우저 동작, 장애 복구, 재설치, 재부팅은 별도 실환경 검증 기록으로 남긴다.

설치별 CA는 접속 PC에서 한 번 신뢰 등록해야 한다. 외부 비밀번호 변경과 설치기 상태 동기화, 공개 CA 운용, 장기 부하·다중 사용자 운영·전체 Community 출시는 후속 범위다. 태그 기반 이미지와 범위형 Python 의존성을 사용하므로 재현 가능한 서명 릴리스라고 주장하지 않는다.
