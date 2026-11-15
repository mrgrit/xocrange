# ADR-0008: Live Fire 판정기가 쓰는 증거 조회 표면

상태: 2026-11-14 제안. 브랜치 `livefire-integration`(Community RC 태그 뒤 main에 합침). 관련: [ADR-0001](0001-core-boundaries.md)(Core는 채점하지 않음), [ADR-0002](0002-contracts-and-planner.md), [ADR-0005](0005-core-telemetry.md).

## 배경

Live Fire의 M15 판정기(Assessor)는 상용 모듈로 각 Core에 설치되어 SIEM 이벤트·Wazuh 경보·장비 로그·장비 정책·서비스 상태를 읽어야 한다. 현재 Core에는 다음 제약이 있다.

- 관리 전용 입구가 없다. 모든 443 요청이 ingress → fw → IPS → WAF를 지나고, 모듈은 TLS 입구로 노출되지 않는다.
- int 망은 평평하다. 취약 타깃이 Wazuh API·Indexer·플랫폼과 같은 망에 있고, 출처 IP로 컨테이너 신원을 증명할 수 없다.
- SIEM 저장소는 root가 소유하는 호스트 SQLite 파일이고, 쓰는 주체는 수집기 하나다.
- 일반 모듈 fragment는 볼륨을 마운트할 수 없다.

## 결정

1. **새 인바운드 입구를 만들지 않는다.** 판정기는 `user` 망에서 Range Control로 나가는 HTTPS(mTLS) 연결로 판정 요청을 받아 가고 결과를 보낸다. 검토된 공격 경로 정책(ADR-0005, `planner.py`의 우회 금지)은 바뀌지 않는다.
2. **증거 조회는 호스트 서비스 `xoc evidence serve`가 한다.**
   - root로 실행하되 읽기만 한다. SIEM 저장소는 `mode=ro`로 연다. 장비 로그와 장비 정책 상태는 볼륨에서 읽고, 서비스 상태는 Docker CLI와 `/proc`에서 읽는다.
   - 컨테이너 안에서 명령을 실행하지 않는다(`docker exec` 금지).
   - 검사 종류와 인자는 Live Fire Assessor API v1의 닫힌 집합으로 제한한다. 패턴은 문자 그대로의 부분 문자열만 받는다.
3. **모듈 전용 소켓.** 다음 세 조건을 모두 만족하는 모듈 컨테이너에만 플래너가 `evidence-<module>` 볼륨을 `/run/xoc-evidence`(읽기 전용)로 마운트한다.
   - `kind: module`
   - C7 권한 있음
   - `requires.capabilities`에 `evidence-query` 선언
   서비스는 그 볼륨 안에 소켓을 만들고 모듈의 컨테이너 사용자에게만 연결을 허용한다. 소켓이 마운트됐다는 사실이 모듈의 신원이다. int 망에는 열지 않는다.
4. **모듈 자격 증명.** `module-<id>-credentials` 볼륨을 해당 모듈에만 `/run/xoc-module`(읽기 전용)로 마운트한다. 들어가는 것은 Range Control 주소, 클라이언트 인증서·키, CA다. 값은 호스트에서 `xoc module credentials <id> <dir>`로 넣고 0600으로 둔다.
5. **감사.** 모든 조회를 모듈 ID, 검사 종류, 인자 해시, 결과, 시각과 함께 `/var/log/xocrange/evidence.jsonl`에 남긴다.
6. **파일 읽기 범위.** 파일 읽기는 서비스별 허용 경로(타깃의 `/tmp`, `/var/tmp`, `/dev/shm`, 웹 루트) 안에서만 한다. 경로를 한 단계씩 링크를 따르지 않고 열며, 크기 상한은 256 KiB다. 장비 설정 확인은 파일이 아니라 장비 정책 상태(`device_config`)로 한다.
7. **레인지 식별.** Live Fire 키가 활성화되면 그 뒤 수집하는 C1 이벤트의 `tenant_id`/`range_id`를 검증된 `identity.json`의 `institution_id`/`range_id`로 쓴다. 이전 이벤트는 `community`/`local`로 남는다.
8. **계약.** `contracts/c2-judgment.json`(판정 레코드 v0.1)을 추가하고 manifest에 `C2: 0.1.0` 선언을 허용한다. Core는 판정 레코드를 만들거나 점수를 계산하지 않는다.
9. **Community 영향 없음.** `xocrange-evidence` 서비스는 설치되지만, `evidence-query`를 요구하는 상용 모듈이 없으면 바로 끝나고 비활성으로 남는다. Community 설치에서는 소켓도 볼륨도 생기지 않는다. 모듈 추가·제거·업데이트 뒤에 서비스를 다시 시작한다.

## 결과

- Core에 채점 로직이 들어가지 않는다. 조회 결과(통과·실패와 증거 참조)를 점수로 바꾸는 일은 Live Fire가 한다.
- 판정기가 공격 경로에 노출되지 않는다. 학습자 타깃은 증거 조회 소켓에 닿을 수 없다.
- 남는 위험: root 호스트 서비스의 입력 처리. 검사 집합을 닫아 두고, 파서 거부 시험과 조회 감사로 관리한다.
