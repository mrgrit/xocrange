# 8종 원본 분석과 SIEM 선택 수명주기

K05/K06의 C1 경로에 독립적인 원본 분석을 추가한다. 원본은 관리자 전용 증거 DB에 그대로 남기고, Wazuh가 읽을 수 있는 한 줄 메시지로만 변환한다. C1의 민감 필드 제외 정책과 native 분석의 원본 필드 보존은 서로 다른 경계다. 현재 관리자용 native 검색에는 명령행·요청 URI 등 원본 값이 포함될 수 있다.

| 소스 | Native 입력과 규칙 | 의미 |
|---|---|---|
| nftables | 원문, xOC decoder → stock 4100/4101 | RFC3339 소수점 predecoder 차이 보완, IP/port/protocol/action 보존. 단일 DROP은 stock `no_log`; C1에서는 계속 조회 가능 |
| Suricata | EVE JSON 한 줄 → stock 86601 | alert SID·action·IP/port 등 원본 필드 |
| ModSecurity | AHZ JSON + 로컬 계산 intervention → 119670/119671/119672 | kt66 번호·level 유지, 정상/경고/차단 구분. `ENABLED` 모드와 메시지 시작의 실제 intervention을 함께 요구 |
| osquery | row별 표준 `osquery` wrapper → stock 24010 | batch/snapshot 분할, 쿼리 이름·전체 columns 유지 |
| Linux Sysmon | XML → `sysmon_linux` JSON → 111201/111203/111211 | Linux provider·EventID·EventData 유지. 프로세스/네트워크/파일 관측 규칙이며 Windows 공격 탐지와 동일하다고 표현하지 않음 |
| auditd | 묶음 record를 한 줄로 결합 → stock auditd decoder | 정상 80700/level 0, DAEMON_ABORT 80704. 원본 줄 구분·ENRICHED 구분 문자는 증거 DB에 보존 |
| Apache access | 실습 요청: combined 호환(referer `"-"`, User-Agent) + request ID → stock web rules + `111303`. 관리 화면 `/core`: 질의 문자열·헤더 없는 형식 | URI를 이용하는 SQLi 등 stock 규칙 복원, 알려진 스캐너 User-Agent는 `111303`(level 6, T1595; User-Agent 칸에서만 일치, SQLi 31103이 우선). C1은 URI·헤더를 제외하고 ModSecurity request ID 연결 유지. 이전 common·JSON 입력도 수용 |
| Apache error | 원문 → stock apache-errorlog | AH code·ModSecurity 오류 등 기본 규칙 사용 |

ModSecurity에서 HTTP 403만 있거나 응답 본문/경고의 인용 문자열에 `Access denied`가 들어 있는 경우는 WAF 차단으로 처리하지 않는다. 입력에 실린 `xoc_modsecurity` 주장은 덮어쓰고 로컬에서 계산한다. 출처 location은 수집기가 생성하므로 다른 로그 파일이 WAF 규칙을 주장할 수 없다. AHZ에 응답 status가 없어도 실제 intervention은 식별하며, 이를 위해 쿠키·인증 헤더·본문 수집 범위를 넓히지 않는다.

## 처리 확인·재전송

- 신규 수집 시 native 입력 ID·frame SHA-256·C1 부모 연결을 같은 SQLite transaction에 기록한다. 기능 활성화 전에 수집한 정상 이력 전체를 다시 전송하지 않는다. 명시적 오류 재처리는 복구된 원본의 native 입력도 등록한다.
- 전송 ACK와 분석 완료는 구분한다. Manager `logall_json` archive에서 입력 ID·source·전체 메시지 hash·허용 decoder를 확인해야 완료한다. 정상 로그가 경보를 만들지 않았다는 이유로 실패하지 않는다.
- JSON object array 등 미지원 형식, 60,000-byte 초과 frame은 잘라서 성공시키지 않는다. 원본과 오류를 남기며 상태에 노출한다. Sysmon 시작 배너는 진단 기록으로 보존하지만 실제 이벤트 검사에 세지 않는다.
- 재전송 간 동일 native 입력·분석 결과는 한 검색 문서로 유지한다. Wazuh ID/시각/단순 firedtimes 변화만 무시하고 최초 경보 원본을 보존한다. 다른 규칙/결과/상관분석 문맥은 별도 경보다. 엔진 자체의 exactly-once 분석을 보장하는 것은 아니다. Native 경보의 시각은 Manager 분석 시각이며, 원본 발생 시각은 원문과 C1에 유지한다.
- 미분석 입력과 선택된 Indexer로 미전송인 경보의 증거는 로컬 1일 경과만으로 삭제하지 않는다. 24 GiB는 신규 수집 예산, 32 GiB는 SQLite 한도이며 전체 디스크 상한이 아니다. 2 GiB 파일시스템 여유 검사와 읽기 완료된 닫힌 archive 2일 정리·색인 7일 정리를 적용한다. 소스·archive 회전 전에 읽지 못한 로그와 장기 디스크 고갈은 별도 운영 검증 대상이다.

## 실제 엔진 비교 재실행

`tests/integration/native_rules.py`는 kt66에서 검토한 ModSecurity rule 파일을 **읽기 전용 입력**으로 받는다. 구버전 Manager 4.10.0과 후보 4.14.10의 digest를 고정하고 network=none, 공개 포트/운영 데이터 연결 없는 일회용 컨테이너에서 DB·analysisd만 실행한다. 기존 kt66 호스트의 서비스·설정은 바꾸지 않는다.

```bash
PYTHONPATH=src python tests/integration/native_rules.py \
  --legacy-rules /private/review/modsecurity-json-rules.xml \
  --output /private/validation/native-rule-comparison.json
```

보고서는 각 입력의 decoder·rule ID·level·주요 필드를 기록한다. 현재 검토 corpus는 엔진당 25건이며, Linux Sysmon EventID 1/3/11과 nftables 시각의 소수점 유무·허용/차단을 포함한다. 기존 분류 유지 항목과 알려진 누락/오분류 수정 항목의 기대 결과를 따로 선언한다. 구버전이 새 원본 형식을 지원하지 않는 결과도 그대로 기록한다. 검토 fixture 범위를 넘어 전체 kt66 탐지 동등성을 선언하지 않는다.

`tests/integration/native_replay.py --isolated-vm`은 이미 분석된 Suricata·ModSecurity·osquery·Sysmon 입력을 실제 Manager로 다시 보내고 archive 재분석, 수집 cursor 진행, 최초 경보 byte/hash와 네 개의 고유 검색 문서 보존을 대조한다. Indexer 장애 회귀는 [수명주기 도구](SIEM-LIFECYCLE-VALIDATION.md)에서 C1 100건과 경보 100건 외에 원본 분석 경보 100건을 따로 확인한다.

## SIEM 전체 선택 회귀

전용 VM의 root 셸에서 현재 설치 소스와 같은 체크아웃을 사용한다. 아래 도구는 사용자 saved search/API 계정 및 일반 OS audit 규칙이 선택 변경 중 유지되는지 확인할 임시 probe를 만들며, `cleanup`에서 그 probe만 제거한다. 명령마다 정상 종료를 확인하고 진행한다.

```bash
xoc_release=$(readlink -f /opt/xocrange/current)
xoc_test_python=/opt/xocrange/venvs/${xoc_release##*/}/bin/python
"$xoc_test_python" tests/integration/siem_selection.py checkpoint --run raw-selection --isolated-vm
bash install.sh --without siem
"$xoc_test_python" tests/integration/siem_selection.py excluded --run raw-selection --isolated-vm
bash install.sh --without siem
"$xoc_test_python" tests/integration/siem_selection.py excluded --run raw-selection --isolated-vm
bash install.sh
"$xoc_test_python" tests/integration/siem_selection.py restored --run raw-selection --isolated-vm
"$xoc_test_python" tests/integration/siem_selection.py cleanup --run raw-selection --isolated-vm
```

전체 제외 상태에서는 Manager·Indexer·Dashboard가 없고, 독립 management의 HTTPS ingress와 `/core/`는 유지하며 collector/osquery/Sysmon은 중지·비활성화돼야 한다. 일반 auditd와 다른 audit 규칙은 유지하고 xOC의 세 watch만 제거한다. 제외 상태 재설치가 증거 건수를 바꾸지 않는지, 재포함 후 원본/C1 24건·경보 24건·8종 분석 receipt·두 CA와 계정·API 사용자·저장 화면이 유지되는지 대조한다. 보안 경로와 새 8종 C1/native 입력 및 HTTPS 검사를 다시 실행한다.

근거: [Wazuh JSON decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html), [실제 규칙 엔진 검사](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html), [alerts와 archives](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html). Wazuh/상용 소스의 출처와 검토 범위는 provenance에 기록한다.

Apache의 요청 전 연결 종료 로그(`"-" 400/408`, 새 형식의 `"-" "-"` 포함 여부와 무관, xoc_id 포함)는 별도 `xoc-apache-empty-request` 디코더가 IP·상태·크기를 추출하고, Wazuh 기본 web-log 규칙 31100(level 0)과 archive receipt로 처리 완료를 확인한다. HTTP 요청 줄을 합성하지 않는다.

프로토콜이 없는 요청 줄(2026-11-20): Apache는 받은 요청 줄을 그대로 적는다. 길이 제한에서 잘린 줄(414), HTTP/0.9 요청, HTTP가 아닌 바이트(400)는 끝에 ` HTTP/x.y`가 없어 기본 `web-accesslog` 디코더가 받지 않고, 기본 pure-ftpd 전송 로그 디코더(`pure-transfer`)가 대신 받았다. 그 입력은 처리 확인이 되지 않아 SIEM이 보존 기간 내내 `degraded`였고 설치·업데이트의 `siem-telemetry` 단계가 실패했다(192.168.16.51에서 8 KB 요청 한 건으로 발생). 조치: `xoc-apache-partial-request`(`"METHOD /경로"`: 출발지·메서드·URL·상태)와 `xoc-apache-malformed-request`(그 밖: 출발지·상태) 디코더를 추가하고, 이 실습 환경에 없는 pure-ftpd 디코더·규칙 파일을 Manager 설정에서 제외했다. 기본 웹 규칙(31100 계열, 긴 URL 31115)이 그대로 적용된다. 격리한 Wazuh 엔진에서 `tests/integration/native_rules.py --inside candidate` 40개 사례 통과.

### 실습 요청 User-Agent 검증 (2026-11-15, 개발 VM 설치본 `livefire-integration` `67f4663`)

att VM(192.168.16.99)에서 `Host: dvwa.xoc.range`로 User-Agent 5종 요청: curl·따옴표 포함 브라우저 200, sqlmap·gobuster·Nuclei는 CRS가 403 차단. SIEM 원본 5건 모두 User-Agent 포함(따옴표는 `\"`로 이스케이프), 저장된 SHA-256과 재계산 일치. 스캐너 3건은 `111303`(level 6) 경보로 C1 이벤트에 연결. 관리 화면 `/core/` 줄은 이전 형식(질의·User-Agent 없음) 유지, 처리 격리 0건. 개별 판정 사례 33개는 설치된 Wazuh 이미지에서 `tests/integration/native_rules.py --inside candidate`로 통과.
