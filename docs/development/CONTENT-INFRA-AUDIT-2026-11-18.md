# 콘텐츠와 현재 인프라의 차이 — 2026-11-18 조사

Community 번들(`contents/`)의 교재·공방전은 이전 실습 인프라를 기준으로 쓰였다. 현재 Core 설치본과
어디가 다른지 세고, 웹 공방전의 Red 명령은 실제 Core에서 실행했다. 이 문서는 조사 기록이며 콘텐츠는
아직 고치지 않았다.

## 1. 규모와 옛 인프라 의존 (코드 계수)

| 대상 | 규모 | 옛 인프라 표현 |
|---|---|---|
| 교재 `contents/academy/wazuh-threat-hunting` | 36차시·미션 96개·구역 72개 | `bastion` 112회, `ccc` 계정 117회, `192.168.0.x` 48회, `10.20.x` 6회, `auth.log` 26회, `agent.name`이 `web` 27회·`bastion` 19회·`xocrange-host` 10회 |
| 교재 본문 그림 | 84장(자산 파일 230개) | 5~8장에 67장. 화면 캡처가 현재 화면과 같은지는 아직 대조하지 않음 |
| 무료 공방전 `contents/battle-scenarios` | 15개 시나리오·미션 105개 | 웹 8개는 `dvwa.xoc.range`·`{{WEB_ENTRY}}`로 변환됨. 호스트 7개는 SSH 실습 서버(`XOC_LINUX_IP`, 계정 `xoc-student`)를 전제 |
| 유료 팩 `xocrange_contents/livefire-tw2` | 310개 시나리오·미션 1,449개 | 그대로 실행 가능 3개, 저자 판단 필요 307개(`conversion-report.json`) |

교재 72개 구역의 `mapping_status`는 모두 `pending-review`, 공방전 15개의 `review_status`는 모두
`authored-awaiting-live-validation`이다.

## 2. 현재 Core에 없는 것

교재 16~30번 사례와 호스트 공방전 7개는 "SSH로 들어가는 리눅스 서버 → `/var/log/auth.log` → 그 서버의
Wazuh 에이전트 → Discover"를 전제한다. 현재 Core의 실습 호스트(`lab-target`, `lab-client`)는 SSH,
`auth.log`, 사용자 계정, Wazuh 에이전트가 없는 최소 컨테이너다(데모 Core에서 확인: `/var/log`에
`apk.log`뿐, 프로세스는 `python`). 따라서 이름 치환만으로는 학생이 따라 할 수 없다.

결정 필요(소유자):

1. Core에 SSH·`auth.log`·Wazuh 에이전트를 갖춘 리눅스 실습 서버 모듈을 추가하고 교재의 `bastion`을
   그 호스트로 바꾼다.
2. 교재·호스트 공방전을 현재 Core의 웹 경로와 호스트 센서(Sysmon·auditd·osquery) 기준으로 다시 쓴다.

## 3. 웹 공방전 Red 명령 실행 결과 (실행 검증)

환경: 공격자 VM 192.168.16.99 → 데모 Core 192.168.16.52(Core fc2881b, `alice.lab`으로 등록).
8개 시나리오의 Red 명령 16개를 본문 그대로 실행했다(태그 `xoc-web-0N-audit18`).

| 미션 | 요청 | 응답 | 태그가 든 경보(규칙) |
|---|---|---|---|
| web-01 red-01 | 없는 경로 | 404 | 31101 |
| web-01 red-02 | `sqlmap-` User-Agent | 403 | 111303, 119672 |
| web-02 red-01 | `id=1` 기준 요청 | 302 → `/login.php` | 없음 |
| web-02 red-02 | UNION SELECT | 403 | 31103 |
| web-03 red-01 | `q=hello` 기준 요청 | 302 → `/login.php` | 없음 |
| web-03 red-02 | `<script>` | 403 | 31105 |
| web-04 red-01 | `file=help.txt` 기준 요청 | 302 → `/login.php` | 없음 |
| web-04 red-02 | `../../etc/passwd` | 403 | 119672, 31101 |
| web-05 red-01 | 로그인 실패 3회 | 302 ×3 | 없음 |
| web-05 red-02 | `/admin` | 404 | 31101 |
| web-06 red-01 | 파일 업로드 | 302 → `/login.php` | 없음 |
| web-06 red-02 | `;printf` 명령 삽입 | 403 | 31101 |
| web-07 red-01 | `${jndi:` 헤더 | 302 → `/login.php` | 없음 |
| web-07 red-02 | Shellshock 헤더 | 403 | 31101 |
| web-08 red-01 | TRACE | 403 | 31101 |
| web-08 red-02 | 2,048자 질의 | 302 → `/login.php` | 없음 |

확인한 것:

- 등록된 Core(`alice.lab`)에서도 `Host: dvwa.xoc.range`는 DVWA로 연결된다. 16개 모두 DVWA까지 갔다.
- 시나리오의 자동 검사(`wazuh_alert`, 태그 문자열 포함)는 8개 시나리오 모두 최소 1건으로 충족된다.
  일부 경보는 요청 2분 뒤에 보였다.

고쳐야 할 것:

- **기준 요청이 모두 302다.** DVWA는 로그인하지 않은 요청을 `/login.php`로 보낸다. "200 응답의 함정"
  (web-02)처럼 200을 전제한 설명·기준 답안은 실제와 다르다. 세션을 얻는 단계를 넣거나 설명을 302
  기준으로 고쳐야 한다.
- **주제와 맞는 경보가 없는 미션이 있다.** 로그인 실패(web-05 red-01), 업로드(web-06 red-01),
  Log4Shell 헤더(web-07 red-01), 긴 URL(web-08 red-02)은 태그가 든 경보를 만들지 않았다. 시나리오의
  검사는 다른 Red 요청의 경보로 통과하므로, 그 미션의 관측 대상은 경보가 아니라 접근 로그여야 한다.
- 명령 삽입·Shellshock·TRACE의 경보는 403을 일반 오류로 분류한 31101 한 건뿐이다. 공격 유형을
  이름으로 보여 주는 경보가 필요하면 Core 규칙을 추가해야 한다.

아직 하지 않은 것: Blue·Purple 미션의 검색식 실행, 호스트 공방전 7개(실습 서버 결정 뒤), 교재 차시별
명령·검색식 실행과 그림 교체, 유료 팩.
