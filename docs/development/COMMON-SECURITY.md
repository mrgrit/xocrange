# K07 공통 보안

`management` 구성요소는 SIEM과 독립된 HTTPS 진입점이다. 설치기의 기본 선택이며 `--without siem` 또는 `--without siem-ui`에서도 `/core/` 로그인·계정·장비 쓰기 정책·감사를 유지한다. 로고는 README의 자산을 공유한다. `bootstrap` 프리셋은 네트워크에 게시하지 않는 health 서비스만 실행한다.

## 계정과 역할

`sudo xoc platform credentials`로 설치 시 생성한 관리자 계정을 확인한다. 첫 로그인에서 14자 이상의 비밀번호로 변경해야 한다. 재설치는 계정·암호 해시·Django 서명 키·세션 DB를 초기화하지 않는다. 변경 후에는 사용자가 지정한 비밀번호를 사용한다.

| 역할 | 허용 범위 |
|---|---|
| 조회자 | 로그인·자신의 비밀번호 변경·장비 쓰기 정책 조회 |
| 운영자 | 조회자 범위와 후속 K08 장비 작업 권한; 관리자만 설정한 쓰기 허용 정책을 함께 검사 |
| 관리자 | 계정 생성·역할 변경·비활성화, 장비 쓰기 허용/잠금, 감사 조회 |

현재 장비 API는 정책 조회·변경까지 제공한다. 실제 nftables·Suricata·ModSecurity 구성의 preview/apply/configtest/rollback은 K08의 작업이다. 정책의 버전이 달라진 변경은 409로 거부한다. 조회자·운영자는 정책을 변경할 수 없다. 본인 계정의 역할·활성 상태 변경은 차단한다.

Wazuh Dashboard는 별도 계정·RBAC·세션을 유지한다. Core 역할을 Wazuh에 자동 반영하거나 로그인 세션을 공유하는 SSO를 구현했다고 표현하지 않는다. Manager API는 내부 TLS와 기존 Wazuh 인증으로 보호하며 호스트에 게시하지 않는다.

## 요청과 세션 경계

```text
HTTPS ingress → nftables → Suricata → Apache/ModSecurity
                                           └ Unix socket → Django Core API
```

관리 API는 TCP 포트를 열지 않는다. `platform:8080`은 읽기 전용 health만 제공한다. Unix 소켓 볼륨은 platform과 WAF만 공유하고, 관리 DB·서명 키·초기 비밀번호는 WAF에 마운트하지 않는다. Docker socket·호스트 PID·privileged 권한을 관리 서비스에 제공하지 않는다.

[Django의 인증](https://docs.djangoproject.com/en/5.2/topics/auth/default/)·DB 세션·암호 검증과 [CSRF 보호](https://docs.djangoproject.com/en/5.2/ref/csrf/)를 사용한다. Secure/HttpOnly/SameSite=Strict의 `__Host-` 쿠키, 로그인 시 세션 교체, 15분 비활성 만료·8시간 절대 만료를 적용한다. 비밀번호·역할·활성 상태 변경은 기존 세션을 폐기한다. POST는 JSON·정확한 Origin·CSRF 토큰을 모두 요구하며, 임의 사용자·역할·Forwarded 헤더를 인증 근거로 삼지 않는다.

계정별 15분에 10회, 전체 100회의 로그인 시도 한도가 DB에 유지된다. 요청 본문은 16KiB로 제한한다. 관리 API의 query 문자열·Authorization 헤더는 ingress에서 거부한다. credentials를 URL에 넣어 접속하지 않는다.

## 감사와 민감값

계정·장비 정책 변경과 감사 레코드는 같은 DB 트랜잭션으로 저장한다. 감사 저장 실패 시 변경을 취소한다. 로그인·권한·CSRF 거부도 감사 대상이다. 기록은 시각, 사용자, 고정된 작업/대상 식별자, 결과, 허용된 변경 전후 필드, 서버 생성 요청 ID로 제한한다. 비밀번호·쿠키·CSRF 토큰·요청 본문은 감사 레코드에 넣지 않는다. 관리 페이지는 no-store와 CSP를 사용한다.

WAF 예외는 정확한 `/core/api/login`, `/core/api/password`, `/core/api/users`의 JSON POST에서 `password`·`current_password` 필드에 한정한다. 다른 필드와 경로는 계속 검사한다. Apache 관리 접근 로그는 query 문자열을 제외한다. 실제 검증은 공격 문자열이 포함된 비밀번호의 정상 처리, 다른 필드의 차단, 프로젝트 로그와 감사 DB의 평문 비밀번호 미기록을 함께 확인한다.

감사 DB는 같은 호스트 관리자가 통제하는 로컬 저장소다. 외부 불변 감사 저장소나 호스트 root 변조 방지를 제공한다고 주장하지 않는다. 이관·백업·복구·감사 장기 보존은 K11 운영 검증과 연결한다.
