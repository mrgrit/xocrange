# C7 서명 권한 계약 · 0.1.0

Community는 키 없이 실행한다. 상용 모듈은 Ed25519 서명과 기관·설치 범위·티어·Core 버전·모듈 버전·시간 조건을 모두 만족해야 설치·등록·시작·실행할 수 있다. 콘텐츠와 시나리오는 별도의 구매 ID·버전 범위를 추가 확인한다. 단순히 Live Fire 티어라는 이유로 모든 콘텐츠를 허용하지 않는다.

```bash
sudo xoc license status
sudo xoc license trust --key-id 공급자키ID --file /공급자/공개키.pem
sudo xoc license activate --file /공급자/license.json --institution 기관ID --range 설치ID
```

공개키는 Ed25519 SPKI PEM이다. Core는 발급 서버·개인키·기본 신뢰 키를 배포하지 않는다. 관리자가 제공받은 공개키만 명시적으로 등록한다. 같은 ID의 키를 다른 키로 덮어쓰지 않는다. 온라인 폐기·동시 접속 수·레지스트리 자격 증명 배포는 이번 계약의 범위 밖이다.

서명 봉투의 필드는 `schema_version`, `key_id`, `payload`, `signature`이며 서명은 Base64 64바이트다. `signature`를 제외한 봉투를 UTF-8 JSON으로 정규화한다(`sort_keys=True`, `separators=(',', ':')`, `ensure_ascii=False`). 그 바이트를 Ed25519로 서명한다. 중복 키·알 수 없는 필드·비정상 숫자·과대 문서는 거부한다.

payload 필수 필드:

| 필드 | 의미 |
|---|---|
| license_id | 발급 건 ID |
| institution_id, range_id | 운영자가 로컬에 고정한 기관·설치 ID와 일치 |
| tier | live-fire 또는 joint-force |
| issued_at, not_before, expires_at | UTC 초 단위 `YYYY-MM-DDTHH:MM:SSZ`; 만료 시각부터 실행 불가 |
| core | 허용 Core 버전 범위 |
| modules | 모듈 ID → 허용 버전 범위 |
| content | 구매 콘텐츠 ID → 허용 버전 범위 |
| scenarios | 구매 공방전 ID → 허용 버전 범위 |

버전은 명시적인 숫자 범위만 받으며 `*`를 허용하지 않는다. 기관 ID를 요청 파라미터로 바꾸거나 manifest만 변경해 권한을 얻을 수 없다. 서명 검증에는 OpenSSL의 [Ed25519 pkeyutl](https://docs.openssl.org/3.5/man1/openssl-pkeyutl/)을 사용한다.

설치 CLI·계획 생성·명시적 시작에서 다시 검증한다. 웹 메뉴 등록과 API는 매 요청마다 다시 검증한다. 만료된 정상 서명은 기존 데이터 읽기·내보내기·정지를 허용하고 신규 실행은 거부한다. 잘못된 서명은 읽기 권한도 부여하지 않는다. 부팅 시 허가되지 않은 상용 모듈과 그 의존 기능을 정지한 채 허용된 Core만 기동한다. 서명 권한이 실행 중인 외부 모듈 내부의 모든 행위를 대신 통제하지는 않으므로 모듈은 실행 API에서도 C7을 호출해야 한다.

호스트 설정은 `/etc/xocrange/entitlements`, 웹 검증용 복사본은 platform-config 볼륨에 있으며 웹에서는 읽기 전용이다. 활성화 실패 시 기존 호스트 설정을 복원하고 새 권한이 웹에만 남지 않게 처리한다.
