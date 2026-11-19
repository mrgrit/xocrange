# 라이선스 적용 절차

xOC Range Core는 라이선스 없이 Community로 동작한다. 유료 등급(Live Fire, Joint Force)은 공급사가
서명한 라이선스를 Core에 활성화해야 쓸 수 있다. 이 문서는 지금 구현된 절차를 적는다. 등급과 판매
정책은 정본 계획(`xocrange_plan`의 `docs/TIERS.md`, `docs/LICENSING.md`, `docs/PACKAGING.md` C7)을 따른다.

## 1. 구성

| 무엇 | 어디 | 설명 |
|---|---|---|
| 라이선스 | `/etc/xocrange/entitlements/license.json` | 등급, 기관, 레인지, 허락한 모듈과 버전 범위, 만료, 학생 도메인. 공급사 키로 서명 |
| 설치 식별 | `/etc/xocrange/entitlements/identity.json` | 이 Core의 기관·레인지. 라이선스의 값과 같아야 한다 |
| 신뢰하는 공급사 키 | `/etc/xocrange/entitlements/trust/<키 이름>.pem` | 공개키만 둔다. 개인키는 Core에 없다 |
| 등록 정보(Live Fire) | `/etc/xocrange/livefire/` | 학교 서버 주소, 레인지, 도메인, 학교 서버에 붙을 자격 증명 |

Core는 요청마다 서명·만료·식별을 다시 확인한다. 화면에 보이는 등급 표시는 안내용이며 권한은
항목별 확인으로 정한다. 만료되면 이미 설치된 유료 기능은 읽기만 된다.

## 2. 경로 A — 반 등록 코드 (Live Fire, 수업용)

학교 서버(Range Control)가 공급사의 발급자 인증서(등급·좌석 수·만료 포함)를 갖고, 학생 Core마다
라이선스를 발급한다.

1. **관리자(한 번):** Range Control에 발급자 인증서와 공급사 공개키를 넣는다(관리 화면 또는
   `POST /admin/issuer`).
2. **강사:** 반 등록 코드를 만든다. 유효 시간과 사용 횟수를 정한다.
3. **학생:** Core를 설치할 때 코드와 자기 실습 도메인을 넣는다.
   ```bash
   sudo bash install.sh --enroll-code <코드> --lab-domain alice.lab
   ```
   학교 서버를 자동으로 찾지 못하면 `--livefire <서버 주소>`를, 공급사 키를 아직 신뢰하지 않는
   Core라면 `--trust-vendor-key <공개키 파일>`을 더한다.
4. 설치기가 학교 서버에 등록하고, 받은 라이선스를 활성화한 뒤 설치를 계속한다. 좌석 하나가 쓰인다.
   설치가 중간에 실패해도 받은 등록 결과는 보관되며, 다시 실행하면 코드를 또 쓰지 않고 이어 간다.

코드가 틀렸거나 만료된 경우, 도메인이 실습용 이름(`.lab`·`.test`·`.internal`·`.home.arpa`)이 아닌
경우, 같은 도메인을 다른 학생이 쓰는 경우, 좌석이 없는 경우에는 등록을 거절하고 안내 문구를 낸다.
코드 없이 설치하면 Community로 설치된다.

## 3. 경로 B — 라이선스 파일 (수동)

공급사가 준 라이선스 파일을 직접 넣는다. Joint Force는 지금 이 경로뿐이다.

```bash
sudo xoc license trust --file <공급사 공개키.pem> --key-id <키 이름>     # 그 키를 처음 쓸 때 한 번
sudo xoc license activate --file <license.json> --institution <기관> --range <레인지>
sudo xoc license status
```

- `--institution`과 `--range`는 라이선스 안의 값과 같아야 한다.
- 이미 라이선스가 있으면 새 것으로 바뀐다(예: Live Fire로 등록한 Core를 Joint Force로 올리기).
- 라이선스 파일은 비밀로 다룬다. 0600으로 두고, 활성화한 뒤 지운다.

## 4. 유료 모듈 받기

라이선스는 권한이고, 모듈은 따로 받는다.

```bash
sudo xoc module login --registry <레지스트리 주소> [--ca <레지스트리 CA 파일>]
sudo xoc module add <모듈 ID> --package <패키지 폴더>
sudo xoc module credentials <모듈 ID> --from /etc/xocrange/livefire/credentials
```

- `module login`은 활성 라이선스를 자격 증명으로 공급사 레지스트리에 로그인한다. 레지스트리는
  라이선스가 허락한 모듈 이미지만, 만료 전까지만 내준다.
- 모듈 패키지는 레지스트리 주소와 `@sha256:` 다이제스트로 이미지를 고정해야 설치된다.
- `module credentials`는 학교 서버에 붙을 자격 증명을 모듈에 넘긴다(학교 서버와 통신하는 모듈만).
- 모듈을 새 버전으로 바꿀 때는 `sudo xoc module upgrade --package <패키지 폴더>`.

## 5. 확인

| 확인할 것 | 방법 |
|---|---|
| 등급·만료·도메인 | `sudo xoc license status` |
| 화면 | Core 화면 머리말의 등급 표시(없으면 Community, 만료면 "만료" 표시) |
| 설치된 모듈 | `sudo xoc module list` |
| 학교 서버 쪽 | Range Control의 반 화면에서 등록된 Core(도메인·주소·최근 접속) |

## 6. 지금의 한계 (2026-11-19)

- **시험용 키뿐이다.** 개발·시연 환경의 발급자 인증서와 라이선스는 시험용 공급사 키로 서명했다.
  실제 공급사 키의 보관과 발급 업무(백오피스) 운영 절차는 정해지지 않았다. 저장소에는 검증용
  공개키만 두고, 시험 키를 배포 빌드에서 신뢰하지 않는다.
- **Joint Force 자동 발급이 없다.** 반 등록 코드는 Live Fire 등급을 발급한다.
- **등급만으로 열리는 화면은 없다.** Core의 층 접근은 2F·B1·옥외·6F로 고정이고, 유료 층의 내용은
  해당 유료 모듈이 제공한다.
- 공급사 레지스트리의 인증서는 시험용 CA다(`--ca`로 넘긴다).

실행 기록: [Live Fire 학생 도메인](development/LIVEFIRE-DOMAINS-RUN-2026-11-16.md),
Live Fire 저장소의 `docs/development/L17-PAID-DELIVERY.md`.
