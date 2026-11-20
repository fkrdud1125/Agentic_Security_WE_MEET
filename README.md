# VibeScan

**바이브코딩으로 만든 웹서비스의 보안 취약점을 내 PC에서 찾아 주는 도구입니다.**

AI 도구로 빠르게 만든 웹앱에는 소스에 박힌 API 키, SQL 인젝션, XSS, 인증 없는 관리자 API 같은 실수가 자주 섞입니다. VibeScan은 프로젝트 폴더를 읽어 이런 문제를 찾고, **어디가 왜 위험한지와 어떻게 고치는지**를 한국어로 보여 줍니다.

- **정적 검사는 내 PC에서 실행합니다.** 대시보드는 `127.0.0.1`에서 열립니다. AI 분석을 사용하면 비밀값 마스킹을 거친 코드 발췌가 OpenAI로 전송됩니다.
- **근거 코드와 수정안을 함께 보여 줍니다.** 발견마다 실제 코드, 문제 설명, 수정 예시를 확인할 수 있습니다.
- **커밋할 때마다 자동으로 검사합니다.** 켜 두면 새로 생긴 위험을 알려 줍니다(선택).
- **ChatGPT 구독으로 더 깊이 분석합니다.** API 키 없이 내 ChatGPT 계정으로 오탐을 걸러 내고 내 코드에 맞는 수정안을 받습니다(선택).

> VibeScan의 결과는 정적 분석으로 찾은 **후보**입니다. 안전을 보증하지 않으며, 실제 수정 전에는 코드를 직접 확인하세요.

## 준비물

| 필요한 것 | 확인 명령 | 비고 |
| --- | --- | --- |
| Python 3.11 이상 | `python --version` | [python.org](https://www.python.org/downloads/)에서 설치. Windows는 설치 화면에서 **Add python.exe to PATH**를 체크하세요. |
| Git | `git --version` | [git-scm.com](https://git-scm.com/downloads)에서 설치 |
| ChatGPT Plus/Pro 구독 | — | **선택 사항.** AI 심층 분석을 쓸 때만 필요합니다. |

검사 엔진(Semgrep)은 아래 설치 과정에서 함께 설치됩니다. 지원 운영체제는 Windows, macOS, Linux입니다.

## 설치

처음 한 번만 하면 됩니다.

**Windows (PowerShell)**

```powershell
git clone https://github.com/jubin0615/WE_MEET.git
cd WE_MEET
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .
```

**macOS / Linux**

```sh
git clone https://github.com/jubin0615/WE_MEET.git
cd WE_MEET
python3 -m venv .venv
.venv/bin/python -m pip install -e .
```

`.venv`는 VibeScan 전용 가상환경이라 PC의 다른 Python 프로그램에 영향을 주지 않습니다. 설치에는 1~2분이 걸립니다.

## 실행하기

```powershell
.\.venv\Scripts\vibescan          # Windows
```

```sh
.venv/bin/vibescan                # macOS / Linux
```

기본 브라우저에 대시보드가 열립니다. 종료하려면 실행한 터미널에서 `Ctrl+C`를 누르세요. 터미널에 표시되는 접속 주소에는 열람 권한이 들어 있으니 다른 사람과 공유하지 마세요.

### 처음 검사해 보기

1. 왼쪽 사이드바의 **+ 프로젝트 추가**를 누르고, 검사할 프로젝트를 입력합니다.
   - 내 PC의 프로젝트 폴더: `C:\Users\me\projects\my-app`
   - GitHub 주소: `https://github.com/소유자/저장소`
2. **지금 첫 스캔 실행**(또는 상단 **지금 스캔**)을 누릅니다. 위쪽에 진행 단계가 표시되고, 끝나면 결과가 열립니다.
3. **보안 상태** 카드에서 위험 등급(심각 / 위험 / 주의 / 낮음 / 발견 없음)과 점수를 확인합니다.
4. 발견 목록에서 항목을 누르면 오른쪽에 **무엇이 문제인가요 · 근거 코드 · 어떻게 고치나요 · 수정안**이 열립니다. 수정안은 **수정안 복사**로 가져갈 수 있으며 자동으로 적용되지는 않습니다.
5. 상단 **보고서**로 한국어 보고서(Markdown)를 내려받을 수 있습니다.

### 어떤 프로젝트를 넣을 수 있나요

| 입력 | 검사 대상 | 참고 |
| --- | --- | --- |
| Git 저장소 폴더 | 마지막 커밋(HEAD)의 모든 파일 | 아직 커밋하지 않은 변경은 검사하지 않습니다. |
| Git이 아닌 일반 폴더 | 그 순간의 폴더 파일 | 원본 폴더는 바꾸지 않습니다. 스캔할 때마다 새로 읽습니다. |
| GitHub 주소 | 기본 브랜치의 최신 커밋 | 내 PC에 복제해 두고, 스캔할 때마다 최신 커밋을 받아옵니다. 비공개 저장소는 PC에 설정된 Git 인증이 필요합니다. |

탐지 규칙은 **Python, JavaScript/TypeScript, Java, HTML 템플릿**(Jinja·Vue·Svelte 등)을 다룹니다. PHP·Ruby·Go 파일은 인증정보 노출만 확인합니다.

Java에서는 Spring MVC의 `@RequestParam` 또는 Servlet의 `getParameter` 입력이 JDBC SQL 본문으로 전달되는지 점검합니다. 소스에서 호출 대상을 식별할 수 있으면 컨트롤러·서비스·저장소 파일을 연결해 보고서에 경로를 표시합니다. Spring MVC 관리자 경로는 `SecurityFilterChain`의 첫 일치 정책 및 `@PreAuthorize`와 대조합니다. 예를 들어 관리자 경로에 로그인만 요구하면 권한 검토 후보로 표시합니다. 실행 프로필, 동적 정책, 실제 사용자별 접근 결과는 수동 확인 대상입니다.

## AI 심층 분석 연결하기 (선택)

ChatGPT Plus/Pro 구독이 있으면 VibeScan이 내 코드 문맥을 보고 오탐을 걸러 내고, 내 코드에 맞는 수정안을 만듭니다. API 키는 필요 없습니다.

1. **이 PC를 한 번 등록합니다.** 프로그램을 설치한 폴더(`WE_MEET`)에서 실행하면 브라우저가 열립니다. 계정을 선택하고 권한을 승인하세요.

   ```powershell
   .\.venv\Scripts\python -m vibescan.register
   ```

2. **로그인합니다.** 대시보드 왼쪽 아래 **ChatGPT 연결 필요**(또는 **설정**)를 눌러 **ChatGPT로 로그인**을 누릅니다. 터미널에서는 `.\.venv\Scripts\vibescan login`으로도 할 수 있습니다.
3. **지금 스캔** 옆 화살표(▾)에서 **AI 심층 분석**을 선택해 스캔합니다.

AI 분석을 사용하면 **비밀값과 주석을 지운 코드 일부**가 OpenAI로 전송되고, ChatGPT 구독 사용량이 차감됩니다. 사용량 한도와 앱 연결은 ChatGPT 설정에서 관리할 수 있습니다. AI 분석이 실패해도(사용량 초과, 로그인 만료 등) 로컬 검사 결과는 그대로 남습니다.

## 커밋할 때마다 자동 검사 (선택)

대시보드 **설정 → 자동 감시**에서 **커밋 후 자동 스캔**을 켜면, 그 프로젝트에서 `git commit`할 때마다 백그라운드에서 검사합니다. 커밋은 기다리지 않고 바로 끝나며, 몇 초 뒤 대시보드에 결과가 나타납니다. 새로 생긴 치명·높음 위험이 있으면 화면 배너와 브라우저 알림으로 알려 줍니다.

- 내 PC에서 직접 커밋하는 Git 저장소에서만 사용할 수 있습니다(GitHub 주소·일반 폴더 제외).
- 프로젝트의 `.git/hooks/post-commit` 파일을 만듭니다. 이미 다른 hook이 있으면 덮어쓰지 않고 직접 추가할 한 줄을 안내합니다.
- 자동 검사는 기본적으로 ChatGPT를 쓰지 않습니다. **자동 스캔에서 AI 검토**를 켜면 새로 생긴 높음 이상 발견만 분석합니다.

## 터미널에서 사용하기

```powershell
.\.venv\Scripts\vibescan scan C:\path\to\my-app --offline        # 로컬 검사만
.\.venv\Scripts\vibescan scan C:\path\to\my-app                  # 로그인되어 있으면 AI 분석 포함
.\.venv\Scripts\vibescan scan C:\path\to\my-app --output D:\out  # 결과 저장 위치 지정
.\.venv\Scripts\vibescan dashboard --results D:\out              # 그 결과를 대시보드로 보기
```

결과 폴더마다 `scan_result.json`(전체 결과)과 `report.md`(한국어 보고서)가 저장됩니다. `vibescan scan`은 Git 저장소 폴더만 받습니다. 일반 폴더와 GitHub 주소는 대시보드에서 연결하세요.

검사에서 빼고 싶은 파일은 프로젝트 최상위에 `.vibescanignore`를 만들어 `.gitignore`와 같은 형식으로 적습니다. `node_modules`, `dist`, `build`, `.venv` 같은 폴더는 자동으로 제외합니다.

## 내 데이터는 어디에 저장되나요

모든 데이터는 아래 폴더에 저장됩니다.

| 운영체제 | 위치 |
| --- | --- |
| Windows | `%LOCALAPPDATA%\vibescan` |
| macOS / Linux | `~/.config/vibescan` |

| 하위 경로 | 내용 |
| --- | --- |
| `scans/` | 스캔 결과(근거 코드 포함, 탐지한 비밀값은 앞 4글자만 남기고 가림) |
| `scan-history.sqlite3` | 프로젝트 연결 목록과 스캔 이력 |
| `github/` | GitHub 주소로 연결한 프로젝트의 복제본 |
| `folders/` | 일반 폴더 프로젝트의 스냅샷 기록 |
| `session.sqlite3`, `registration.sqlite3` | ChatGPT 로그인 정보(Windows는 사용자 계정 암호화로 보호) |

**외부로 나가는 것은 AI 심층 분석을 켰을 때 OpenAI로 보내는 코드 일부뿐입니다.** 이때도 비밀값과 주석은 지운 뒤 보냅니다. 결과 파일과 내려받은 보고서에는 실제 소스 코드가 들어 있으니, 다른 사람에게 보낼 때 주의하세요.

## 업데이트와 삭제

**업데이트** — 설치한 폴더에서 최신 코드를 받습니다. 실행 중인 대시보드는 `Ctrl+C`로 끄고 다시 실행하세요.

```powershell
git pull
.\.venv\Scripts\python -m pip install -e .
```

**삭제** — 아래 두 가지를 지우면 됩니다.

1. 설치한 `WE_MEET` 폴더
2. 데이터 폴더(`%LOCALAPPDATA%\vibescan` 또는 `~/.config/vibescan`)

자동 감시를 켠 프로젝트가 있다면, 삭제 전에 대시보드에서 끄거나 그 프로젝트의 `.git/hooks/post-commit` 파일을 지우세요.

## 문제 해결

| 증상 | 해결 |
| --- | --- |
| `python`을 찾을 수 없음 | Python 설치 시 PATH 추가를 체크했는지 확인하세요. Windows는 `py -3 -m venv .venv`로도 만들 수 있습니다. |
| "커밋이 있는 로컬 Git 저장소…" 오류 | Git이 설치되어 있는지 확인하세요. Git 저장소라면 커밋이 하나 이상 있어야 합니다. |
| "Semgrep을 찾을 수 없습니다" | 설치 명령을 다시 실행하세요: `.\.venv\Scripts\python -m pip install -e .` |
| 대시보드에 예전 화면이 보임 | 실행 중인 대시보드를 `Ctrl+C`로 끄고 다시 실행하세요. |
| GitHub 비공개 저장소 연결 실패 | 같은 PC에서 `git clone <주소>`가 되는지 먼저 확인하세요. |
| AI 분석이 안 됨 | 설정의 ChatGPT 상태를 확인하세요. 처음이라면 `python -m vibescan.register`부터 실행해야 합니다. |

## 개발자 정보

```powershell
.\.venv\Scripts\python -m pip install -e . -r vulnapp/requirements.txt httpx
.\.venv\Scripts\python -m unittest discover -s tests
node tests/test_dashboard_ui.cjs
.\.venv\Scripts\python -m bench.check_rules   # 규칙별 취약/안전 표본 검사
.\.venv\Scripts\python -m bench.run           # 합성 표본 탐지 벤치마크
```

| 경로 | 역할 |
| --- | --- |
| `vibescan/` | CLI, 대시보드 서버(`dashboard.py`), 로그인·세션, 자동 감시 hook |
| `vibescan/web/` | 대시보드 화면(HTML·CSS·JS, 번들 폰트) |
| `scanner/` | 코드 수집, 정적 검사, 시크릿 탐지, 결과 모델, 이력 저장 |
| `rules/` | VibeScan 전용 Semgrep 규칙과 분류 카탈로그 |
| `bench/` | 탐지 벤치마크 |
| [`vulnapp/`](vulnapp/README.md) | 일부러 취약하게 만든 Flask 샘플 앱 |

문서: [기술 문서(데이터 형식·진단 범위)](docs/technical.md) · [진단 로직 보강](docs/diagnosis-plan.md) · [규칙 작성](rules/README.md) · [벤치마크](bench/report.md) · 스프린트 기록 [1](docs/sprint1.md) · [2](docs/sprint2.md) · [3](docs/sprint3.md) · [4](docs/sprint4.md)

Pretendard 폰트는 [SIL Open Font License](vibescan/web/fonts/OFL.txt)를 따릅니다.
