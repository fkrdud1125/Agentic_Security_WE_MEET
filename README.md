# VibeScan

**바이브코딩으로 만든 웹서비스의 보안 취약점을 내 PC에서 찾아 주는 도구입니다.**

AI 도구로 빠르게 만든 웹앱에는 소스에 박힌 API 키, SQL 인젝션, XSS, 인증 없는 관리자 API 같은 실수가 자주 섞입니다. VibeScan은 프로젝트 폴더를 읽어 이런 문제를 찾고, **어디가 왜 위험한지와 어떻게 고치는지**를 한국어로 보여 줍니다.

- **정적 검사는 내 PC에서 실행합니다.** 대시보드는 `127.0.0.1`에서 열립니다. AI 분석을 사용하면 비밀값 마스킹을 거친 코드 발췌가 OpenAI로 전송됩니다.
- **근거 코드와 수정안을 함께 보여 줍니다.** 발견마다 실제 코드, 문제 설명, 수정 예시를 확인할 수 있습니다.
- **커밋할 때마다 자동으로 검사합니다.** 켜 두면 새로 생긴 위험을 알려 줍니다(선택).
- **ChatGPT 구독으로 더 깊이 분석합니다.** API 키 없이 내 ChatGPT 계정으로 오탐을 걸러 내고 내 코드에 맞는 수정안을 받습니다(선택).

> VibeScan의 결과는 정적 분석으로 찾은 **후보**입니다. 안전을 보증하지 않으며, 실제 수정 전에는 코드를 직접 확인하세요.

## 대시보드 실행

처음 사용하는 PC에서는 아래 [설치](#설치)를 한 번 진행하세요. 설치 후에는 Windows, macOS, Linux 모두 **어느 폴더에서든** 터미널에 다음 한 단어를 입력하면 기본 브라우저에서 대시보드가 열립니다.

```sh
vibescan
```

대시보드를 사용하는 동안 터미널을 열어 두세요. 종료하려면 `Ctrl+C`를 누르세요. 터미널에 표시된 접속 주소에는 열람 권한이 포함되어 있습니다.

## 준비물

| 필요한 것 | 확인 명령 | 비고 |
| --- | --- | --- |
| Python 3.11 이상 | Windows `python --version`, macOS·Linux `python3 --version` | [python.org](https://www.python.org/downloads/)에서 설치. Windows는 설치 화면에서 **Add python.exe to PATH**를 체크하세요. |
| Git | `git --version` | [git-scm.com](https://git-scm.com/downloads)에서 설치 |
| ChatGPT Plus/Pro 구독 | — | **선택 사항.** AI 심층 분석을 쓸 때만 필요합니다. |

검사 엔진(Semgrep)은 아래 설치 과정에서 함께 설치됩니다. 지원 운영체제는 Windows, macOS, Linux입니다.

## 설치

먼저 저장소를 받고 설치 폴더로 이동합니다.

```sh
git clone https://github.com/jubin0615/WE_MEET.git
cd WE_MEET
```

**Windows (PowerShell)**

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .

$bin = Join-Path $env:USERPROFILE '.local\bin'
New-Item -ItemType Directory -Force $bin | Out-Null
Copy-Item .\.venv\Scripts\vibescan.exe $bin
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($bin -notin ($userPath -split ';')) {
    [Environment]::SetEnvironmentVariable('Path', "$bin;$userPath", 'User')
}
$env:Path = "$bin;$env:Path"
```

**macOS (zsh) · Linux (bash)**

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
mkdir -p "$HOME/.local/bin"
ln -s "$PWD/.venv/bin/vibescan" "$HOME/.local/bin/vibescan"
export PATH="$HOME/.local/bin:$PATH"
```

새 터미널에서도 명령을 찾을 수 있도록 위의 `export PATH` 한 줄을 macOS에서는 `~/.zshrc`에, Linux의 bash에서는 `~/.bashrc`에 한 번 추가하세요. 실행 명령이 가상환경을 사용하므로 설치한 `WE_MEET` 폴더는 그 위치에 두세요.

## 처음 검사해 보기

1. 상단의 **+ 프로젝트 추가**를 누르고, 검사할 프로젝트를 입력합니다.
   - 내 PC의 프로젝트 폴더: `C:\Users\me\projects\my-app`
   - GitHub 주소: `https://github.com/소유자/저장소`
2. **지금 첫 스캔 실행**(또는 상단 **지금 스캔**)을 누릅니다. 위쪽에 진행 단계가 표시되고, 끝나면 결과가 열립니다.
3. **지금 확인할 것**에서 치명·높음 항목을 확인합니다. 같은 규칙의 발견은 카드 하나로 묶이며, **위치별 근거와 수정 방법**을 펼치면 파일별 판정과 코드를 확인할 수 있습니다.
4. **수정 요청 프롬프트 복사**를 누르면 프로젝트와 열린 위치를 AI 코딩 도구에 전달할 수 있습니다. 다음에 확인할 항목, 해결된 항목, 오탐 후보와 검사 범위는 하단 플로팅 바에서 선택합니다.
5. 상단 **보고서**로 한국어 보고서(Markdown)를 내려받을 수 있습니다.

### 어떤 프로젝트를 넣을 수 있나요

| 입력 | 검사 대상 | 참고 |
| --- | --- | --- |
| Git 저장소 폴더 | 마지막 커밋(HEAD)의 모든 파일 | 아직 커밋하지 않은 변경은 검사하지 않습니다. |
| Git이 아닌 일반 폴더 | 그 순간의 폴더 파일 | 원본 폴더는 바꾸지 않습니다. 스캔할 때마다 새로 읽습니다. |
| GitHub 주소 | 기본 브랜치의 최신 커밋 | 내 PC에 복제해 두고, 스캔할 때마다 최신 커밋을 받아옵니다. 비공개 저장소는 PC에 설정된 Git 인증이 필요합니다. |

탐지 규칙은 **Python, JavaScript/TypeScript, Java, HTML 템플릿**(Jinja·Vue·Svelte 등)을 다룹니다. PHP·Ruby·Go 파일은 인증정보 노출만 확인합니다.

Java에서는 Spring MVC의 `@RequestParam` 또는 Servlet의 `getParameter` 입력이 JDBC SQL 본문으로 전달되는지 점검합니다. 소스에서 호출 대상을 식별할 수 있으면 컨트롤러·서비스·저장소 파일을 연결해 보고서에 경로를 표시합니다. Spring MVC 관리자 경로는 `SecurityFilterChain`의 첫 일치 정책 및 `@PreAuthorize`와 대조합니다. 예를 들어 관리자 경로에 로그인만 요구하면 권한 검토 후보로 표시합니다. 실행 프로필, 동적 정책, 실제 사용자별 접근 결과는 수동 확인 대상입니다.

## 정적 검사 + AI 2차 검토 (선택)

검사는 **파일 수집 → 로컬 구조 분석 → 정적 검사·이전 결과 비교 → AI 2차 검토 → 결과·보고서 저장** 순서로 진행합니다. AI가 사전 계획을 작성하는 호출은 하지 않으며, 정적 검사기는 기존 규칙으로 먼저 실행됩니다.

AI는 발견 후보와 관련 코드를 보고 오탐 가능성·심각도·영향·수정 방법을 검토합니다. 검사기가 놓친 취약점 전체를 다시 찾거나 실행 중인 웹사이트에서 실제 악용을 검증하는 단계는 아닙니다. **현재 AI 검토는 마스킹 후 문맥을 추출할 수 있는 Python 발견사항만 지원하며, 심각도순 최대 30건을 5건씩 검토합니다.** JS/TS·Java 등은 기존 정적 검사 결과를 유지합니다.

검토할 후보나 지원 코드 문맥이 없으면 AI 인증·모델 조회·검토 요청을 모두 생략합니다. 일부 후보만 검토되거나 AI 연결이 실패해도 원래 발견사항과 미검토 항목은 결과에 남습니다. 대시보드는 검토 완료·일부 완료·생략·불가 상태와 이유를 표시합니다.

검토 결과를 포함한 `scan_result.json`을 저장하고, 동일한 데이터로 대시보드와 `report.md`를 제공합니다. 보고서를 위해 AI를 다시 호출하지 않습니다.

ChatGPT Plus/Pro 구독이 있으면 VibeScan이 내 코드 문맥을 보고 오탐을 걸러 내고, 내 코드에 맞는 수정안을 만듭니다. API 키는 필요 없습니다.

1. **이 PC를 한 번 등록합니다.** 프로그램을 설치한 폴더(`WE_MEET`)에서 실행하면 브라우저가 열립니다. 계정을 선택하고 권한을 승인하세요.

   ```powershell
   .\.venv\Scripts\python -m vibescan.register
   ```

2. **로그인합니다.** 대시보드 상단의 **ChatGPT 연결 필요**(또는 **설정**)를 눌러 **ChatGPT로 로그인**을 누릅니다. 터미널에서는 `vibescan login`으로도 할 수 있습니다.
3. **지금 스캔** 옆 화살표(▾)에서 **정적 검사 + AI 2차 검토**를 선택해 스캔합니다.

AI 분석을 사용하면 **비밀값과 주석을 지운 코드 일부**가 OpenAI로 전송되고, ChatGPT 구독 사용량이 차감됩니다. 사용량 한도와 앱 연결은 ChatGPT 설정에서 관리할 수 있습니다. AI 분석이 실패해도(사용량 초과, 로그인 만료 등) 로컬 검사 결과는 그대로 남습니다.

## 커밋할 때마다 자동 검사 (선택)

대시보드 **설정 → 자동 감시**에서 **커밋 후 자동 스캔**을 켜면, 그 프로젝트에서 `git commit`할 때마다 백그라운드에서 검사합니다. 커밋은 기다리지 않고 바로 끝나며, 몇 초 뒤 대시보드에 결과가 나타납니다. 새로 생긴 치명·높음 위험이 있으면 화면 알림과 브라우저 알림으로 알려 줍니다.

- 내 PC에서 직접 커밋하는 Git 저장소에서만 사용할 수 있습니다(GitHub 주소·일반 폴더 제외).
- 프로젝트의 `.git/hooks/post-commit` 파일을 만듭니다. 이미 다른 hook이 있으면 덮어쓰지 않고 직접 추가할 한 줄을 안내합니다.
- 자동 검사는 기본적으로 ChatGPT를 쓰지 않습니다. **자동 스캔에서 AI 검토**를 켜면 새로 생긴 높음 이상 발견만 분석합니다.

## 기준별 점검 현황

진단 결과의 **기준별 점검 현황 → 31개 기준 상세 보기**에서 OWASP Top 10 2025의 10개 범주와 주통기 웹의 21개 항목을 나누어 확인합니다. 항목을 펼치면 점검 범위·남은 확인 사유·연결된 발견 ID가 나오고, 발견 위치를 펼치면 근거 코드와 수정 방법을 볼 수 있습니다. 다운로드하는 한국어 보고서에도 같은 기준표가 포함됩니다.

- **검사 상태**: 대기, 검사 중, 정적 범위 완료, 부분 점검, 수동·동적 확인 필요, 기록 없음, 중단을 구분합니다. 실행 중에는 상단의 기준별 작업 상태에서 확인합니다.
- **발견 결과**: 취약 후보, 정적 범위 내 미발견, 판정 보류를 표시합니다. 미발견은 기준 전체의 양호 판정이 아닙니다.
- **AI 검토**: 그 기준에 연결된 발견 중 몇 건을 검토했는지 별도로 표시합니다. 31은 기준 분류 수이며 AI 호출 횟수가 아닙니다. 같은 발견이 두 기준에 연결되어도 전체 발견 수를 중복 집계하지 않습니다.

이전 결과도 기존 기록에 근거해 기준표를 표시하며, 실행 기록이 없는 항목은 완료로 추정하지 않습니다. 과거 결과 파일은 덮어쓰지 않고, 대시보드에서 내려받는 보고서에 기준표를 보충합니다. 자세한 상태 기록은 새 스캔부터 저장됩니다.

이 분류를 추가했다고 모든 기준의 자동 검사가 구현된 것은 아닙니다. 자동 규칙이 없는 항목과 설계·실행 환경 검토는 추가 확인 대상으로 남습니다. 기준 간 연결은 프로젝트의 참고 분류입니다.

## 터미널에서 사용하기

```powershell
vibescan scan C:\path\to\my-app --offline        # 로컬 검사만
vibescan scan C:\path\to\my-app                  # 로그인되어 있으면 AI 분석 포함
vibescan scan C:\path\to\my-app --output D:\out  # 결과 저장 위치 지정
vibescan dashboard --results D:\out              # 그 결과를 대시보드로 보기
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

macOS와 Linux에서는 `WE_MEET` 폴더에서 `git pull` 후 `.venv/bin/python -m pip install -e .`을 실행합니다. 다음 실행부터 기존 `vibescan` 명령에 업데이트가 적용됩니다. Windows에서는 아래 명령을 사용합니다.

```powershell
git pull
.\.venv\Scripts\python -m pip install -e .
```

**삭제** — 아래 두 가지를 지우면 됩니다.

설치할 때 등록한 실행 명령도 제거하세요. Windows에서는 `%USERPROFILE%\.local\bin\vibescan.exe`를 삭제하고, macOS와 Linux에서는 `unlink "$HOME/.local/bin/vibescan"`을 실행합니다.

1. 설치한 `WE_MEET` 폴더
2. 데이터 폴더(`%LOCALAPPDATA%\vibescan` 또는 `~/.config/vibescan`)

자동 감시를 켠 프로젝트가 있다면, 삭제 전에 대시보드에서 끄거나 그 프로젝트의 `.git/hooks/post-commit` 파일을 지우세요.

## 문제 해결

| 증상 | 해결 |
| --- | --- |
| `vibescan`을 찾을 수 없음 | 설치 단계의 사용자 명령 폴더가 `PATH`에 있는지 확인하세요. Windows는 새 터미널에서 `Get-Command vibescan`, macOS·Linux는 `command -v vibescan`으로 등록 위치를 확인할 수 있습니다. |
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
