# WE_MEET

VibeScan은 사용자 PC에서 Git 저장소를 점검하고, 발견한 문제의 위치와 수정 방법을 한국어로 알려주는 보안 진단기입니다. CLI에서 로그인 → 코드 정찰·점검 계획 → 정적 검사·트리아지 → JSON·한국어 보고서 저장까지 수행하며, 로컬 대시보드에서 저장된 결과를 확인할 수 있습니다.

## 저장소 구조

| 경로 | 역할 |
| --- | --- |
| `vibescan/register.py` | 브라우저를 통한 ChatGPT 클라이언트 최초 등록 |
| `scanner/models.py` | 발견 한 건을 나타내는 `Finding`, 스캔 전체를 나타내는 `ScanResult`, JSON 직렬화 |
| `scanner/history.py` | 커밋별 스캔 및 발견 이력을 SQLite에 저장·조회 |
| [`vulnapp/`](vulnapp/README.md) | 로컬 Flask 샘플 앱과 탐지 기준표 |
| `tests/` | 엔진과 대시보드가 공유하는 데이터 형식 검증 |
| `vibescan/dashboard.py`, `vibescan/web/` | 로컬 결과 조회 API와 대시보드 화면 |

## 개발 시작

Python 3.11 이상에서 저장소 루트에서 실행합니다. 샘플 앱 테스트에는 Flask가 필요합니다.

```sh
python -m pip install . -r vulnapp/requirements.txt httpx
python -m unittest discover -s tests -v
```

`ScanResult.to_json()`은 한국어를 유지한 JSON 문자열을 반환합니다. `mode`는 실행 URL 유무에 따라 `source-only` 또는 `graybox`가 되며, `summary`는 발견 목록에서 심각도별 건수를 계산합니다. `risk_score`는 엔진이 산정해 전달할 0~100점 값입니다.

## 설치 및 수동 진단

Python 3.11 이상과 Git이 필요합니다. 저장소 루트에서 가상환경에 설치합니다.

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install .
.\.venv\Scripts\python -m vibescan.register
.\.venv\Scripts\vibescan login
.\.venv\Scripts\vibescan scan ..\vulnapp-repo
```

이미 클라이언트를 등록한 PC에서는 `login`부터 진행합니다. 샘플을 독립 저장소로 만드는 방법은 [샘플 README](vulnapp/README.md)에 있습니다. macOS·Linux에서는 가상환경의 `bin/vibescan`을 사용합니다.

- 기본 스캔은 HEAD 커밋의 텍스트 파일을 읽습니다. 변경 중인 작업 트리, 링크, 빌드 산출물은 제외합니다. 커밋된 `.env`·개인키·서비스 계정 파일은 내용을 스냅샷에 쓰거나 모델에 보내지 않고 경로·종류·환경변수 이름만 기록합니다. 이미 추적된 민감 파일은 `.gitignore`에 있어도 보고하며, 명시적인 `.vibescanignore` 제외는 존중합니다. `.env.example`/`.env.sample`은 일반 텍스트 검사 대상입니다.
- 수동 로그인 상태에서는 계정의 모델 목록을 조회하고 정찰·계획과 발견 리뷰를 요청합니다. 비밀값을 가린 주변 코드로 입력·DB·라우트·인증 단서를 분석하고, 5종 점검의 이유·우선순위와 근거를 기록합니다. 모델 검토는 심각도순 최대 30건, 요청당 5건입니다.
- `vibescan scan <경로> --offline`은 모델 호출을 생략합니다. 미로그인·구독 권한 부족·사용량 초과·모델 응답 오류에서도 정적 결과와 한국어 조치 안내가 남습니다. 파일 파싱 실패는 부분 점검으로 기록하고 나머지 결과를 보존합니다. 규칙·엔진 오류는 실패로 종료합니다.
- 출력된 실행 폴더의 `scan_result.json`과 `report.md`에 결과가 있습니다. `--output <폴더>`로 저장 위치를 정할 수 있습니다. 기본 위치는 사용자 설정 디렉터리 아래의 `scans/<scan_id>`이며, 메타데이터 이력은 같은 설정 디렉터리의 `scan-history.sqlite3`에 저장합니다.
- 로그인은 `127.0.0.1`의 임시 포트에서 진행합니다. 세션은 Windows에서 현재 사용자 DPAPI, POSIX에서 사용자 전용 권한으로 보호합니다. 사용량과 앱 권한은 ChatGPT 설정에서 관리할 수 있습니다.

자체 Semgrep 규칙은 Python·JS/TS의 SQL/코드 실행/XSS/파일 접근, Python 업로드·JWT·SSRF, JS JWT·CORS·쿠키·오류 응답, Jinja/Vue/Svelte의 원시 HTML 패턴을 검사합니다. 자체 검사기는 시크릿, Python 설정, Flask/FastAPI/Express 라우트의 관리자 가드·객체 소유자 확인 후보를 보탭니다. 점수는 열린 발견에 Critical 40, High 20, Medium 10, Low 3, Info 0을 합해 최대 100으로 제한합니다. 모델의 오탐 후보 판정과 최초 심각도는 보존합니다.

모델 수정 diff는 문맥·Python 문법을 확인한 **동작 검증 전 제안**이며 자동 적용하지 않습니다. 모델 코드 발췌는 아직 Python만 지원합니다. 인증·인가와 쿠키 검사는 정적 단서만 제공하며 실제 미들웨어·업무 권한·배포 상태는 수동 확인해야 합니다.

## 진단 보강 (Sprint 2.5)

[세부계획과 구현 한계](docs/diagnosis-plan.md) · [규칙 작성·검증](rules/README.md) · [합성 표본 벤치마크](bench/report.md)

발견에 `rule_id`, `fingerprint`, `kisa`가 추가되고 SQLite는 기존 이력을 보존하며 열을 추가합니다. Python 지문은 줄 이동·공백·주석 변화에 독립적입니다. 같은 함수의 동일 코드가 반복된 경우 동일 지문이 될 수 있으며 JS 내부 공백 정규화는 후속 범위입니다. 이 지문으로 직전 스캔과 발견을 비교합니다(아래 ‘커밋별 스캔 이력’).

21개 CI + 4개 V 분류 매핑, 엔드포인트·설정 수집은 검사 범위 판정 등 **내부 처리에만 쓰고 보고서와 대시보드에는 표시하지 않습니다.** 결과 JSON(`kisa_checklist`, `routes`, `config_summary`)에는 남습니다. **CI 분류는 사용자 계획서 기반 초안이며 KISA 원문 대조 미완료**입니다. 연결된 공식 PDF에서 이 CI 체계를 확인하지 못해 중요도·페이지 번호를 비워 두었습니다. KISA 공식 평가나 양호 판정으로 사용하지 마세요.

```sh
python -m bench.check_rules
python -m bench.run
```

벤치마크는 계획서의 35개 패턴을 재구성한 합성 소스와 안전 표본 22개를 사용하며 실행하지 않습니다. CI는 탐지 34/35 미만 또는 안전 표본 오탐 발생 시 실패합니다. 미탐인 의존성 검사, 추가 LLM 설계, Django/Next.js 라우트·BaaS 정책·동적 검사는 후속 단계입니다.

[단계별 구현 계획과 검증 기준](docs/sprint1.md)

## 로컬 대시보드 (Sprint 2 첫 단계)

설치 후 `vibescan` 또는 `python -m vibescan`을 실행하면 기본 브라우저에 대시보드가 열립니다. 저장소에서 가상환경으로 실행하려면 다음 명령을 사용합니다.

```powershell
.\.venv\Scripts\python -m vibescan
# scan --output으로 별도 저장한 결과를 볼 때
.\.venv\Scripts\python -m vibescan dashboard --results "C:\path\to\scan-output"
```

기본 결과 위치는 사용자 설정 디렉터리의 `scans`입니다. 지정 폴더 바로 아래 `<scan_id>/scan_result.json`을 읽어 스캔 이력·위험 점수·검사 범위·우선 확인 항목과 발견 상세를 표시합니다. 심각도·상태·파일/제목/유형 필터, 수정안 복사, 한국어 Markdown 보고서 다운로드를 지원합니다. **결과 새로고침은 저장된 파일을 다시 읽으며 스캔을 실행하지 않습니다.**

‘레포 연결’에 Git 저장소 루트 경로나 GitHub 주소(`https://github.com/소유자/저장소`)를 입력해 연결한 뒤 ‘다시 스캔’을 누르면 현재 HEAD를 전체 검사하고, 완료되면 새 결과를 자동으로 엽니다. 기본은 로컬 규칙만 쓰는 정적 검사이며, ‘ChatGPT 분석 사용’을 체크한 경우에만 연결한 계정으로 모델 분석을 요청합니다. 로그인은 대시보드의 ‘ChatGPT로 로그인’ 또는 `vibescan login`으로 하며, 사용 한도 초과·구독 자격 없음·로그인 만료로 모델 분석이 멈추면 정적 검사 결과를 저장하고 원인과 조치를 안내합니다. GitHub 주소는 설정 폴더의 `github/`에 clone되며 스캔할 때마다 최신 커밋을 가져옵니다. 비공개 저장소는 이 PC의 Git 인증을 사용합니다. 로그아웃은 이 PC에 저장된 토큰만 지우므로, 앱 연결 자체를 끊으려면 ChatGPT 설정에서 해제하세요. 미커밋 변경은 제외되고, 한 번에 하나의 스캔만 실행되며, 실패해도 이전 결과는 유지됩니다.

커밋 변화는 같은 레포의 직전 스캔과 비교한 새 발견·해결 건수이며, 비교할 이전 결과가 없으면 `비교 전`으로 표시합니다. 위험 점수 타일에는 최근 12회 스캔의 점수 추이를 표시합니다. ‘커밋 후 자동 스캔 켜기’를 누르면 레포에 `post-commit` hook이 설치되어, 커밋할 때마다 백그라운드에서 정적 검사가 실행되고 결과가 대시보드에 자동으로 나타납니다(대시보드가 꺼져 있어도 저장). 다른 hook이 이미 있으면 덮어쓰지 않고 추가할 한 줄을 안내합니다. 스캔 중에는 5단계 진행 표시와 활동 로그가 보이고, 자동 스캔에서 새로 생긴 Critical/High가 있으면 화면 경고와 브라우저 알림을 띄웁니다. 자동 스캔은 기본적으로 ChatGPT를 쓰지 않으며, ‘커밋 후 자동 스캔에서도 ChatGPT 검토 사용’을 켜면 새로 생긴 High 이상 발견만 검토합니다. 검사 범위가 없는 과거 결과는 `검사 여부 미확인`으로 취급하고, 손상되거나 16 MiB를 초과한 결과는 읽을 수 없는 항목으로 안내합니다. 출력 파일을 옮기거나 삭제했다면 SQLite 메타데이터만으로 상세 내용을 복구하지 않습니다.

대시보드는 `127.0.0.1` 임시 포트에서 실행되며 종료는 터미널의 `Ctrl+C`입니다. 출력된 접속 주소는 결과 열람 권한을 포함하므로 공유하지 마세요. 외부 CDN·폰트·분석 스크립트는 없습니다. 소스는 읽기만 하며, 스캔 실행 시에만 새 결과 폴더와 이력 DB(연결 레포 포함)에 기록합니다.

Sprint 2 흐름(로그인 → 레포 연결 → 스캔 → 확인)이 완성되었습니다. [구현 범위와 확인 결과](docs/sprint2.md) · Sprint 3 진행 상황은 [docs/sprint3.md](docs/sprint3.md)에 있습니다.

## 커밋별 스캔 이력

엔진은 `ScanResult`에 `branch`, `commit`, `scan_type`(full/diff), `trigger`(manual/git-hook/watcher)를 지정합니다. 변경분 스캔에는 `baseline_commit`도 필요하며, 전체 스캔에서는 비교에 쓴 직전 스캔의 커밋입니다. 각 발견의 `change`는 new/existing/fixed, `introduced_in`은 처음 발견된 커밋입니다. 변화가 판정되지 않은 과거 결과에서는 두 필드가 `null`입니다. `delta`는 명시된 new/fixed 건수를 세고, 심각도 요약에서는 이번 비교에서 해결된 발견을 제외합니다. 스캔할 때마다 같은 레포의 가장 최근 결과와 발견 지문을 맞춰 new/existing/fixed를 정하고, 사라진 발견은 `fixed` 항목으로 결과에 남깁니다. 이번에 파싱하지 못한 파일의 이전 발견은 해결로 보지 않고 `existing`으로 유지합니다.

기존 형식 또는 v6 형식의 `scan_result.json`을 다음처럼 이력에 추가할 수 있습니다.

```python
from pathlib import Path
from scanner.history import list_scans, save_scan
from scanner.models import ScanResult

result = ScanResult.from_json(Path("scan_result.json").read_text(encoding="utf-8"))
database = Path("scan-history.sqlite3")
save_scan(database, result)
print(list_scans(database, result.target.source))
```

이력의 단위는 `scan_id`입니다. 같은 커밋을 다시 스캔하면 별도의 ID를 사용합니다. 중복 ID는 저장 오류로 처리하고 기존 기록을 유지합니다. SQLite에는 커밋·점수·변화 건수와 발견별 분류·위치를 저장합니다. 근거 코드, 수정 diff, 보고서 본문은 입력 JSON에만 있습니다.

## ChatGPT 클라이언트 최초 등록

저장소 루트에서 다음 명령을 실행한 뒤 기본 브라우저에서 계정과 워크스페이스를 선택하고 권한 요청을 검토합니다.

```sh
python -m vibescan.register
```

명령은 `127.0.0.1`의 임시 포트에서 최대 5분간 응답을 기다립니다. 승인하면 설치 식별자와 발급된 클라이언트 ID가 Windows의 `%LOCALAPPDATA%/vibescan`, 그 밖의 환경의 `$XDG_CONFIG_HOME/vibescan`(기본 `~/.config/vibescan`)에 저장됩니다. 같은 설치에서 다시 실행하면 기존 등록을 확인합니다. 등록 후 아래의 로그인 명령으로 같은 계정에 연결합니다. [OpenAI 등록 문서](https://developers.openai.com/siwc/token-sharing-open-source/sign-in)

## v6 기반 작업 진행 상황

- [x] ChatGPT 클라이언트 등록 명령 구현 및 콜백 처리 테스트
- [x] 실제 설치에서 ChatGPT 클라이언트 등록 완료 (사용자 확인)
- [x] 저장소 구조 및 기본 Finding / ScanResult 데이터 모델
- [x] 커밋·기준 커밋·발견 변화량 필드 및 SQLite 스캔 이력 스키마
- [x] 로컬 Flask 샘플 앱 구성
- [x] Semgrep 실행 및 JSON 결과 파싱 확인 ([원본 결과](tests/fixtures/semgrep-sample.json) · [실행 기록](https://github.com/jubin0615/WE_MEET/actions/runs/44067063217))
