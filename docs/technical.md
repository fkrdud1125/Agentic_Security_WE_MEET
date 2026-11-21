# VibeScan 기술 문서

README에서 옮긴 엔진·데이터 형식·진단 범위의 세부 설명입니다. 사용 방법은 [README](../README.md)를 보세요.

## 저장소 구조

| 경로 | 역할 |
| --- | --- |
| `vibescan/register.py` | 브라우저를 통한 ChatGPT 클라이언트 최초 등록 |
| `scanner/models.py` | 발견 한 건을 나타내는 `Finding`, 스캔 전체를 나타내는 `ScanResult`, JSON 직렬화 |
| `scanner/history.py` | 커밋별 스캔 및 발견 이력을 SQLite에 저장·조회 |
| [`vulnapp/`](../vulnapp/README.md) | 로컬 Flask 샘플 앱과 탐지 기준표 |
| `tests/` | 엔진과 대시보드가 공유하는 데이터 형식 검증 |
| `vibescan/dashboard.py`, `vibescan/web/` | 로컬 결과 조회 API와 대시보드 화면 |

## 설치 및 수동 진단

Python 3.11 이상과 Git이 필요합니다. 저장소 루트에서 가상환경에 설치합니다.

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install .
.\.venv\Scripts\python -m vibescan.register
.\.venv\Scripts\vibescan login
.\.venv\Scripts\vibescan scan ..\vulnapp-repo
```

이미 클라이언트를 등록한 PC에서는 `login`부터 진행합니다. 샘플을 독립 저장소로 만드는 방법은 [샘플 README](../vulnapp/README.md)에 있습니다. macOS·Linux에서는 가상환경의 `bin/vibescan`을 사용합니다.

- 기본 스캔은 HEAD 커밋의 텍스트 파일을 읽습니다. 변경 중인 작업 트리, 링크, 빌드 산출물은 제외합니다. 커밋된 `.env`·개인키·서비스 계정 파일은 내용을 스냅샷에 쓰거나 모델에 보내지 않고 경로·종류·환경변수 이름만 기록합니다. 이미 추적된 민감 파일은 `.gitignore`에 있어도 보고하며, 명시적인 `.vibescanignore` 제외는 존중합니다. `.env.example`/`.env.sample`은 일반 텍스트 검사 대상입니다.
- 파일 수집·로컬 구조 분석·정적 검사·이전 결과 비교를 먼저 실행합니다. AI 사전 정찰·계획 호출은 생략하며 기본 검사 범위를 사용합니다. 온라인 모드에서 검토 가능한 후보가 있을 때만 인증과 모델 조회를 수행한 뒤, 비밀값과 주석을 가린 Python 코드 문맥으로 AI 2차 검토를 요청합니다. 모델 검토는 심각도순 최대 30건, 요청당 5건입니다. 후보가 없거나 지원 문맥이 없으면 인증·모델 조회도 생략합니다. 백그라운드 선택 검토는 기존처럼 새 High 이상만 대상으로 합니다.
- AI 검토는 탐지 후보의 오탐 가능성·심각도·수정 방법을 보강합니다. 미탐 없음이나 실제 악용 가능성을 확정하지 않습니다. AI 검토 완료 수와 대상 수, 생략·실패 이유는 `analysis_note`에 저장하여 다시 연 결과에서도 표시하며, 원래 탐지 근거와 미검토 결과를 보존합니다. 보고서는 저장된 검토 결과로 렌더링하고 별도 AI 요청을 하지 않습니다.
- `vibescan scan <경로> --offline`은 모델 호출을 생략합니다. 미로그인·구독 권한 부족·사용량 초과·모델 응답 오류에서도 정적 결과와 한국어 조치 안내가 남습니다. 파일 파싱 실패는 부분 점검으로 기록하고 나머지 결과를 보존합니다. 규칙·엔진 오류는 실패로 종료합니다.
- 출력된 실행 폴더의 `scan_result.json`과 `report.md`에 결과가 있습니다. `--output <폴더>`로 저장 위치를 정할 수 있습니다. 기본 위치는 사용자 설정 디렉터리 아래의 `scans/<scan_id>`이며, 메타데이터 이력은 같은 설정 디렉터리의 `scan-history.sqlite3`에 저장합니다.
- 로그인은 `127.0.0.1`의 임시 포트에서 진행합니다. 세션은 Windows에서 현재 사용자 DPAPI, POSIX에서 사용자 전용 권한으로 보호합니다. 사용량과 앱 권한은 ChatGPT 설정에서 관리할 수 있습니다.

자체 Semgrep 규칙은 Python·JS/TS의 SQL/코드 실행/XSS/파일 접근, Python 업로드·JWT·SSRF, JS JWT·CORS·쿠키·오류 응답, Jinja/Vue/Svelte의 원시 HTML 패턴을 검사합니다. 자체 검사기는 시크릿, Python 설정, Flask/FastAPI/Express 라우트의 관리자 가드·객체 소유자 확인 후보를 보탭니다. 점수는 열린 발견에 Critical 40, High 20, Medium 10, Low 3, Info 0을 합해 최대 100으로 제한합니다. 모델의 오탐 후보 판정과 최초 심각도는 보존합니다.

Java 규칙 `vs-java-sql`은 같은 메서드의 Spring MVC·Servlet 입력과 JDBC SQL 본문을 검사합니다. 파일 간 검사기는 Tree-sitter로 로컬 소스를 파싱하고 메서드 인자, 지역 변수, 문자열 결합, 반환값을 따라갑니다. 선언 타입·메서드 이름·인자 개수로 호출 대상을 찾고 직접 구현한 인터페이스의 구현 메서드도 연결합니다. 바인딩 인자에만 전달한 값은 SQL 발견에서 제외합니다. 같은 인자 개수의 여러 후보, 분기·반복문, 재귀 및 탐색 상한(깊이 16, 진입점당 메서드 256회)에서는 정밀한 경로를 보장하지 않습니다.

Spring MVC에서는 클래스와 메서드의 리터럴 경로를 합치고, 숫자 `@Order` 순서에 따라 적용되는 필터 체인과 첫 일치 인가 규칙을 확인합니다. 지원 범위는 직접 구성한 `authorizeHttpRequests`, 정확한 경로와 접미 `/**`, HTTP 메서드, 표준 관리자 역할 및 메서드 보안 단서입니다. 복잡한 경로 표현, 동적 정책, 순서가 불분명한 체인은 수동 확인으로 남깁니다. 인가 후보의 근거는 핸들러 위치와 필터 체인 설정 위치이며 실제 배포에서 호출 가능하다는 판정은 별도로 검증해야 합니다.

모델 수정 diff는 문맥·Python 문법을 확인한 **동작 검증 전 제안**이며 자동 적용하지 않습니다. 모델 코드 발췌는 아직 Python만 지원합니다. 인증·인가와 쿠키 검사는 정적 단서만 제공하며 실제 미들웨어·업무 권한·배포 상태는 수동 확인해야 합니다.

## 진단 보강 (Sprint 2.5)

[세부계획과 구현 한계](diagnosis-plan.md) · [규칙 작성·검증](../rules/README.md) · [합성 표본 벤치마크](../bench/report.md)

발견에 `rule_id`, `fingerprint`, `kisa`가 추가되고 SQLite는 기존 이력을 보존하며 열을 추가합니다. Python 지문은 줄 이동·공백·주석 변화에 독립적입니다. 같은 함수의 동일 코드가 반복된 경우 동일 지문이 될 수 있으며 JS 내부 공백 정규화는 후속 범위입니다. 이 지문으로 직전 스캔과 발견을 비교합니다(아래 ‘커밋별 스캔 이력’).

`criteria`는 주통기 웹 21개와 OWASP Top 10 2025 10개를 합친 31행이며 대시보드와 보고서가 함께 사용합니다. 주통기 표시 코드는 CI·SI·DI 등 사용자 제공 PDF의 웹 항목 코드입니다. 기존 규칙·이력의 `CI-01`~`CI-21` 별칭과 4개 추가 V 분류는 내부 호환성을 위해 유지하고, V 항목을 31개 기준에 추가로 세지 않습니다. 카탈로그의 주통기명·쪽수는 기존 `demo/data/criteria.json`의 PDF 추출 목록에서 가져왔으며 이 변경에서 PDF 원문을 새로 대조한 것은 아닙니다. OWASP 목록 출처는 [공식 2025 목록](https://top10.owasp.org/2025/)입니다.

각 행은 `framework`, `code`, `execution`, `outcome`, `findings`, `dismissed`, `reason`, `ai`를 기록합니다. 실행 상태와 발견 결과를 구분하고 AI 상태는 실제 검토 배치의 성공·실패에서 집계합니다. 관련 KISA 규칙이 끝나도 OWASP 전체 평가를 완료로 간주하지 않습니다. CWE와 내부 기준 연결은 프로젝트의 참고 분류이며 공식 일대일 대응이나 적합성 인증이 아닙니다. `criteria_progress` 콜백은 정적 검사 시작·완료 및 AI 배치 상태를 대시보드와 커밋 훅에 전달합니다. 정적 규칙은 함께 실행되므로 각 기준을 순차적으로 검사하는 것처럼 진행률을 만들지 않습니다.

기존 `kisa_checklist`, `coverage`, `routes`, `config_summary` 필드는 보존합니다. `criteria`가 없는 과거 결과를 읽으면 저장된 실행 기록과 발견으로 기준표를 생성하고 다운로드 보고서에 덧붙입니다. 원본 JSON·보고서는 수정하지 않습니다. 기록이 없는 항목은 미확인으로 남으며 과거 AI 완료 여부를 문장에서 추정하지 않습니다.

```sh
python -m bench.check_rules
python -m bench.run
```

벤치마크는 합성 소스의 취약 표본 35개와 안전 표본 22개를 정적으로 검사합니다. CI는 의존성 검사 표본 P35 외에 미탐이 생기거나 안전 표본에서 오탐이 발생하면 실패합니다. 관리자 경로의 안전 표본 S11에는 관리자 전용 가드가 있습니다. 회귀 테스트에서는 로그인만 확인하는 관리자 경로가 계속 검토 후보로 남는지도 검사합니다. 의존성 검사, Django/Next.js 라우트·BaaS 정책·동적 검사는 후속 단계입니다.

[단계별 구현 계획과 검증 기준](sprint1.md)

## 커밋별 스캔 이력

일반 폴더는 검사할 파일을 임시 디렉터리에서 읽습니다. 관리용 Git 저장소에는 검사 시점을 나타내는 빈 커밋만 추가합니다. 이전 버전이 만든 커밋이나 보고서에는 당시 수집한 값이 남아 있을 수 있습니다.

변화 비교는 같은 브랜치에서 검사한 현재 커밋 또는 그 조상 커밋을 기준으로 합니다. 브랜치를 전환하거나 이력을 다시 작성한 뒤 비교 가능한 검사가 없으면 해결 건수를 집계하지 않습니다.

엔진은 `ScanResult`에 `branch`, `commit`, `scan_type`(full/diff), `trigger`(manual/git-hook/watcher)를 지정합니다. 변경분 스캔에는 `baseline_commit`도 필요하며, 전체 스캔에서는 비교에 쓴 직전 스캔의 커밋입니다. 각 발견의 `change`는 new/existing/fixed, `introduced_in`은 처음 발견된 커밋입니다. 변화가 판정되지 않은 과거 결과에서는 두 필드가 `null`입니다. `delta`는 명시된 new/fixed 건수를 세고, 심각도 요약에서는 이번 비교에서 해결된 발견을 제외합니다. 비교 기준으로 선택한 검사 결과와 발견 지문을 맞춰 new/existing/fixed를 정하고, 사라진 발견은 `fixed` 항목으로 결과에 남깁니다. 이번에 파싱하지 못한 파일의 이전 발견은 해결로 보지 않고 `existing`으로 유지합니다.

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
- [x] Semgrep 실행 및 JSON 결과 파싱 확인 ([원본 결과](../tests/fixtures/semgrep-sample.json) · [실행 기록](https://github.com/jubin0615/WE_MEET/actions/runs/44067063217))
