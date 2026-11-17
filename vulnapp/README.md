# 로컬 진단용 Flask 샘플

저장소 루트에서 다음 명령으로 실행합니다. 앱 주소는 `http://127.0.0.1:5000`입니다.

```sh
python -m pip install -r vulnapp/requirements.txt
python -m vulnapp.app
```

## 탐지 기준표

| 유형 | 위치 | 확인할 근거 |
| --- | --- | --- |
| 하드코딩된 시크릿 | `app.py`의 `DEMO_API_TOKEN` | 소스에 테스트 토큰 문자열이 들어 있다. 실제 서비스에서 사용하는 키는 없다. |
| SQL 인젝션 위험 패턴 | `static_cases.py`의 `find_note` | 함수 인자를 SQL 문자열에 결합해 실행한다. |
| 인가 누락 | `app.py`의 `GET /review` | 샘플 정책상 검토자 전용인 고정 메모를 익명 사용자도 읽을 수 있다. |
| XSS 위험 패턴 | `static_cases.py`의 `render_note` | 함수 인자를 이스케이프 없이 신뢰된 마크업으로 표시한다. |
| 보안 헤더·쿠키 설정 누락 | `app.py`의 `GET /` | 응답에 CSP 헤더가 없고 테스트 쿠키에 HttpOnly 속성이 없다. |

SQL과 HTML 표본은 정적 검사 대상입니다. HTTP 입력에서 해당 함수까지 이어지는 경로가 없으므로 두 결과는 보고서에서 코드 패턴 발견으로 기록합니다. 헤더와 쿠키 누락은 같은 유형 안에서 별도 발견으로 집계할 수 있습니다.

## 동작 확인

### Semgrep으로 정적 표본 확인

저장소 루트에서 다음 순서로 실행합니다. 규칙은 저장소의 `rules/sample.yml`을 사용합니다.

```sh
python -m pip install semgrep==1.185.0
semgrep scan --metrics=off --disable-version-check --no-rewrite-rule-ids --config rules/sample.yml --json-output=semgrep-sample.local.json vulnapp
python tests/verify_semgrep_sample.py semgrep-sample.local.json
```

기준 실행에서는 `app.py:8`의 토큰 대입, `static_cases.py:8`의 SQL 실행, `static_cases.py:12`의 마크업 변환을 각각 한 건씩 탐지했습니다. 이 세 규칙은 샘플의 정적 패턴을 확인합니다. 아래 Flask 테스트는 익명 접근과 실제 응답 헤더·쿠키를 확인합니다.

### 독립 Git 저장소로 사용

커밋 비교를 연습하려면 WE_MEET 루트에서 PowerShell로 다음 명령을 실행합니다. 대상은 새 폴더여야 합니다. 첫 커밋을 기준으로 샘플 코드를 수정하고 변경 이력을 쌓을 수 있습니다.

```powershell
$sample = New-Item -ItemType Directory ../vulnapp-repo -ErrorAction Stop
Copy-Item -LiteralPath vulnapp/app.py,vulnapp/static_cases.py,vulnapp/requirements.txt -Destination $sample.FullName
git -C $sample.FullName init -b main
git -C $sample.FullName add -- app.py static_cases.py requirements.txt
git -C $sample.FullName -c user.name=VibeScan -c user.email=fixture@example.invalid commit -m "fix:(로컬 진단 기준 샘플 앱 추가)"
```

### Flask 테스트

```sh
python -m unittest discover -s tests -p test_vulnapp.py -v
```
