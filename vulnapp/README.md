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

```sh
python -m unittest discover -s tests -p test_vulnapp.py -v
```
