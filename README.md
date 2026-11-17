# WE_MEET

AI로 만든 웹앱의 소스 코드를 점검하고, 발견한 문제의 위치와 수정 방법을 한국어로 알려주는 보안 진단기를 개발합니다. 엔진이 생성할 `scan_result.json`을 CLI와 웹 대시보드가 공유합니다.

## 저장소 구조

| 경로 | 역할 |
| --- | --- |
| `scanner/models.py` | 발견 한 건을 나타내는 `Finding`, 스캔 전체를 나타내는 `ScanResult`, JSON 직렬화 |
| `vulnapp/` | Sprint 0에서 추가할 로컬 Flask 샘플 앱 |
| `tests/` | 엔진과 대시보드가 공유하는 데이터 형식 검증 |
| `dashboard/` | Sprint 2에서 구현할 웹 화면 |

## 개발 시작

Python 3.11 이상에서 저장소 루트에서 실행합니다. 현재 모델과 테스트는 표준 라이브러리만 사용합니다.

```sh
python -m unittest discover -s tests -v
```

`ScanResult.to_json()`은 한국어를 유지한 JSON 문자열을 반환합니다. `mode`는 실행 URL 유무에 따라 `source-only` 또는 `graybox`가 되며, `summary`는 발견 목록에서 심각도별 건수를 계산합니다. `risk_score`는 엔진이 산정해 전달할 0~100점 값입니다.

## Sprint 0 진행 상황

- [x] 저장소 구조 및 Finding / ScanResult 데이터 모델
- [ ] 로컬 Flask 샘플 앱 구성
- [ ] Semgrep 실행 및 JSON 결과 파싱 확인
- [ ] 로컬 Ollama 모델의 OpenAI 호환 호출 확인
