# WE_MEET

VibeScan은 사용자 PC에서 Git 저장소를 점검하고, 발견한 문제의 위치와 수정 방법을 한국어로 알려주는 보안 진단기입니다. 개발 중인 로컬 대시보드와 CLI는 엔진의 `scan_result.json`을 공유합니다.

## 저장소 구조

| 경로 | 역할 |
| --- | --- |
| `vibescan/register.py` | 브라우저를 통한 ChatGPT 클라이언트 최초 등록 |
| `scanner/models.py` | 발견 한 건을 나타내는 `Finding`, 스캔 전체를 나타내는 `ScanResult`, JSON 직렬화 |
| [`vulnapp/`](vulnapp/README.md) | 로컬 Flask 샘플 앱과 탐지 기준표 |
| `tests/` | 엔진과 대시보드가 공유하는 데이터 형식 검증 |
| `dashboard/` | Sprint 2에서 구현할 웹 화면 |

## 개발 시작

Python 3.11 이상에서 저장소 루트에서 실행합니다. 샘플 앱 테스트에는 Flask가 필요합니다.

```sh
python -m pip install -r vulnapp/requirements.txt
python -m unittest discover -s tests -v
```

`ScanResult.to_json()`은 한국어를 유지한 JSON 문자열을 반환합니다. `mode`는 실행 URL 유무에 따라 `source-only` 또는 `graybox`가 되며, `summary`는 발견 목록에서 심각도별 건수를 계산합니다. `risk_score`는 엔진이 산정해 전달할 0~100점 값입니다.

## ChatGPT 클라이언트 최초 등록

저장소 루트에서 다음 명령을 실행한 뒤 기본 브라우저에서 계정과 워크스페이스를 선택하고 권한 요청을 검토합니다.

```sh
python -m vibescan.register
```

명령은 `127.0.0.1`의 임시 포트에서 최대 5분간 응답을 기다립니다. 승인하면 설치 식별자와 발급된 클라이언트 ID가 Windows의 `%LOCALAPPDATA%/vibescan`, 그 밖의 환경의 `$XDG_CONFIG_HOME/vibescan`(기본 `~/.config/vibescan`)에 저장됩니다. 같은 설치에서 다시 실행하면 기존 등록을 확인합니다. 현재 명령은 첫 프로필의 등록까지 처리합니다. 로그인 세션을 만드는 토큰 교환과 구독을 사용하는 모델 호출은 후속 작업입니다. [OpenAI 등록 문서](https://developers.openai.com/siwc/token-sharing-open-source/sign-in)

## v6 기반 작업 진행 상황

- [x] ChatGPT 클라이언트 등록 명령 구현 및 콜백 처리 테스트
- [ ] 실제 계정 동의 및 클라이언트 ID 발급 확인
- [x] 저장소 구조 및 기본 Finding / ScanResult 데이터 모델
- [ ] 커밋·기준 커밋·발견 변화량 필드 및 SQLite 스캔 이력 스키마
- [x] 로컬 Flask 샘플 앱 구성
- [ ] Semgrep 실행 및 JSON 결과 파싱 확인
