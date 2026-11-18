# 자체 규칙팩

`vibescan/*.yml`은 이번 프로젝트에서 작성한 Semgrep 규칙이다. 외부 레지스트리 규칙을 복사·다운로드하지 않는다. YAML의 JSON 표기법으로 저장해 메타데이터를 표준 라이브러리로도 읽을 수 있다.

규칙에는 `metadata.cwe`, `metadata.kisa`, `metadata.vibescan`의 `title_ko`, `remediation_ko`, `severity`, `confidence`를 반드시 넣는다. 새 규칙은 이 디렉터리에 파일과 같은 이름의 취약/안전 테스트를 추가하면 적용된다. `fix_example`은 선택 사항이며 실행 가능한 자동 수정으로 취급하지 않는다. 원시 코드·메타변수의 값은 보고서에 복사하지 않는다.

`python -m bench.check_rules`는 규칙마다 `semgrep --test --strict`를 실행한다. 모든 규칙에 `ruleid`와 `ok` 표본이 있어야 하고, 파싱·실행 오류나 빠진 검사도 실패 처리한다. Windows에서 Semgrep 1.185의 병렬 테스트가 설정 파일을 동시에 교체하는 문제를 피하도록 규칙별로 순서대로 실행한다. 앱 검사에서는 전체 규칙을 한 번에 실행한다.

직접 추적한 입력→싱크는 Likely, API·설정·가드 부재 추정은 Potential이다. 여러 패턴이 겹친다는 이유만으로 Confirmed나 Likely로 승격하지 않는다. Semgrep CE의 함수 내부 분석과 제한된 프레임워크 패턴만 제공하며 파일·함수 간 흐름을 보장하지 않는다.

`catalog/kisa-2026-web.yml`은 계획서의 CI 매핑 초안이다. 공식 링크의 873쪽 PDF를 다운로드했으나 CI-01~CI-21 체계를 확인하지 못했다. 원문 대조 전까지 `source.verified=false`, 중요도·페이지는 null로 유지한다. 현재 판단기준은 자체 요약이며 공식 문구 인용이 아니다. V-01~04는 VibeScan 추가 분류다.

참고: [KISA 게시물](https://www.kisa.or.kr/2060204/form?postSeq=22), [Semgrep taint 규칙](https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/overview), [규칙 테스트](https://docs.semgrep.dev/writing-rules/testing-rules).
