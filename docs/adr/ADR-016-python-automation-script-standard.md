# ADR-016: Lambda 자동화 스크립트는 공통 구조를 따름

- 상태: Accepted — **재구성 신뢰도 낮음, 아래 참고**
- 관련 파일: `scripts/*.py` 전체

## ⚠️ 이 문서의 근거에 대해

`scripts/ciem-unused-access-report.py` 상단에 `ADR-016(Python 자동화
스크립트 표준)`이라는 한 줄이 있을 뿐, 그 "표준"이 구체적으로 무엇인지
설명하는 텍스트는 코드 어디에도 없다. 아래 내용은 `scripts/` 아래 실제
Python 파일들(`ciem-unused-access-report.py`, `ciem-key-exception-callback.py`,
`ciem-key-exception-notify.py`, `ciem-boundary-drift-notify.py`,
`eks-pod-isolate.py`, `session-revoke.py`, `rds-view-permission-check.py`
등)이 공통적으로 따르고 있는 패턴을 역산해서 정리한 것이며, "표준 문서"가
원래 이 내용이었는지는 확인할 수 없다.

## Context (추정)

여러 사람이 시차를 두고 자동화 Lambda를 추가해도 구조가 들쭉날쭉해지지
않도록, 공통 골격을 정해뒀을 것으로 보인다.

## Decision (추정, 코드에서 관찰된 공통 패턴)

1. 진입점 함수 이름은 `handler(event, context)`로 통일한다.
2. `boto3` 클라이언트는 모듈 최상단에서 한 번만 생성해 재사용한다(핸들러
   호출마다 새로 만들지 않음).
3. 필요한 설정값은 Lambda 환경변수(`os.environ`)로 주입받고, 각 스크립트
   상단에서 한 번에 읽어들인다 — 함수 내부 곳곳에서 산발적으로 읽지
   않는다.
4. 자체서명 인증서를 쓰는 내부 엔드포인트(Keycloak 등)를 호출할 때는
   `ssl.create_default_context()` 기반의 전용 컨텍스트를 만들어 검증을
   끄되, 그 사실과 이유를 주석으로 남긴다 — 프로젝트 전역 SSL 검증을
   끄지 않는다.
5. 사람 승인이 필요한 조치([ADR-005](ADR-005-human-approval-for-destructive-actions.md) 결정 5)는 실행 결과를 SNS 또는
   Slack `response_url`로 알림을 남긴다 — 조용히 끝내지 않는다.

## Consequences / 알려진 한계

- 이 문서는 "코드가 실제로 하고 있는 것"을 사후에 기술한 것이라, 표준을
  어긴 스크립트가 있어도 이 문서만 보고는 무엇이 위반인지 원래 의도와
  다를 수 있다.
- 새 자동화 스크립트를 추가할 때 이 문서를 "표준"으로 참고하려면, 먼저
  기존 `scripts/*.py`를 실제로 열어 패턴이 여전히 유효한지 확인하는 게
  안전하다.
