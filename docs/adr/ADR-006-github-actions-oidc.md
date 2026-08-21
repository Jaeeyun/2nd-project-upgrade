# ADR-006: GitHub Actions는 OIDC로 단기 Role, 정적 키 없음

- 상태: Accepted
- 관련 파일: `22-cicd-oidc.tf`

## Context

CI/CD 파이프라인(GitHub Actions)이 Terraform apply 등으로 AWS를 호출해야
한다. IAM 사용자 Access Key를 GitHub Secrets에 저장하는 방식은 키 유출·
로테이션 부담이 있어([ADR-001](ADR-001-saml-temporary-credentials-for-humans.md)에서 사람에게 이미 적용한 것과 같은 이유), CI에도
동일하게 정적 키 없는 방식을 적용하기로 했다.

## Decision

1. **결정 2**: GitHub Actions OIDC 프로바이더를 등록하고, CI 전용 IAM
   Role이 `AssumeRoleWithWebIdentity`로 단기 자격증명을 받는다. 신뢰
   정책에 특정 저장소(`github_org`/`github_repo`)와 브랜치(`main`) 조건을
   걸어, 다른 저장소/PR 브랜치에서는 이 Role을 assume할 수 없게 한다.
2. CI Role의 초기 권한은 이 프로젝트가 관리하는 리소스 타입으로 한정한
   베이스라인이다(계정 전체 admin이 아님) — 이 초기 권한 자체는
   [ADR-007](ADR-007-ciem-unused-access-cycle.md) 결정 1(4주 관찰 후 최소화) 대상이다.
3. GitHub Actions OIDC의 thumbprint는 GitHub이 주기적으로 갱신할 수 있는
   값이라, apply 전 최신값을 GitHub 공식 문서에서 재확인해야 한다.
4. `sub` 클레임 조건은 리터럴(`repo:org/repo:ref:...`) 형태뿐 아니라 조직
   뒤에 숫자 ID가 `@`로 붙는 형태(`repo:org@<id>/repo@<id>:ref:...`)도
   있어, 와일드카드로 두 형태를 모두 허용한다 — 리터럴만 믿고 조건을
   걸면 `AssumeRoleWithWebIdentity`가 막힌다.

## Consequences / 알려진 한계

- `github_org`/`github_repo` 값을 실제 값으로 채우지 않으면 신뢰 정책
  조건이 의미 없이 넓어지거나 아예 막힐 수 있다 — apply 전 필수 확인
  항목이다.
- thumbprint는 GitHub 쪽에서 갱신될 수 있는 외부 종속값이라, 이 저장소가
  통제할 수 없는 변경에 노출되어 있다.
