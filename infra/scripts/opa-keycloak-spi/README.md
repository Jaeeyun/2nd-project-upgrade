# OPA 로그인 컨텍스트 게이트 (Keycloak Authenticator SPI)

ADR-022 참고. Keycloak 브라우저 로그인 플로우에 실행 단계를 하나 추가해서,
1차 인증(비밀번호)+OTP를 통과한 뒤 마지막으로 OPA에 "발신 IP + MFA 등록
여부"를 물어보고 최종 허용 여부를 재확인한다.

## 빌드

```bash
cd infra/opa-keycloak-spi
mvn -q package
# target/opa-context-authenticator-1.0.0.jar 생성됨
```

**검증 완료**: Maven 3.9.9 + JDK 21로 실제 `mvn clean package`까지 돌려서 빌드가
성공하는 것, 산출물 jar 안에 두 `.class`와
`META-INF/services/org.keycloak.authentication.AuthenticatorFactory`가 정상
포함되는 것까지 확인함(`pom.xml` 상단 주석 참고). Keycloak 26.7.0 Maven
아티팩트가 이 버전 문자열 그대로 Maven Central에 실재한다는 것도 이 빌드
성공으로 같이 확인된 셈이다.

## 배포 (개요)

이 jar는 인터넷이 필요한 빌드 산출물이라, OPA 바이너리와 같은 방식으로
사람이 미리(배포 전 1회) S3에 올려둬야 한다:

```bash
aws s3 cp target/opa-context-authenticator-1.0.0.jar \
  "s3://$(cd ../.. && terraform output -raw opa_artifacts_bucket)/spi/opa-context-authenticator-1.0.0.jar"
```

`keycloak-bootstrap.sh.tpl`이 Keycloak 컨테이너를 **최초로 띄우기 전에** 이
경로에서 jar를 받아 `/opt/keycloak/providers/`(컨테이너에 새로 추가한 볼륨
마운트)에 놓는다. `start-dev` 모드는 부팅 시 providers 디렉터리를 자동
스캔/빌드하므로, 별도로 `kc.sh build`를 실행하거나 컨테이너를 재기동할
필요가 없다 - jar가 최초 `docker run` 시점에 이미 마운트돼 있기만 하면 된다.

## 브라우저 플로우 배치 — 반드시 OTP "다음"

`OpaContextAuthenticator.isMfaConfigured()`는 "이 사용자가 OTP를 등록해뒀는가"만
확인하고 "이번 로그인에서 실제로 입력해서 통과했는가"는 별도로 검증하지
않는다. 그래서 **이 실행 단계를 브라우저 플로우에서 OTP 실행 단계보다 반드시
뒤에** 둬야 한다 — 그래야 이 코드가 실행됐다는 사실 자체가 "이번 로그인에서
OTP를 통과했다"는 뜻이 된다. 앞에 두면 이 전제가 깨진다.

**검증 완료 (Docker로 로컬 재현)**: `keycloak-bootstrap.sh.tpl`의 등록
시퀀스(browser 플로우 복제 → "forms" 서브플로우 안에 execution 추가 →
priority를 유지한 채 requirement=REQUIRED로 격상 → realm의 browserFlow
교체)를 실제 Keycloak 26.7.0 컨테이너에 그대로 실행해서 확인했다. 그 결과:

- **execution을 top-level에 추가하면 안 된다.** 최초 구현이 이렇게
  했었는데, top-level에 REQUIRED 요소가 하나라도 있으면 Keycloak이 같은
  레벨의 ALTERNATIVE 요소(Cookie, IdP Redirector, 그리고 **로그인 폼이
  들어있는 "forms" 서브플로우 자체**)를 전부 무시해버린다 - 그러면 로그인
  폼도 없이 곧바로 우리 Authenticator가 실행되려다 "user not set" 예외로
  전체 로그인이 깨진다(컨테이너 로그로 실측 확인).
- **"forms" 서브플로우 안쪽**(Username Password Form과 같은 레벨, Conditional
  2FA 서브플로우 뒤)에 추가해야 한다 - 이 레벨엔 이미 REQUIRED(Username
  Password Form)와 CONDITIONAL(2FA)이 공존하고 있어서 우리 REQUIRED
  execution이 추가돼도 무시되지 않는다.
- requirement를 바꾸는 API도 `authentication/executions/{id}` PUT은
  404였고, `authentication/flows/{flowAlias}/executions` PUT에 **priority를
  같이 보내야** 순서가 안 깨진다(빠뜨리면 0으로 취급돼 맨 앞으로 이동).
- 이렇게 고친 뒤, 실제 로그인 폼에 진짜 비밀번호를 제출해서 우리
  Authenticator가 정상적으로 실행되고 OPA를 호출해 deny를 반환받아
  로그인을 막는 것까지 end-to-end로 확인했다.

## Fail 모드

OPA가 응답하지 않으면 **fail-closed**(로그인 거부)로 구현했다(`OpaContextAuthenticator.authenticate()`의
catch 블록). 이건 곧 OPA 프로세스 하나가 Keycloak처럼 새로운 단일 장애점이
된다는 뜻이다 — ADR-001이 이미 인지한 "Keycloak이 죽으면 아무도 AWS에 못
들어간다"는 트레이드오프와 같은 종류가 하나 더 생긴 것. fail-open으로
바꾸는 것도 가능하지만, 그러면 게이트의 존재 의미 자체가 없어진다는 걸
같이 문서화해야 한다.
