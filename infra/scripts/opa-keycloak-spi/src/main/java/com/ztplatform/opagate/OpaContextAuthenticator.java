package com.ztplatform.opagate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * ADR-022: 로그인 컨텍스트 게이트.
 *
 * 브라우저 인증 플로우에서 OTP 실행 "다음" 단계로 배치하는 게 전제다(README 참고) -
 * 그래야 이 코드가 실행되는 시점엔 이미 1차 인증(비밀번호)+OTP를 통과했다는 게
 * 보장된다. 여기서는 그 위에 "발신 IP가 허용 대역인가"를 OPA에 물어서 신뢰
 * 여부를 한 번 더 재확인한다 - Keycloak 로그인 성공만으로 SAML assertion을
 * 내주던 기존 흐름의 공백(맥락 미평가)을 메우는 지점이다.
 *
 * 정책 엔진(OPA)은 같은 EC2의 localhost:8181에서만 응답한다(opa-setup.sh) -
 * 네트워크 홉이 없어 지연시간·장애 지점 추가가 최소화된다.
 *
 * ⚠️ Fail 모드: OPA가 응답하지 않으면 이 코드는 fail-closed(로그인 거부)한다.
 * ADR-001이 이미 지적한 "Keycloak 자체가 단일 장애점"이라는 문제와 같은 종류의
 * 트레이드오프가 하나 더 생기는 셈이다 - OPA 프로세스가 죽으면 전사 AWS 로그인이
 * 막힌다. fail-open으로 바꾸려면 아래 catch 블록에서 context.success()를
 * 호출하도록 바꾸면 되지만, 그러면 게이트가 있으나 마나 해진다는 것도
 * 같이 인지해야 한다(ADR-022 Consequences 참고).
 */
public class OpaContextAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(OpaContextAuthenticator.class);
    private static final String OPA_URL = "http://127.0.0.1:8181/v1/data/login_context/allow";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(2))
            .build();

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        String username = user != null ? user.getUsername() : "unknown";
        String sourceIp = context.getConnection().getRemoteAddr();
        boolean mfaConfigured = isMfaConfigured(context.getSession(), context.getRealm(), user);

        boolean allow;
        try {
            allow = queryOpa(username, sourceIp, mfaConfigured);
        } catch (Exception e) {
            // fail-closed: OPA 미응답/오류 시 거부. 이 예외 경로 자체를 별도로
            // 모니터링해야 "OPA가 죽어서 전원 로그인 실패"를 탐지할 수 있다
            // (opa-decision-log-shipper.py는 OPA가 살아있을 때만 로그를 만들므로
            // 이 케이스는 그쪽에 안 잡힌다 - Keycloak 자체 로그/CloudWatch Agent로
            // 별도 감시 필요, [검증 필요]로 남겨둠).
            logger.errorf(e, "OPA 정책 조회 실패 - fail-closed로 로그인 거부 (user=%s)", username);
            context.getEvent().detail("opa_gate", "error:" + e.getClass().getSimpleName());
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
            return;
        }

        context.getEvent().detail("opa_gate", allow ? "allow" : "deny");
        if (allow) {
            context.success();
        } else {
            logger.warnf("OPA 로그인 컨텍스트 게이트 거부: user=%s ip=%s", username, sourceIp);
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
        }
    }

    private boolean isMfaConfigured(KeycloakSession session, RealmModel realm, UserModel user) {
        if (user == null) {
            return false;
        }
        // "이번 로그인에서 OTP를 실제로 입력했는가"가 아니라 "OTP가 등록돼
        // 있는가"를 본다 - 이 Authenticator를 브라우저 플로우의 OTP 실행 단계
        // 뒤에 두면(README 참고) 여기 도달했다는 사실 자체가 그 세션에서 OTP를
        // 통과했다는 뜻이 되므로 실질적으로는 동등하다. 플로우 배치를 지키지
        // 않으면 이 값의 의미가 깨진다.
        return user.credentialManager().isConfiguredFor(OTPCredentialModel.TYPE);
    }

    private boolean queryOpa(String username, String sourceIp, boolean mfaConfigured) throws Exception {
        Map<String, Object> input = new HashMap<>();
        input.put("username", username);
        input.put("source_ip", sourceIp);
        input.put("mfa_configured", mfaConfigured);
        Map<String, Object> body = new HashMap<>();
        body.put("input", input);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(OPA_URL))
                .timeout(Duration.ofSeconds(3))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(body)))
                .build();

        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("OPA HTTP " + response.statusCode());
        }
        JsonNode root = MAPPER.readTree(response.body());
        JsonNode result = root.get("result");
        return result != null && result.asBoolean(false);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // 이 Authenticator는 사용자 입력을 받는 화면이 없다(authenticate()에서
        // 바로 success/failure를 결정) - action()이 호출될 일이 없다.
    }

    @Override
    public boolean requiresUser() {
        return true; // 1차 인증(비밀번호)이 끝나 UserModel이 확정된 뒤에만 의미가 있음
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // 없음
    }

    @Override
    public void close() {
        // 상태 없음 - 정리할 리소스 없음
    }
}
