package com.ztplatform.opagate;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.List;

/**
 * ADR-022. getId()가 반환하는 "opa-context-gate"가 브라우저 플로우에
 * execution으로 추가할 때 kcadm이 참조하는 provider id다
 * (keycloak-bootstrap.sh.tpl의 등록 스텝, [검증 필요]).
 */
public class OpaContextAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "opa-context-gate";
    private static final OpaContextAuthenticator SINGLETON = new OpaContextAuthenticator();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "OPA Login Context Gate";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED,
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "로그인 성공 직후 발신 IP + MFA 등록 여부를 OPA 정책엔진에 물어 최종 허용 여부를 재확인한다(ADR-022).";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
        // 설정 없음
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // 없음
    }

    @Override
    public void close() {
        // 없음
    }
}
