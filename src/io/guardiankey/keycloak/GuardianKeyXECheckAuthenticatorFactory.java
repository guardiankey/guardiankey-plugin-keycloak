package io.guardiankey.keycloak;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class GuardianKeyXECheckAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "guardiankey-xe-check";
    private static final GuardianKeyXECheckAuthenticator SINGLETON = new GuardianKeyXECheckAuthenticator();
    private static final Requirement[] REQUIREMENT_CHOICES = {
        AuthenticationExecutionModel.Requirement.REQUIRED,
        AuthenticationExecutionModel.Requirement.DISABLED
    };

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        configProperties.addAll(GuardianKeyXEConfig.commonProperties());
    }

    @Override
    public Authenticator create(KeycloakSession session) { return SINGLETON; }

    @Override
    public void init(Scope config) { }

    @Override
    public void postInit(KeycloakSessionFactory factory) { }

    @Override
    public void close() { }

    @Override
    public String getId() { return PROVIDER_ID; }

    @Override
    public String getDisplayType() { return "GuardianKey XE Check"; }

    @Override
    public String getReferenceCategory() { return "GuardianKey XE"; }

    @Override
    public String getHelpText() {
        return "GuardianKey XE — Step 2 of 2. After credentials are validated, calls /checkaccessxe with the captured gkas_solution and the user context, then enforces ALLOW/NOTIFY/BLOCK.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() { return configProperties; }

    @Override
    public boolean isConfigurable() { return true; }

    @Override
    public Requirement[] getRequirementChoices() { return REQUIREMENT_CHOICES; }

    @Override
    public boolean isUserSetupAllowed() { return false; }
}
