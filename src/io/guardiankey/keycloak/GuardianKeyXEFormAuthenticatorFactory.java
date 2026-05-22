package io.guardiankey.keycloak;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class GuardianKeyXEFormAuthenticatorFactory extends UsernamePasswordFormFactory {

    public static final String PROVIDER_ID = "guardiankey-xe-form";
    private static final GuardianKeyXEFormAuthenticator SINGLETON = new GuardianKeyXEFormAuthenticator();
    private static final Requirement[] REQUIREMENT_CHOICES = {
        AuthenticationExecutionModel.Requirement.REQUIRED,
        AuthenticationExecutionModel.Requirement.DISABLED
    };

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        configProperties.addAll(GuardianKeyXEConfig.commonProperties());

        ProviderConfigProperty jsUrl = new ProviderConfigProperty();
        jsUrl.setName("guardiankey.xe.jsurl");
        jsUrl.setLabel("Frontend JS URL");
        jsUrl.setHelpText("URL for the GKAS frontend script that collects the device identity (gkas_solution).");
        jsUrl.setDefaultValue("https://guardiankey.io/js/gkas-setup-latest.js?v=1");
        jsUrl.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(jsUrl);
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
    public String getDisplayType() { return "GuardianKey XE Form"; }

    @Override
    public String getReferenceCategory() { return "GuardianKey XE"; }

    @Override
    public String getHelpText() {
        return "GuardianKey XE — Step 1 of 2. Renders the username/password form with the GKAS device-identity script injected, validates credentials, and captures gkas_solution for the XE Check step.";
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
