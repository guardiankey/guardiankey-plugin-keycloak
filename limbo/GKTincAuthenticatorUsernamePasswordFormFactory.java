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

public class GKTincAuthenticatorUsernamePasswordFormFactory extends UsernamePasswordFormFactory {

    public static final String PROVIDER_ID = "gktinc-authenticator";
    private static final GKTincAuthenticatorUsernamePasswordForm SINGLETON = new GKTincAuthenticatorUsernamePasswordForm();
    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
        AuthenticationExecutionModel.Requirement.REQUIRED,
        AuthenticationExecutionModel.Requirement.DISABLED
    };
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty p1 = new ProviderConfigProperty();
        p1.setName("gktinc.apikey");
        p1.setLabel("API Key");
        p1.setHelpText("GKTinc API Key, obtained from the GuardianKey panel.");
        p1.setType(ProviderConfigProperty.STRING_TYPE);

        ProviderConfigProperty p2 = new ProviderConfigProperty();
        p2.setName("gktinc.protectiongrouphashid");
        p2.setLabel("Protection Group Hash ID");
        p2.setHelpText("Hash ID of the GKTinc protection group, obtained from the GuardianKey panel.");
        p2.setType(ProviderConfigProperty.STRING_TYPE);

        ProviderConfigProperty p3 = new ProviderConfigProperty();
        p3.setName("gktinc.apiurl");
        p3.setLabel("API URL");
        p3.setHelpText("GKTinc API URL. Use 'https://api.guardiankey.io/' for cloud.");
        p3.setDefaultValue("https://api.guardiankey.io/");
        p3.setType(ProviderConfigProperty.STRING_TYPE);

        ProviderConfigProperty p4 = new ProviderConfigProperty();
        p4.setName("gktinc.agentid");
        p4.setLabel("Agent ID");
        p4.setHelpText("Identifier for this Keycloak instance sent in events.");
        p4.setDefaultValue("gktinc-keycloak-plugin-v1.0.0");
        p4.setType(ProviderConfigProperty.STRING_TYPE);

        ProviderConfigProperty p5 = new ProviderConfigProperty();
        p5.setName("gktinc.useipreputation");
        p5.setLabel("Use IP Reputation Check?");
        p5.setHelpText("If enabled, queries the API before showing the login page to get a dynamic challenge level based on IP reputation. If disabled, uses challenge level 2 by default.");
        p5.setDefaultValue("false");
        p5.setType(ProviderConfigProperty.BOOLEAN_TYPE);

        ProviderConfigProperty p6 = new ProviderConfigProperty();
        p6.setName("gktinc.failopen");
        p6.setLabel("Fail open?");
        p6.setHelpText("If the GKTinc API is unreachable or returns an error, allow the login to proceed (fail open). Recommended: true.");
        p6.setDefaultValue("true");
        p6.setType(ProviderConfigProperty.BOOLEAN_TYPE);

        configProperties.add(p1);
        configProperties.add(p2);
        configProperties.add(p3);
        configProperties.add(p4);
        configProperties.add(p5);
        configProperties.add(p6);
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
    public String getDisplayType() { return "GKTinc Authenticator"; }

    @Override
    public String getReferenceCategory() { return "GKTinc"; }

    @Override
    public String getHelpText() {
        return "Validates a cryptographic challenge silently resolved by the browser to deter automated attacks (bots, brute force, credential stuffing).";
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
