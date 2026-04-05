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

public class GKTincAuthenticatorFactory extends UsernamePasswordFormFactory {

    public static final String PROVIDER_ID = "gktinc-authenticator";
    private static final GKTincAuthenticator SINGLETON = new GKTincAuthenticator();
    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
        AuthenticationExecutionModel.Requirement.REQUIRED,
        AuthenticationExecutionModel.Requirement.DISABLED
    };
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();


    static {

        ProviderConfigProperty p1 = new ProviderConfigProperty();
        p1.setName("gktinc.enablegktinc");
        p1.setLabel("Enable GKTinc?");
        p1.setHelpText("If disabled, this authenticator will do nothing and allow all attempts. This can be used to disable GKTinc without removing the authenticator from the flow.");
        p1.setDefaultValue("true");
        p1.setType(ProviderConfigProperty.BOOLEAN_TYPE);

        ProviderConfigProperty p2 = new ProviderConfigProperty();
        p2.setName("gktinc.verbose");
        p2.setLabel("Verbose?");
        p2.setHelpText("If enabled, prints detailed logs for debugging purposes.");
        p2.setDefaultValue("false");
        p2.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        
        ProviderConfigProperty p3 = new ProviderConfigProperty();
        p3.setName("gktinc.apikey");
        p3.setLabel("API Key");
        p3.setHelpText("GKTinc API Key, obtained from the GuardianKey panel.");
        p3.setType(ProviderConfigProperty.STRING_TYPE);

        ProviderConfigProperty p4 = new ProviderConfigProperty();
        p4.setName("gktinc.protectiongrouphashid");
        p4.setLabel("Protection Group Hash ID");
        p4.setHelpText("Hash ID of the GKTinc protection group, obtained from the GuardianKey panel.");
        p4.setType(ProviderConfigProperty.STRING_TYPE);

        ProviderConfigProperty p5 = new ProviderConfigProperty();
        p5.setName("gktinc.apiurl");
        p5.setLabel("API URL");
        p5.setHelpText("GKTinc API URL. Use 'https://api.guardiankey.io/' for cloud.");
        p5.setDefaultValue("https://api.guardiankey.io/");
        p5.setType(ProviderConfigProperty.STRING_TYPE);

        ProviderConfigProperty p6 = new ProviderConfigProperty();
        p6.setName("gktinc.agentid");
        p6.setLabel("Agent ID");
        p6.setHelpText("Identifier for this Keycloak instance sent in events.");
        p6.setDefaultValue("gktinc-keycloak-plugin-v1.0.0");
        p6.setType(ProviderConfigProperty.STRING_TYPE);

        ProviderConfigProperty p7 = new ProviderConfigProperty();
        p7.setName("gktinc.useipreputation");
        p7.setLabel("Use IP Reputation Check?");
        p7.setHelpText("If enabled, queries the API before showing the login page to get a dynamic challenge level based on IP reputation. If disabled, uses challenge level 2 by default.");
        p7.setDefaultValue("false");
        p7.setType(ProviderConfigProperty.BOOLEAN_TYPE);

        ProviderConfigProperty p8 = new ProviderConfigProperty();
        p8.setName("gktinc.preenforceblock");
        p8.setLabel("Pre-Enforce Block?");
        p8.setHelpText("If enabled, blocked origins by policies will be blocked before showing the login page. If disabled, the login page will be shown but the challenge will be unsolvable, effectively blocking the login but with a different user experience. Enabling this may reduce load on the server and provide a clearer block to malicious users, but may also cause issues if there are false positives in blocking.");
        p8.setDefaultValue("false");
        p8.setType(ProviderConfigProperty.BOOLEAN_TYPE);


        configProperties.add(p1);
        configProperties.add(p2);
        configProperties.add(p3);
        configProperties.add(p4);
        configProperties.add(p5);
        configProperties.add(p6);
        configProperties.add(p7);
        configProperties.add(p8);
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
    public String getDisplayType() { return "GuardianKey GKTinc Authenticator"; }

    @Override
    public String getReferenceCategory() { return "GKTinc"; }

    @Override
    public String getHelpText() {
        return "A 'Frictionless CAPTCHA'. Validates a cryptographic challenge silently resolved by the browser to deter automated attacks (bots, brute force, credential stuffing).";
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
