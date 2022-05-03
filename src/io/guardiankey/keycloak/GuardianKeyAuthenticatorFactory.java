package io.guardiankey.keycloak;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class GuardianKeyAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {


    public static final String PROVIDER_ID = "guardiankey-authenticator";
    private static final GuardianKeyAuthenticator SINGLETON = new GuardianKeyAuthenticator();
    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };
	private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property1;
        property1 = new ProviderConfigProperty();
        property1.setName("guardiankey.orgid");
        property1.setLabel("Organization ID");
        property1.setHelpText("Hash to identify your organization for GuardianKey.");
        property1.setType(ProviderConfigProperty.STRING_TYPE);
        
        ProviderConfigProperty property2;
        property2 = new ProviderConfigProperty();
        property2.setName("guardiankey.authgroupid");
        property2.setLabel("AuthGroup ID");
        property2.setHelpText("Hash to identify your authentication group for GuardianKey.");
        property2.setType(ProviderConfigProperty.STRING_TYPE);
        
        ProviderConfigProperty property3;
        property3 = new ProviderConfigProperty();
        property3.setName("guardiankey.key");
        property3.setLabel("Key");
        property3.setHelpText("The key for cryptographics, in base64.");
        property3.setType(ProviderConfigProperty.STRING_TYPE);
        
        ProviderConfigProperty property4;
        property4 = new ProviderConfigProperty();
        property4.setName("guardiankey.iv");
        property4.setLabel("IV");
        property4.setHelpText("The IV (Initialization Vector) for the key, in base64.");
        property4.setType(ProviderConfigProperty.STRING_TYPE);
        
        ProviderConfigProperty property5;
        property5 = new ProviderConfigProperty();
        property5.setName("guardiankey.service");
        property5.setLabel("Service name");
        property5.setHelpText("A service name to identify the service provider. E.g., 'KeyCloak'.");
        property5.setType(ProviderConfigProperty.STRING_TYPE);
        property5.setDefaultValue("KeyCloak");
        
        ProviderConfigProperty property5b;
        property5b = new ProviderConfigProperty();
        property5b.setName("guardiankey.agentid");
        property5b.setLabel("Agent ID");
        property5b.setHelpText("An information (hash, number, or name) to identify the event sender system.");
        property5b.setDefaultValue("KeyCloakServer");
        property5b.setType(ProviderConfigProperty.STRING_TYPE);
        
        ProviderConfigProperty property6;
        property6 = new ProviderConfigProperty();
        property6.setName("guardiankey.reverse");
        property6.setLabel("Reverse DNS");
        property6.setHelpText("Enable reverse DNS resolve?");
        property6.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        
//        List<String> listOptions=new ArrayList<String>();
//        listOptions.add("None");
//        listOptions.add("Admin only");
//        listOptions.add("Notify Users");
//        listOptions.add("Admin and users");
        ProviderConfigProperty property7;
        property7 = new ProviderConfigProperty();
        property7.setName("guardiankey.sendmails");
        property7.setLabel("Send e-mails?");
        property7.setHelpText("Users should receive event notification by e-mail?");
        property7.setType(ProviderConfigProperty.BOOLEAN_TYPE);
//        property7.setOptions(listOptions);
        
        ProviderConfigProperty property8;
        property8 = new ProviderConfigProperty();
        property8.setName("guardiankey.emailsubject");
        property8.setLabel("E-mail subject");
        property8.setHelpText("The e-mail subject. E.g., 'Security Alert!'.");
        property8.setType(ProviderConfigProperty.STRING_TYPE);
        property8.setDefaultValue("Security Alert!");
        
//        ProviderConfigProperty property9;
//        property9 = new ProviderConfigProperty();
//        property9.setName("guardiankey.adminemail");
//        property9.setLabel("Admin e-mail");
//        property9.setHelpText("The admin e-mail, that may receive alert e-mails.");
//        property9.setType(ProviderConfigProperty.STRING_TYPE);
        
        ProviderConfigProperty property9;
        property9 = new ProviderConfigProperty();
        property9.setName("guardiankey.panelurl");
        property9.setLabel("PANEL URL");
        property9.setHelpText("The GuardianKey PANEL URL. E.g., 'https://panel.guardiankey.io'");
        property9.setDefaultValue("https://panel.guardiankey.io");
        property9.setType(ProviderConfigProperty.STRING_TYPE);
        
        ProviderConfigProperty property10;
        property10 = new ProviderConfigProperty();
        property10.setName("guardiankey.apiurl");
        property10.setLabel("API URL");
        property10.setHelpText("The GuardianKey API URL. E.g., 'https://api.guardiankey.io'");
        property10.setDefaultValue("https://api.guardiankey.io");
        property10.setType(ProviderConfigProperty.STRING_TYPE);
        
        ProviderConfigProperty property11;
        property11 = new ProviderConfigProperty();
        property11.setName("guardiankey.sendonly");
        property11.setLabel("Send only");
        property11.setHelpText("Only send events to GuardianKey? If you choose no, the module may block risky auth attempts, depending on your policy set-up in the GuardianKey's panel.");
        property11.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property11.setDefaultValue(true);

        ProviderConfigProperty property12;
        property12 = new ProviderConfigProperty();
        property12.setName("guardiankey.anonkey");
        property12.setLabel("Anonymization KEY");
        property12.setHelpText("Anonymization KEY if used.");
        property12.setDefaultValue("");
        property12.setType(ProviderConfigProperty.STRING_TYPE);
        
        ProviderConfigProperty property13;
        property13 = new ProviderConfigProperty();
        property13.setName("guardiankey.anoniv");
        property13.setLabel("Anonymization IV");
        property13.setHelpText("Anonymization IV if used.");
        property13.setDefaultValue("");
        property13.setType(ProviderConfigProperty.STRING_TYPE);
        
        configProperties.add(property1);
        configProperties.add(property2);
        configProperties.add(property3);
        configProperties.add(property4);
        configProperties.add(property5);
        configProperties.add(property5b);
        configProperties.add(property6);
        configProperties.add(property7);
        configProperties.add(property8);
        configProperties.add(property9);
        configProperties.add(property10);
        configProperties.add(property11);
        configProperties.add(property12);
        configProperties.add(property13);
    }
    
	
	@Override
	public Authenticator create(KeycloakSession session) { return SINGLETON; }

	@Override
	public void init(Scope config) { 
		SINGLETON.setConfig(config);
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) { }

	@Override
	public void close() { }

	@Override
	public String getId() {
		 return PROVIDER_ID;
	}

	@Override
	public String getHelpText() {
		 return "Submits the authentication attempt to the GuardianKey engine to evaluate attack risks.";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		 return configProperties;
	}
	
	@Override
	public String getDisplayType() {
		return "GuardianKey Authenticator";
	}

	@Override
	public String getReferenceCategory() {
		return "GuardianKey";
	}

	@Override
	public boolean isConfigurable() {return true;}

	@Override
	public Requirement[] getRequirementChoices() {        
		return REQUIREMENT_CHOICES;
	}

	@Override
	public boolean isUserSetupAllowed() {return false;}

}
