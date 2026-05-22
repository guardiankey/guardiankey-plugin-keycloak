package io.guardiankey.keycloak;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.provider.ProviderConfigProperty;

public final class GuardianKeyXEConfig {

    private GuardianKeyXEConfig() {}

    public static List<ProviderConfigProperty> commonProperties() {
        List<ProviderConfigProperty> props = new ArrayList<>();

        props.add(prop("guardiankey.xe.enable",       "Enable GuardianKey XE?",
                "If disabled, this step does nothing and lets the request pass through.",
                "true", ProviderConfigProperty.BOOLEAN_TYPE));

        props.add(prop("guardiankey.xe.verbose",      "Verbose?",
                "If enabled, prints detailed logs to the Keycloak server log for debugging.",
                "false", ProviderConfigProperty.BOOLEAN_TYPE));

        props.add(prop("guardiankey.xe.apiurl",       "API URL",
                "GKAS XE API URL. Use 'https://api.guardiankey.io/' for the cloud version.",
                "https://api.guardiankey.io/", ProviderConfigProperty.STRING_TYPE));

        props.add(prop("guardiankey.xe.orgid",        "Organization ID",
                "Organization hash from the GuardianKey panel.",
                "", ProviderConfigProperty.STRING_TYPE));

        props.add(prop("guardiankey.xe.authgroupid",  "Auth Group ID",
                "Authentication Group hash from the GuardianKey panel.",
                "", ProviderConfigProperty.STRING_TYPE));

        props.add(prop("guardiankey.xe.apikey",       "API Key",
                "API Key sent as the X-Api-Key header. If empty, it is derived as sha256(key + iv) when both Key and IV are provided.",
                "", ProviderConfigProperty.STRING_TYPE));

        props.add(prop("guardiankey.xe.key",          "Key (base64)",
                "Optional. Base64-encoded AES key. Used only to derive the API Key automatically when API Key is empty.",
                "", ProviderConfigProperty.STRING_TYPE));

        props.add(prop("guardiankey.xe.iv",           "IV (base64)",
                "Optional. Base64-encoded AES IV, paired with Key for automatic API Key derivation.",
                "", ProviderConfigProperty.STRING_TYPE));

        props.add(prop("guardiankey.xe.salt",         "Salt",
                "Optional. Challenge salt sent to the frontend script. If empty, defaults to sha1(apikey + authgroupid).",
                "", ProviderConfigProperty.STRING_TYPE));

        props.add(prop("guardiankey.xe.agentid",      "Agent ID",
                "Agent identifier reported to GKAS XE.",
                "KeyCloakServer", ProviderConfigProperty.STRING_TYPE));

        props.add(prop("guardiankey.xe.service",      "Service name",
                "Service name reported to GKAS XE.",
                "KeyCloak", ProviderConfigProperty.STRING_TYPE));

        props.add(prop("guardiankey.xe.reverse",      "Reverse DNS?",
                "If enabled, the server performs a reverse DNS lookup of the client IP and includes it in the event.",
                "true", ProviderConfigProperty.BOOLEAN_TYPE));

        props.add(prop("guardiankey.xe.sendmails",    "Send alert e-mails?",
                "If enabled, NOTIFY/BLOCK responses also trigger an alert e-mail to the user via Keycloak SMTP settings.",
                "false", ProviderConfigProperty.BOOLEAN_TYPE));

        props.add(prop("guardiankey.xe.emailsubject", "E-mail subject",
                "Subject line for the alert e-mail.",
                "Security Alert!", ProviderConfigProperty.STRING_TYPE));

        props.add(prop("guardiankey.xe.panelurl",     "Panel URL",
                "Base URL for the GuardianKey panel, used in event-resolution links inside the alert e-mail.",
                "https://panel.guardiankey.io", ProviderConfigProperty.STRING_TYPE));

        props.add(prop("guardiankey.xe.anonkey",      "Anonymization Key (base64)",
                "Optional. AES key (base64) used to anonymize the username sent to GKAS XE.",
                "", ProviderConfigProperty.STRING_TYPE));

        props.add(prop("guardiankey.xe.anoniv",       "Anonymization IV (base64)",
                "Optional. AES IV (base64) paired with the Anonymization Key.",
                "", ProviderConfigProperty.STRING_TYPE));

        return props;
    }

    private static ProviderConfigProperty prop(String name, String label, String help, String defaultValue, String type) {
        ProviderConfigProperty p = new ProviderConfigProperty();
        p.setName(name);
        p.setLabel(label);
        p.setHelpText(help);
        p.setDefaultValue(defaultValue);
        p.setType(type);
        return p;
    }
}
