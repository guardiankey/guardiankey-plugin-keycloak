package io.guardiankey.keycloak;

import java.io.InputStreamReader;
import java.io.StringWriter;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import freemarker.template.Configuration;
import freemarker.template.Template;

import org.keycloak.email.EmailSenderProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.theme.Theme;

public final class GuardianKeyEmailUtil {

    private GuardianKeyEmailUtil() {}

    public static void sendAlert(KeycloakSession session, RealmModel realm, UserModel user,
                                  String username, String clientIP, String systemURL,
                                  Map<String, String> config, Map<String, ?> checkReturn,
                                  String panelUrlConfigKey, String subjectConfigKey,
                                  String sendMailsConfigKey) {
        if (config == null) return;
        String sendMails = config.get(sendMailsConfigKey);
        if (sendMails == null || sendMails.equals("false")) return;

        try {
            Map<String, String> configSMTP = realm.getSmtpConfig();
            String panelURL = config.get(panelUrlConfigKey);
            if (panelURL == null || panelURL.isEmpty()) panelURL = "https://panel.guardiankey.io";
            String subject = config.get(subjectConfigKey);
            if (subject == null) subject = "Security Alert!";

            String datetime = "recently";
            Object genTimeObj = checkReturn.get("generatedTime");
            if (genTimeObj != null) {
                try {
                    long secs;
                    if (genTimeObj instanceof Number) secs = ((Number) genTimeObj).longValue();
                    else secs = Long.parseLong(genTimeObj.toString());
                    Date d = new Date(secs * 1000L);
                    DateFormat fmt = new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US);
                    datetime = fmt.format(d) + " (UTC)";
                } catch (Exception e) { }
            }

            String clientUa = strVal(checkReturn.get("client_ua"));
            String clientOs = strVal(checkReturn.get("client_os"));
            String alertDevice = clientUa;
            if (!clientOs.isEmpty()) {
                alertDevice = alertDevice.isEmpty() ? clientOs : alertDevice + ", " + clientOs;
            }
            String eventId = strVal(checkReturn.get("eventId"));
            String token   = strVal(checkReturn.get("event_token"));
            String country = strVal(checkReturn.get("country"));

            Map<String, Object> attrs = new HashMap<>();
            attrs.put("USERNAME", username);
            attrs.put("DATETIME", datetime);
            attrs.put("SYSTEM", alertDevice);
            attrs.put("LOCATION", country);
            attrs.put("IPADDRESS", clientIP);
            attrs.put("CHECKURL", panelURL + "/events/viewresolve/" + eventId + "/" + token);
            attrs.put("EVENTID", eventId);
            attrs.put("EVENTTOKEN", token);
            attrs.put("SYSTEM_URL", systemURL);

            Theme theme = session.theme().getTheme(Theme.Type.EMAIL);
            String templateName = "guardiankey-security_alert.ftl";
            String htmlBody = processTemplate(theme, templateName, attrs);
            String textBody = "You cannot see this e-mail. Your client must support HTML e-mail messages.";

            EmailSenderProvider emailSender = session.getProvider(EmailSenderProvider.class);
            emailSender.send(configSMTP, user, subject, textBody, htmlBody);
        } catch (Exception e) {
            System.out.println("GuardianKeyEmailUtil: failed to send alert e-mail: " + e.getMessage());
        }
    }

    private static String strVal(Object o) {
        return o == null ? "" : o.toString();
    }

    private static String processTemplate(Theme theme, String templateName, Map<String, Object> attrs) throws Exception {
        try (InputStreamReader reader = new InputStreamReader(theme.getTemplate(templateName).openStream(), java.nio.charset.StandardCharsets.UTF_8)) {
            Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);
            cfg.setDefaultEncoding("UTF-8");
            Template template = new Template(templateName, reader, cfg);
            StringWriter out = new StringWriter();
            template.process(attrs, out);
            return out.toString();
        }
    }
}
