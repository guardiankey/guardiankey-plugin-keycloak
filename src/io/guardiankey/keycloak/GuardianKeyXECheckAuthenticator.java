package io.guardiankey.keycloak;

import java.util.List;
import java.util.Map;

import jakarta.ws.rs.core.Response;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class GuardianKeyXECheckAuthenticator implements Authenticator {

    protected static final GuardianKeyXEAPI GKAPI = new GuardianKeyXEAPI();

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Map<String, String> config;
        try {
            AuthenticatorConfigModel m = context.getAuthenticatorConfig();
            if (m == null) {
                System.out.println("GuardianKeyXECheckAuthenticator: no config model, bypassing.");
                context.success();
                return;
            }
            config = m.getConfig();
        } catch (Exception e) {
            System.out.println("GuardianKeyXECheckAuthenticator: error loading config: " + e.getMessage());
            context.success();
            return;
        }

        boolean enabled = !"false".equals(config.get("guardiankey.xe.enable"));
        boolean verbose = "true".equals(config.get("guardiankey.xe.verbose"));
        if (!enabled) {
            if (verbose) System.out.println("GuardianKeyXECheckAuthenticator: disabled, allowing.");
            context.success();
            return;
        }

        UserModel user = context.getUser();
        if (user == null || user.getUsername() == null) {
            if (verbose) System.out.println("GuardianKeyXECheckAuthenticator: no user in context, allowing.");
            context.success();
            return;
        }

        GKAPI.setConfig(config);

        String username = user.getUsername();
        boolean anon = config.get("guardiankey.xe.anonkey") != null && !config.get("guardiankey.xe.anonkey").isEmpty();
        String email = (!anon && user.getEmail() != null) ? user.getEmail() : "";

        String clientIP = "";
        try { clientIP = context.getSession().getContext().getConnection().getRemoteAddr(); } catch (Exception e) { }

        String userAgent = getHeader(context.getSession(), "User-Agent");
        String secChUa = getHeader(context.getSession(), "Sec-CH-UA");
        String secChUaMobile = getHeader(context.getSession(), "Sec-CH-UA-Mobile");
        String secChUaPlatform = getHeader(context.getSession(), "Sec-CH-UA-Platform");

        String solution = context.getAuthenticationSession().getAuthNote(GuardianKeyXEFormAuthenticator.AUTH_NOTE_GKXE_SOLUTION);
        String url  = context.getAuthenticationSession().getAuthNote(GuardianKeyXEFormAuthenticator.AUTH_NOTE_GKXE_URL);
        String salt = context.getAuthenticationSession().getAuthNote(GuardianKeyXEFormAuthenticator.AUTH_NOTE_GKXE_SALT);
        String once = context.getAuthenticationSession().getAuthNote(GuardianKeyXEFormAuthenticator.AUTH_NOTE_GKXE_ONCE);
        String time = context.getAuthenticationSession().getAuthNote(GuardianKeyXEFormAuthenticator.AUTH_NOTE_GKXE_TIME);

        if (url == null)  url  = GuardianKeyXEFormAuthenticator.getUrl(context);
        if (salt == null) salt = GKAPI.getSalt();
        if (once == null) once = GuardianKeyXEFormAuthenticator.getOnce(context);
        if (time == null) time = String.valueOf(System.currentTimeMillis() / 1000);

        if (verbose) System.out.println("GuardianKeyXECheckAuthenticator: calling /checkaccessxe for user " + username);

        Map<String, Object> resp = GKAPI.checkAccessXE(
                context.getSession(),
                username, email,
                false,
                "Authentication",
                clientIP, userAgent, secChUa, secChUaMobile, secChUaPlatform,
                solution, url, salt, once, time);

        String decision = String.valueOf(resp.get("response"));
        if (verbose) System.out.println("GuardianKeyXECheckAuthenticator: GKAS response = " + decision);

        String systemURL = "";
        try { systemURL = context.getRefreshExecutionUrl().getHost(); } catch (Exception e) { }

        if ("BLOCK".equals(decision)) {
            GuardianKeyEmailUtil.sendAlert(context.getSession(), context.getRealm(), user,
                    username, clientIP, systemURL, config, resp,
                    "guardiankey.xe.panelurl", "guardiankey.xe.emailsubject", "guardiankey.xe.sendmails");
            Response challenge = context.form()
                    .setError("Attempt blocked by GuardianKey. Check your e-mails.")
                    .createForm("error.ftl");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            return;
        } else if ("NOTIFY".equals(decision) || "HARD_NOTIFY".equals(decision)) {
            GuardianKeyEmailUtil.sendAlert(context.getSession(), context.getRealm(), user,
                    username, clientIP, systemURL, config, resp,
                    "guardiankey.xe.panelurl", "guardiankey.xe.emailsubject", "guardiankey.xe.sendmails");
        }

        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) { }

    @Override
    public boolean requiresUser() { return true; }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) { }

    @Override
    public void close() { }

    private String getHeader(KeycloakSession session, String name) {
        try {
            List<String> values = session.getContext().getRequestHeaders().getRequestHeader(name);
            return (values != null && !values.isEmpty()) ? values.get(0) : "";
        } catch (Exception e) {
            return "";
        }
    }
}
