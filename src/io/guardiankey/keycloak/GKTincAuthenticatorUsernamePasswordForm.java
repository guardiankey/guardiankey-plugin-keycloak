package io.guardiankey.keycloak;

import java.util.List;
import java.util.Map;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

//extends UsernamePasswordForm {
public class GKTincAuthenticatorUsernamePasswordForm extends AbstractUsernameFormAuthenticator {

    protected static final GKTincAPI GKAPI = new GKTincAPI();

    public static final String AUTH_NOTE_ONCE                    = "gktinc.once";
    public static final String AUTH_NOTE_CLIENT_IP               = "gktinc.client_ip";
    public static final String AUTH_NOTE_URL                     = "gktinc.url";
    public static final String AUTH_NOTE_ENABLED                 = "gktinc.enablegktinc";
    public static final String AUTH_NOTE_VERBOSE                 = "gktinc.verbose";
    public static final String AUTH_NOTE_APIURL                  = "gktinc.apiurl";
    public static final String AUTH_NOTE_USEIPREPUTATION         = "gktinc.useipreputation";
    public static final String AUTH_NOTE_AGENTID                 = "gktinc.agentid";
    public static final String AUTH_NOTE_APIKEY                  = "gktinc.apikey";
    public static final String AUTH_NOTE_PROTECTION_GROUP_HASHID = "gktinc.protectiongrouphashid";
    public static final String AUTH_NOTE_PREENFORCEBLOCK         = "gktinc.preenforceblock";

    /**
     * Writes every GKTinc config value that the LoginFormsProvider needs into the
     * current auth session as notes. This must be called BEFORE {@code super.authenticate()}
     * so the values are available when {@code injectGKTincAttributes()} runs at render time.
     */
    protected void setNotes(AuthenticationFlowContext context, Map<String, String> config) {
        AuthenticationSessionModel session = context.getAuthenticationSession();
        session.setAuthNote(AUTH_NOTE_ONCE,                    getOnce(context));
        session.setAuthNote(AUTH_NOTE_CLIENT_IP,               getClientIP(context));
        session.setAuthNote(AUTH_NOTE_URL,                     getUrl(context));
        session.setAuthNote(AUTH_NOTE_ENABLED,                 config.get("gktinc.enablegktinc"));
        session.setAuthNote(AUTH_NOTE_VERBOSE,                 config.get("gktinc.verbose"));
        session.setAuthNote(AUTH_NOTE_APIURL,                  config.get("gktinc.apiurl"));
        session.setAuthNote(AUTH_NOTE_USEIPREPUTATION,         config.get("gktinc.useipreputation"));
        session.setAuthNote(AUTH_NOTE_AGENTID,                 config.get("gktinc.agentid"));
        session.setAuthNote(AUTH_NOTE_APIKEY,                  config.get("gktinc.apikey"));
        session.setAuthNote(AUTH_NOTE_PROTECTION_GROUP_HASHID, config.get("gktinc.protectiongrouphashid"));
        session.setAuthNote(AUTH_NOTE_PREENFORCEBLOCK,         config.get("gktinc.preenforceblock"));
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        try {
            AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
            if (configModel == null) {
                System.out.println("GKTincAuthenticatorUsernamePasswordForm.authenticate: no config model, bypassing GKTinc.");
                //super.authenticate(context);
                return;
            }
            System.out.println("GKTincAuthenticatorUsernamePasswordForm.authenticate: config model found, setting notes for LoginFormsProvider.");
            Map<String, String> config = configModel.getConfig();
            // Always set notes so the LoginFormsProvider can read them at render time,
            // regardless of whether GKTinc is enabled or disabled.
            setNotes(context, config);
        } catch (Exception e) {
            System.out.println("GKTincAuthenticatorUsernamePasswordForm.authenticate: error setting notes, bypassing GKTinc. " + e.getMessage());
        }
        Response challenge = context.form().createLoginUsernamePassword();
        context.challenge(challenge);
    }

    public static String getOnce(AuthenticationFlowContext context) {
        // get sessionid or tokenid to use as "once" value for GKTinc API calls, to correlate events. This should be a unique value that changes on each authentication attempt. The authentication session ID is a good choice.
        return context.getAuthenticationSession().getParentSession().getId();
    }

    public static String getClientIP(AuthenticationFlowContext context) {
        String clientIp = "";
        try {
            clientIp = context.getSession().getContext().getConnection().getRemoteAddr();
        } catch (Exception e) { }
        return clientIp;
    }

     public static String getUrl(AuthenticationFlowContext context) {
        String host = "";
        try {
            host = context.getRefreshExecutionUrl().getHost();
        } catch (Exception e) { }
        try{
            return host + "/realms/" + context.getRealm().getName() + "/protocol/openid-connect/auth";
        } catch (Exception e) {
            return host + "/auth";
        }
    }

    protected Object[] getVars(AuthenticationFlowContext context, Map<String, String> config) {

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String gktincSolution = formData.getFirst("gktinc_solution");
        String username = "";
        try {
            if (context.getUser() != null && context.getUser().getUsername() != null)
                username = context.getUser().getUsername();
        } catch (Exception e) { }
        String once        = getOnce(context);
        String clientIp = "";//   = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_CLIENT_IP);


        clientIp = getClientIP(context);


        String url         = getUrl(context);
        int challengeLevel = 2;
        
        boolean useIpReputation = config != null && "true".equals(config.get("gktinc.useipreputation"));
        if (useIpReputation) {
            challengeLevel = -1;
        }
        // try {
        //     String cl = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_CHALLENGE_LEVEL);
        //     if (cl != null) challengeLevel = Integer.parseInt(cl);
        // } catch (NumberFormatException e) { }

        int formPayloadSize = 0;
        try {
            int total = 0;
            for (Map.Entry<String, List<String>> entry : formData.entrySet()) {
                for (String v : entry.getValue()) total += v.length();
            }
            formPayloadSize = Math.max(0, total - (gktincSolution != null ? gktincSolution.length() : 0));
        } catch (Exception e) { }

        String userAgent = "", secChUa = "", secChUaMobile = "", secChUaPlatform = "";
        try {
            jakarta.ws.rs.core.HttpHeaders headers = context.getSession().getContext().getRequestHeaders();
            userAgent      = getHeader(headers, "User-Agent");
            secChUa        = getHeader(headers, "Sec-CH-UA");
            secChUaMobile  = getHeader(headers, "Sec-CH-UA-Mobile");
            secChUaPlatform = getHeader(headers, "Sec-CH-UA-Platform");
        } catch (Exception e) { }

        return new Object[] {
            gktincSolution, username, clientIp, url, once, formPayloadSize,
            userAgent, secChUa, secChUaMobile, secChUaPlatform, challengeLevel
        };
    }




    @Override
    public void action(AuthenticationFlowContext context) {
        boolean verbose = true;
        Map<String,String> config = null;
        try {
            AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
            if (configModel == null) { 
                if (verbose) System.out.println("GKTincAuthenticatorUsernamePasswordForm.action: no config model, bypassing GKTinc.");
                super.action(context);
                return; 
            }
            config = configModel.getConfig();
            boolean gkEnabled = "true".equals(config.get("gktinc.enablegktinc")) ;
            verbose = "true".equals(config.get("gktinc.verbose"));
            if(gkEnabled) {
                if (verbose) System.out.println("GKTincAuthenticatorUsernamePasswordForm executing with GKTinc enabled.");
                GKAPI.setConfig(config);
            } else {
                if (verbose) System.out.println("GKTincAuthenticatorUsernamePasswordForm executing with GKTinc disabled. This authenticator will allow all attempts.");
                super.action(context);
                return;
            }
        } catch (Exception e) {
            if(verbose) System.out.println("GKTincAuthenticatorUsernamePasswordForm.action: error loading config, bypassing GKTinc. " + e.getMessage());
            super.action(context);
            return;
        }
        

        // if enabled, the API client will have already been configured by the factory based on the realm's configuration. If not enabled, this will be a no-op instance that allows all attempts.
        Object[] vars = getVars(context, config);
        String gktincSolution = (String) vars[0];
        String username = (String) vars[1];
        String clientIp = (String) vars[2];
        String url = (String) vars[3];
        String once = (String) vars[4];
        int formPayloadSize = (int) vars[5];
        String userAgent = (String) vars[6];
        String secChUa = (String) vars[7];
        String secChUaMobile = (String) vars[8];
        String secChUaPlatform = (String) vars[9];
        int challengeLevel = (int) vars[10];

        Map<String, Object> result = GKAPI.validateChallenge(
            context.getSession(), gktincSolution, username,
            clientIp, url, once, formPayloadSize,
            userAgent, secChUa, secChUaMobile, secChUaPlatform, challengeLevel, null
        );

        if ("BLOCK".equals(result.get("action"))) {
            Response response = context.form()
                .setError("Access blocked by GKTinc. Suspicious activity detected.")
                .createForm("error.ftl");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, response);
            return;
        }

        // Validate username + password (inherited from AbstractUsernameFormAuthenticator)
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (validateUserAndPassword(context, formData)) {
            context.success();
        }
    }

    private String getHeader(jakarta.ws.rs.core.HttpHeaders headers, String name) {
        try {
            List<String> values = headers.getRequestHeader(name);
            return (values != null && !values.isEmpty()) ? values.get(0) : "";
        } catch (Exception e) {
            return "";
        }
    }

    @Override
    public boolean requiresUser() {
       return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        
    }

}
