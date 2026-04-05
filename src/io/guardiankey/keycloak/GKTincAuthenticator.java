package io.guardiankey.keycloak;

import java.util.List;
import java.util.Map;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.utils.FormMessage;
public class GKTincAuthenticator extends UsernamePasswordForm {

    protected static final GKTincAPI GKAPI = new GKTincAPI();

    private static final String AUTH_NOTE_GKTINC_JS = "gktinc.javascript";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Map<String, String> localConfig = loadConfig(context);
        if (localConfig == null) {
            super.authenticate(context);
            return;
        }

        boolean gkEnabled = "true".equals(localConfig.get("gktinc.enablegktinc"));
        boolean verbose   = "true".equals(localConfig.get("gktinc.verbose"));

        if (!gkEnabled) {
            if (verbose) System.out.println("GKTincAuthenticator.authenticate: GKTinc disabled.");
            super.authenticate(context);
            return;
        }

        String clientIp         = getClientIP(context);
        boolean ipReputation    = "true".equals(localConfig.get("gktinc.useipreputation"));
        boolean preEnforceBlock = "true".equals(localConfig.get("gktinc.preenforceblock"));

        if (verbose) System.out.println("GKTincAuthenticator.authenticate: enabled. IP: " + clientIp
                + ", ipReputation: " + ipReputation + ", preEnforceBlock: " + preEnforceBlock);

        Map<String, Object> challengeLevelResult = null;
        if (ipReputation) {
            challengeLevelResult = GKAPI.getChallengeLevel(context.getSession(), clientIp);
            if (preEnforceBlock && challengeLevelResult != null
                    && "BLOCK".equals(challengeLevelResult.get("action"))) {
                Response response = context.form()
                    .setError("Access blocked by GKTinc. Your origin is blocked by policy. If you think this is a mistake, please contact support.")
                    .createForm("error.ftl");
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, response);
                return;
            }
        }

        GKAPI.setConfig(localConfig);
        // Pre-compute JS and store in auth session so challenge() can inject it into
        // the correct LoginFormsProvider instance (created inside super.authenticate).
        String js = buildJavascript(context, localConfig, challengeLevelResult);
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_GKTINC_JS, js);
        if (verbose) System.out.println("GKTincAuthenticator.authenticate: JS stored in auth session.");

        super.authenticate(context);  // → calls our overridden challenge(context, formData)
    }

    /**
     * Called by super.authenticate() (initial display) and by super.action() when
     * re-challenging after login errors. Single point where LoginFormsProvider is
     * created, so gktinc_javascript is guaranteed to reach the correct instance.
     */
    @Override
    protected Response challenge(AuthenticationFlowContext context,
                                 MultivaluedMap<String, String> formData) {
        LoginFormsProvider forms = context.form();
        String js = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_GKTINC_JS);
        if (js != null) forms.setAttribute("gktinc_javascript", js);
        if (formData != null && !formData.isEmpty()) forms.setFormData(formData);
        return forms.createLoginUsernamePassword();
    }

    @Override
    protected Response challenge(AuthenticationFlowContext context, String error, String field) {
        LoginFormsProvider form = context.form()
                .setExecution(context.getExecution().getId());
        String js = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_GKTINC_JS);
        if (js != null) form.setAttribute("gktinc_javascript", js);
        if (error != null) {
            if (field != null) {
                form.addError(new FormMessage(field, error));
            } else {
                form.setError(error);
            }
        }
        return createLoginForm(form);
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
        String username = formData.getFirst("username");
        String once        = getOnce(context);
        String clientIp    = getClientIP(context);
        String url         = getUrl(context);
        int challengeLevel = 2;
        
        boolean useIpReputation = config != null && "true".equals(config.get("gktinc.useipreputation"));
        if (useIpReputation) {
            challengeLevel = -1;
        }

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

        System.out.println("GKTincAuthenticator.action: started.");
        boolean verbose = true;
        Map<String,String> config = null;
        try {
            AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
            if (configModel == null) { 
                if (verbose) System.out.println("GKTincAuthenticator.action: no config model, bypassing GKTinc.");
                //context.success();
                super.action(context);
                return; 
            }
            config = configModel.getConfig();
            boolean gkEnabled = "true".equals(config.get("gktinc.enablegktinc")) ;
            verbose = "true".equals(config.get("gktinc.verbose"));
            if(gkEnabled) {
                if (verbose) System.out.println("GKTincAuthenticator executing with GKTinc enabled.");
                GKAPI.setConfig(config);
            } else {
                if (verbose) System.out.println("GKTincAuthenticator executing with GKTinc disabled. This authenticator will allow all attempts.");
                // context.success();
                super.action(context);
                return;
            }
        } catch (Exception e) {
            if(verbose) System.out.println("GKTincAuthenticator.action: error loading config, bypassing GKTinc. " + e.getMessage());
            //context.success();
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

        if (result != null && ( "BLOCK".equals(result.get("action")) || "INVALID".equals(result.get("action")) )) {
            Response response = context.form()
                .setError("Access blocked by GKTinc. Suspicious activity detected.")
                .createForm("error.ftl");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, response);
            return;
        }

        super.action(context);
    }

    private String getHeader(jakarta.ws.rs.core.HttpHeaders headers, String name) {
        try {
            List<String> values = headers.getRequestHeader(name);
            return (values != null && !values.isEmpty()) ? values.get(0) : "";
        } catch (Exception e) {
            return "";
        }
    }

    private Map<String, String> loadConfig(AuthenticationFlowContext context) {
        try {
            AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
            if (configModel == null) {
                System.out.println("GKTincAuthenticator: no config model, bypassing.");
                return null;
            }
            return configModel.getConfig();
        } catch (Exception e) {
            System.out.println("GKTincAuthenticator: error loading config: " + e.getMessage());
            return null;
        }
    }

    private String buildJavascript(AuthenticationFlowContext context,
                                   Map<String, String> cfg,
                                   Map<String, Object> challengeLevelResult) {
        try {
            boolean ipReputation    = "true".equals(cfg.get("gktinc.useipreputation"));
            boolean preEnforceBlock = "true".equals(cfg.get("gktinc.preenforceblock"));
            boolean verbose         = "true".equals(cfg.get("gktinc.verbose"));
            String clientIp = getClientIP(context);
            String url      = getUrl(context);
            String once     = getOnce(context);
            String salt     = GKAPI.getSalt();
            String jsConfig = GKAPI.getJavascriptConfig(
                challengeLevelResult, ipReputation, preEnforceBlock, clientIp, url, salt, once);
            String js =
                "<script src='https://guardiankey.io/js/gktinc-setup-latest.js?v=2026040502'></script>" +
                "<script>" + jsConfig + "</script>" +
                "<script>" +
                    "var form_input_element = 'username';" +
                    "var form_element = null;" +
                    "gktinc_init(gktinc_config, form_element, form_input_element, " + verbose + ");" +
                "</script>";
            if (verbose) System.out.println("GKTincAuthenticator: JavaScript built.");
            return js;
        } catch (Exception e) {
            System.out.println("GKTincAuthenticator.buildJavascript error: " + e.getMessage());
            return "<script>/* GKTinc error */</script>";
        }
    }
}
