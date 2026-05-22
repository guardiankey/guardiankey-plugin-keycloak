package io.guardiankey.keycloak;

import java.util.Map;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.utils.FormMessage;

public class GuardianKeyXEFormAuthenticator extends UsernamePasswordForm {

    protected static final GuardianKeyXEAPI GKAPI = new GuardianKeyXEAPI();

    public static final String AUTH_NOTE_GKXE_JS = "guardiankey.xe.javascript";
    public static final String AUTH_NOTE_GKXE_SOLUTION = "guardiankey.xe.solution";
    public static final String AUTH_NOTE_GKXE_URL = "guardiankey.xe.url";
    public static final String AUTH_NOTE_GKXE_SALT = "guardiankey.xe.salt";
    public static final String AUTH_NOTE_GKXE_ONCE = "guardiankey.xe.once";
    public static final String AUTH_NOTE_GKXE_TIME = "guardiankey.xe.time";

    private static final String DEFAULT_JS_URL = "https://guardiankey.io/js/gkas-setup-latest.js?v=1";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Map<String, String> config = loadConfig(context);
        if (config == null) {
            super.authenticate(context);
            return;
        }

        boolean enabled = !"false".equals(config.get("guardiankey.xe.enable"));
        boolean verbose = "true".equals(config.get("guardiankey.xe.verbose"));
        if (!enabled) {
            if (verbose) System.out.println("GuardianKeyXEFormAuthenticator: disabled, falling back to standard form.");
            super.authenticate(context);
            return;
        }

        GKAPI.setConfig(config);

        String url  = getUrl(context);
        String salt = GKAPI.getSalt();
        String once = getOnce(context);
        String time = String.valueOf(System.currentTimeMillis() / 1000);

        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_GKXE_URL,  url);
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_GKXE_SALT, salt);
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_GKXE_ONCE, once);
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_GKXE_TIME, time);

        String jsUrl = config.get("guardiankey.xe.jsurl");
        if (jsUrl == null || jsUrl.isEmpty()) jsUrl = DEFAULT_JS_URL;

        String js = buildJavascript(jsUrl, url, salt, once, time, verbose);
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_GKXE_JS, js);
        if (verbose) System.out.println("GuardianKeyXEFormAuthenticator: JS prepared and stored in auth session.");

        super.authenticate(context);
    }

    @Override
    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        LoginFormsProvider forms = context.form();
        String js = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_GKXE_JS);
        if (js != null) forms.setAttribute("gkxe_javascript", js);
        if (formData != null && !formData.isEmpty()) forms.setFormData(formData);
        return forms.createLoginUsernamePassword();
    }

    @Override
    protected Response challenge(AuthenticationFlowContext context, String error, String field) {
        LoginFormsProvider form = context.form().setExecution(context.getExecution().getId());
        String js = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_GKXE_JS);
        if (js != null) form.setAttribute("gkxe_javascript", js);
        if (error != null) {
            if (field != null) form.addError(new FormMessage(field, error));
            else form.setError(error);
        }
        return createLoginForm(form);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        try {
            MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
            String solution = formData.getFirst("gkas_solution");
            if (solution != null) {
                context.getAuthenticationSession().setAuthNote(AUTH_NOTE_GKXE_SOLUTION, solution);
            }
        } catch (Exception e) {
            System.out.println("GuardianKeyXEFormAuthenticator.action: failed to capture gkas_solution: " + e.getMessage());
        }
        super.action(context);
    }

    public static String getOnce(AuthenticationFlowContext context) {
        try {
            return context.getAuthenticationSession().getParentSession().getId();
        } catch (Exception e) {
            return "";
        }
    }

    public static String getUrl(AuthenticationFlowContext context) {
        String host = "";
        try {
            host = context.getRefreshExecutionUrl().getHost();
        } catch (Exception e) { }
        try {
            return host + "/realms/" + context.getRealm().getName() + "/protocol/openid-connect/auth";
        } catch (Exception e) {
            return host + "/auth";
        }
    }

    private Map<String, String> loadConfig(AuthenticationFlowContext context) {
        try {
            AuthenticatorConfigModel m = context.getAuthenticatorConfig();
            if (m == null) {
                System.out.println("GuardianKeyXEFormAuthenticator: no config model, bypassing.");
                return null;
            }
            return m.getConfig();
        } catch (Exception e) {
            System.out.println("GuardianKeyXEFormAuthenticator: error loading config: " + e.getMessage());
            return null;
        }
    }

    private String buildJavascript(String jsUrl, String url, String salt, String once, String time, boolean verbose) {
        StringBuilder sb = new StringBuilder();
        sb.append("<script src='").append(escapeAttr(jsUrl)).append("'></script>");
        sb.append("<script>var gkas_config = {");
        sb.append("url: \"").append(escapeJs(url)).append("\",");
        sb.append("salt: \"").append(escapeJs(salt)).append("\",");
        sb.append("once: \"").append(escapeJs(once)).append("\",");
        sb.append("time: \"").append(escapeJs(time)).append("\"};");
        sb.append("</script>");
        sb.append("<script>");
        sb.append("(function(){");
        sb.append("var form_element = document.getElementById('kc-form-login');");
        sb.append("var form_input_element = document.getElementById('username');");
        sb.append("if (typeof gkas_init === 'function') {");
        sb.append("gkas_init(gkas_config, form_element, form_input_element, ").append(verbose).append(");");
        sb.append("} else { console.warn('gkas_init not loaded'); }");
        sb.append("})();");
        sb.append("</script>");
        return sb.toString();
    }

    private static String escapeJs(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r");
    }

    private static String escapeAttr(String value) {
        if (value == null) return "";
        return value.replace("\"", "&quot;").replace("'", "&#39;");
    }
}
