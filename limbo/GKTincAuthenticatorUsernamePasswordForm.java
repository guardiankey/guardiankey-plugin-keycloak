package io.guardiankey.keycloak;

import java.util.List;
import java.util.Map;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.models.AuthenticatorConfigModel;

public class GKTincAuthenticatorUsernamePasswordForm extends UsernamePasswordForm {

    public static final GKTincAPI GKAPI = new GKTincAPI();

    private static final String AUTH_NOTE_ONCE           = "gktinc.once";
    private static final String AUTH_NOTE_CHALLENGE_LEVEL = "gktinc.challenge_level";
    private static final String AUTH_NOTE_CLIENT_IP      = "gktinc.client_ip";
    private static final String AUTH_NOTE_URL            = "gktinc.url";

    @Override
    public void authenticate(AuthenticationFlowContext context) {

        

        try {
            AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
            if (configModel == null) { context.success(); return; }
            GKAPI.setConfig(configModel.getConfig());
        } catch (Exception e) {
            context.success();
            return;
        }

        String clientIp = "";
        String host = "";

        try {
            clientIp = context.getSession().getContext().getConnection().getRemoteAddr();
        } catch (Exception e) { }

        try {
            host = context.getRefreshExecutionUrl().getHost();
        } catch (Exception e) { }

        String once = context.getAuthenticationSession().getParentSession().getId();
        String url = host + "/realms/" + context.getRealm().getName() + "/protocol/openid-connect/auth";

        Map<String, Object> challengeResult = GKAPI.getChallengeLevel(context.getSession(), clientIp);

        if ("BLOCK".equals(challengeResult.get("action"))) {
            Response response = context.form()
                .setError("Access blocked by GKTinc.")
                .createForm("error.ftl");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, response);
            return;
        }

        int level = 2;
        Object cl = challengeResult.get("challenge_level");
        if (cl instanceof Number) level = ((Number) cl).intValue();

        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_ONCE, once);
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_CHALLENGE_LEVEL, String.valueOf(level));
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_CLIENT_IP, clientIp);
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_URL, url);

        String jsConfig = GKAPI.getJavascriptConfig(challengeResult, clientIp, url, once);

        String username = "";
        try {
            if (context.getUser() != null && context.getUser().getUsername() != null)
                username = context.getUser().getUsername();
        } catch (Exception e) { }

        Response challenge = context.form()
            .setAttribute("gktincConfig", jsConfig)
            .setAttribute("gktincUsername", username)
            .createForm("gktinc-challenge.ftl");
        context.challenge(challenge);
        // Não chamar super.authenticate() aqui: o desafio já foi emitido
        // e o fluxo fica suspenso até action() ser invocado no submit do form.
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        String gktincSolution = formData.getFirst("gktinc_solution");

        String username = "";
        try {
            if (context.getUser() != null && context.getUser().getUsername() != null)
                username = context.getUser().getUsername();
        } catch (Exception e) { }

        String once        = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_ONCE);
        String clientIp    = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_CLIENT_IP);
        String url         = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_URL);
        int challengeLevel = 2;
        try {
            String cl = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_CHALLENGE_LEVEL);
            if (cl != null) challengeLevel = Integer.parseInt(cl);
        } catch (NumberFormatException e) { }

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

        Map<String, Object> result = GKAPI.validateChallenge(
            context.getSession(), gktincSolution, username,
            clientIp, url, once, formPayloadSize,
            userAgent, secChUa, secChUaMobile, secChUaPlatform, challengeLevel
        );

        if ("BLOCK".equals(result.get("action"))) {
            Response response = context.form()
                .setError("Access blocked by GKTinc. Suspicious activity detected.")
                .createForm("error.ftl");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, response);
            return;
        }

        context.success();
    }

    private String getHeader(jakarta.ws.rs.core.HttpHeaders headers, String name) {
        try {
            List<String> values = headers.getRequestHeader(name);
            return (values != null && !values.isEmpty()) ? values.get(0) : "";
        } catch (Exception e) {
            return "";
        }
    }

}
