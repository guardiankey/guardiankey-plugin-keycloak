package io.guardiankey.keycloak;

import java.util.HashMap;
import java.util.Map;

import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProvider;
import org.keycloak.models.KeycloakSession;

import jakarta.ws.rs.core.Response;

/**
 * Custom LoginFormsProvider that injects additional attributes into every FreeMarker
 * template rendered by Keycloak login flows.
 *
 * <p>Extends {@link FreeMarkerLoginFormsProvider} and overrides template rendering
 * entry points to add custom attributes via {@link #setAttribute(String, Object)}
 * before delegating to the default behaviour.</p>
 *
 * <h3>Activation in Keycloak:</h3>
 * <ul>
 *   <li>Quarkus (Keycloak 20+): {@code KC_SPI_LOGIN_DEFAULT_PROVIDER=gktinc-freemarker}
 *       or in {@code keycloak.conf}: {@code spi-login-default-provider=gktinc-freemarker}</li>
 *   <li>WildFly (Keycloak 18): in {@code standalone.xml}:
 *       {@code <spi name="login"><default-provider>gktinc-freemarker</default-provider></spi>}</li>
 * </ul>
 *
 * <h3>Usage in templates (.ftl):</h3>
 * <pre>
 *   ${customMessage}
 *   ${buildVersion}
 *   ${environment}
 *   ${realmDisplayName}
 *   ${currentTimestamp?c}
 * </pre>
 */
public class GKTincLoginFormsProvider extends FreeMarkerLoginFormsProvider {

    protected static final GKTincAPI GKAPI = new GKTincAPI();

    /** The Keycloak session — stored for lazy API calls at render time. */
    private final KeycloakSession kcSession;

    /**
     * Constructs the provider with the current Keycloak session.
     *
     * <p>The constructor MUST remain minimal. At this point no authentication
     * session exists yet (it is set later via {@code setAuthenticationSession()}).
     * All GKTinc initialisation is deferred to {@link #injectGKTincAttributes()}.</p>
     *
     * @param session the current Keycloak session
     */
    public GKTincLoginFormsProvider(KeycloakSession session) {
        super(session);
        this.kcSession = session;
    }

    // -------------------------------------------------------------------------
    //  LoginFormsProvider entry points.
    //  Each method injects attributes BEFORE delegating to super,
    //  ensuring the data is available in the template.
    // -------------------------------------------------------------------------

    /** Standard username + password login page. */
    // @Override
    // public Response createLoginPassword() {
    //     injectGKTincAttributes();
    //     return super.createLoginPassword();
    // }

    @Override
    public Response createLoginUsernamePassword() {
        injectGKTincAttributes();
        return super.createLoginUsernamePassword();
    }

    /**
     * Entry point used by custom authenticators via:
     * {@code context.form().setAttribute(...).createForm("my-template.ftl")}.
     *
     * <p>This is the method called by {@link GKTincAuthenticatorUsernamePasswordForm}
     * to render {@code gktinc-challenge.ftl}.</p>
     *
     * @param template the FTL file name (e.g. "gktinc-challenge.ftl")
     * @return HTTP Response with the rendered HTML
     */
    @Override
    public Response createForm(String template) {
        injectGKTincAttributes();
        return super.createForm(template);
    }

    /** Forgot password page. */
    @Override
    public Response createPasswordReset() {
        injectGKTincAttributes();
        return super.createPasswordReset();
    }

    /** Generic error page. */
    // @Override
    // public Response createErrorPage(jakarta.ws.rs.core.Response.Status status) {
    //     injectGKTincAttributes();
    //     if (verbose) System.out.println("GKTincLoginFormsProvider.createErrorPage called for status '" + status + "' in realm '" + (realm != null ? realm.getName() : "<unknown>") + "'.");
    //     return super.createErrorPage(status);
    // }

    // -------------------------------------------------------------------------
    //  Custom attribute injection
    // -------------------------------------------------------------------------

    /**
     * Adds GKTinc custom data to the template attribute map.
     *
     * <p>Called before any rendering. {@link #setAttribute(String, Object)}
     * (inherited from {@link FreeMarkerLoginFormsProvider}) writes into the internal
     * {@code attributes} map, which is passed directly to the FreeMarker context.</p>
     *
     * <p>Attributes already set via {@code context.form().setAttribute(...)}
     * by the authenticator are NOT overwritten — to preserve them,
     * add an {@code attributes.containsKey(key)} check before calling setAttribute.</p>
     */
    /**
     * Lazily reads GKTinc configuration from authentication session notes (set by
     * {@link GKTincAuthenticatorUsernamePasswordForm#setNotes}) and injects the
     * client-side JavaScript block into the FreeMarker attribute map.
     *
     * <p>Called at render time, after {@code setAuthenticationSession()} has been
     * invoked by Keycloak and after the authenticator has set the notes.
     * Safe to call when no auth session is present — outputs a disabled comment.</p>
     */
    private void injectGKTincAttributes() {
        String gktinc_javascript = "<script>/* GKTinc disabled */</script>";
        try {
            // authenticationSession is an inherited protected field set by setAuthenticationSession().
            // It may be null during very early Keycloak setup — always guard against it.
            if (this.authenticationSession == null) {
                setAttribute("gktinc_javascript", gktinc_javascript);
                return;
            }

            boolean gkEnabled = "true".equals(this.authenticationSession.getAuthNote("gktinc.enablegktinc"));
            boolean verbose   = "true".equals(this.authenticationSession.getAuthNote("gktinc.verbose"));

            if (!gkEnabled) {
                if (verbose) System.out.println("GKTincLoginFormsProvider: GKTinc is disabled.");
                setAttribute("gktinc_javascript", gktinc_javascript);
                return;
            }

            // Read per-request values stored as auth notes by the authenticator.
            String clientIp = orEmpty(this.authenticationSession.getAuthNote("gktinc.client_ip"));
            String url      = orEmpty(this.authenticationSession.getAuthNote("gktinc.url"));
            String once     = orEmpty(this.authenticationSession.getAuthNote("gktinc.once"));
            boolean ipReputation    = "true".equals(this.authenticationSession.getAuthNote("gktinc.useipreputation"));
            boolean preEnforceBlock = "true".equals(this.authenticationSession.getAuthNote("gktinc.preenforceblock"));

            // Reconstruct a minimal config map for GKAPI from auth notes.
            Map<String, String> cfg = new HashMap<>();
            cfg.put("gktinc.enablegktinc",       orEmpty(this.authenticationSession.getAuthNote("gktinc.enablegktinc")));
            cfg.put("gktinc.verbose",            orEmpty(this.authenticationSession.getAuthNote("gktinc.verbose")));
            cfg.put("gktinc.apikey",               orEmpty(this.authenticationSession.getAuthNote("gktinc.apikey")));
            cfg.put("gktinc.agentid",              orEmpty(this.authenticationSession.getAuthNote("gktinc.agentid")));
            cfg.put("gktinc.protectiongrouphashid",orEmpty(this.authenticationSession.getAuthNote("gktinc.protectiongrouphashid")));
            cfg.put("gktinc.apiurl",               orEmpty(this.authenticationSession.getAuthNote("gktinc.apiurl")));
            cfg.put("gktinc.useipreputation",      orEmpty(this.authenticationSession.getAuthNote("gktinc.useipreputation")));
            GKAPI.setConfig(cfg);

            String salt = GKAPI.getSalt();

            Map<String, Object> challengeLevelResult = null;
            if (ipReputation) {
                challengeLevelResult = GKAPI.getChallengeLevel(kcSession, clientIp);
                if(preEnforceBlock && challengeLevelResult != null) {
                    if ("BLOCK".equals(challengeLevelResult.get("action")) && context != null) {
                        Response response = context.form()
                            .setError("Access blocked by GKTinc. Your origin is blocked by policy. If you think this is a mistake, please contact support.")
                            .createForm("error.ftl");
                        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, response);
                        return;
                    }
                }
            }

            String gktinc_config = GKAPI.getJavascriptConfig(
                challengeLevelResult, ipReputation, preEnforceBlock, clientIp, url, salt, once);

            gktinc_javascript =
                "<script src='https://guardiankey.io/js/gktinc-setup-latest.js?v=9'></script>" +
                "<script>" + gktinc_config + "</script>" +
                "<script>" +
                    "var form_input_element = document.getElementById('username');" +
                    "var form_element = null;" +
                    "gktinc_init(gktinc_config, form_element, form_input_element, " + verbose + ");" +
                "</script>";

            if (verbose) System.out.println("GKTincLoginFormsProvider: JavaScript injected.");

        } catch (Exception e) {
            // Never let GKTinc errors break the login page.
            System.out.println("GKTincLoginFormsProvider.injectGKTincAttributes error: " + e.getMessage());
        }
        setAttribute("gktinc_javascript", gktinc_javascript);
    }

    private static String orEmpty(String s) {
        return s != null ? s : "";
    }
}
