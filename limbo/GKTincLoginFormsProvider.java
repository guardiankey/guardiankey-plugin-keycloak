package io.guardiankey.keycloak;

import org.jboss.logging.Logger;
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

    private static final Logger logger = Logger.getLogger(GKTincLoginFormsProvider.class);

    /**
     * Constructs the provider with the current Keycloak session.
     *
     * @param session the current Keycloak session
     */
    public GKTincLoginFormsProvider(KeycloakSession session) {
        super(session);
    }

    // -------------------------------------------------------------------------
    //  LoginFormsProvider entry points.
    //  Each method injects attributes BEFORE delegating to super,
    //  ensuring the data is available in the template.
    // -------------------------------------------------------------------------

    /** Standard username + password login page. */
    @Override
    public Response createLoginPassword() {
        injectGKTincAttributes();
        return super.createLoginPassword();
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
        logger.debugf("[GKTinc] Rendering template '%s' in realm '%s'",
                template, realm != null ? realm.getName() : "<unknown>");
        return super.createForm(template);
    }

    /** Forgot password page. */
    @Override
    public Response createPasswordReset() {
        injectGKTincAttributes();
        return super.createPasswordReset();
    }

    /** Generic error page. */
    @Override
    public Response createErrorPage(jakarta.ws.rs.core.Response.Status status) {
        injectGKTincAttributes();
        return super.createErrorPage(status);
    }

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
    private void injectGKTincAttributes() {
        // -------------------------------------------------------------------
        // Static / build-time attributes
        // -------------------------------------------------------------------

        setAttribute("gktinc_javascript",   "xxxx");

        // -------------------------------------------------------------------
        // Dynamic data: realm information.
        // The realm is set by the framework via setRealm() before any
        // create*() call, so it is safe to access here.
        // -------------------------------------------------------------------
        if (realm != null) {
            String displayName = realm.getDisplayName();
            setAttribute("realmDisplayName",
                    (displayName != null && !displayName.isEmpty()) ? displayName : realm.getName());
            setAttribute("realmName", realm.getName());
        }

        // -------------------------------------------------------------------
        // Dynamic data: current Unix timestamp in seconds.
        // In templates: ${currentTimestamp?c}
        // -------------------------------------------------------------------
        setAttribute("currentTimestamp", System.currentTimeMillis() / 1000L);
    }
}
