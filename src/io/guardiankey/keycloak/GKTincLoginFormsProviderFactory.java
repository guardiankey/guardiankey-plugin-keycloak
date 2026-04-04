package io.guardiankey.keycloak;

import org.keycloak.Config;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.forms.login.LoginFormsProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Factory for {@link GKTincLoginFormsProvider}.
 *
 * <p>Registered in the Keycloak "login" SPI under the ID {@value #PROVIDER_ID}.
 * Follows the same pattern as the upstream {@code FreeMarkerLoginFormsProviderFactory}.</p>
 *
 * <h3>Activation in Keycloak:</h3>
 * <ul>
 *   <li>Quarkus (Keycloak 20+):
 *       environment variable {@code KC_SPI_LOGIN_DEFAULT_PROVIDER=gktinc-freemarker}
 *       or in {@code keycloak.conf}: {@code spi-login-default-provider=gktinc-freemarker}</li>
 *   <li>WildFly (Keycloak 18):
 *       <pre>{@code
 *       <subsystem xmlns="urn:jboss:domain:keycloak-server:1.1">
 *           <spi name="login">
 *               <default-provider>gktinc-freemarker</default-provider>
 *           </spi>
 *       </subsystem>
 *       }</pre>
 *   </li>
 * </ul>
 */
public class GKTincLoginFormsProviderFactory implements LoginFormsProviderFactory {

    /**
     * Unique identifier of this implementation within the "login" SPI.
     * Used to select the provider via Keycloak configuration.
     */
    public static final String PROVIDER_ID = "gktinc-freemarker";

    /**
     * Returns the unique ID of this provider within the "login" SPI.
     * Must match the value set in {@code KC_SPI_LOGIN_DEFAULT_PROVIDER}.
     */
    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public int order() {
        return 1;
    }

    /**
     * Creates a new {@link GKTincLoginFormsProvider} instance for the current session.
     * Called by Keycloak on every request that requires form rendering.
     *
     * @param session the Keycloak session for the current request
     * @return a provider instance for this session
     */
    @Override
    public LoginFormsProvider create(KeycloakSession session) {
        return new GKTincLoginFormsProvider(session);
    }

    /**
     * Factory initialization. Called once during Keycloak startup.
     *
     * @param config SPI configuration scope for this provider (may be null if not configured)
     */
    @Override
    public void init(Config.Scope config) {
        // no initialization required
    }

    /**
     * Called after all factories have been initialized.
     * Can be used to resolve cross-provider dependencies.
     */
    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no cross-provider dependencies
    }

    /** Releases factory resources when Keycloak shuts down. */
    @Override
    public void close() {
        // FreeMarkerUtil does not require explicit cleanup
    }
}
