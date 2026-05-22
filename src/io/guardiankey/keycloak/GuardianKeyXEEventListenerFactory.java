package io.guardiankey.keycloak;

import org.keycloak.Config.Scope;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class GuardianKeyXEEventListenerFactory implements EventListenerProviderFactory {

    public static final String PROVIDER_ID = "guardiankey-xe-event-listener";
    private static final GuardianKeyXEEventListener SINGLETON = new GuardianKeyXEEventListener();

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        SINGLETON.session = session;
        return SINGLETON;
    }

    @Override
    public void init(Scope config) { }

    @Override
    public void postInit(KeycloakSessionFactory factory) { }

    @Override
    public void close() { }

    @Override
    public String getId() { return PROVIDER_ID; }
}
