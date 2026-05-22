package io.guardiankey.keycloak;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

public class GuardianKeyXEEventListener implements EventListenerProvider {

    protected static final GuardianKeyXEAPI GKAPI = new GuardianKeyXEAPI();

    public KeycloakSession session;

    @Override
    public void onEvent(Event event) {
        if (event.getType() != EventType.LOGIN_ERROR) return;
        if (session == null) return;

        Map<String, String> config;
        try {
            AuthenticatorConfigModel cfg = findConfig(session, GuardianKeyXECheckAuthenticatorFactory.PROVIDER_ID);
            if (cfg == null) cfg = findConfig(session, GuardianKeyXEFormAuthenticatorFactory.PROVIDER_ID);
            if (cfg == null) return;
            config = cfg.getConfig();
        } catch (Exception e) {
            System.out.println("GuardianKeyXEEventListener: could not resolve XE config: " + e.getMessage());
            return;
        }

        if ("false".equals(config.get("guardiankey.xe.enable"))) return;

        boolean verbose = "true".equals(config.get("guardiankey.xe.verbose"));
        GKAPI.setConfig(config);

        String username = null;
        if (event.getDetails() != null) username = event.getDetails().get("username");
        if (username == null) username = event.getUserId();
        if (username == null) {
            if (verbose) System.out.println("GuardianKeyXEEventListener: no username in event, skipping.");
            return;
        }

        String clientIP = event.getIpAddress() != null ? event.getIpAddress() : "";
        String userAgent = "";
        try {
            List<String> uas = session.getContext().getRequestHeaders().getRequestHeader("User-Agent");
            if (uas != null && !uas.isEmpty()) userAgent = uas.get(0);
        } catch (Exception e) { }

        if (verbose) System.out.println("GuardianKeyXEEventListener: reporting LOGIN_ERROR for " + username);

        GKAPI.checkAccessXE(
                session,
                username, "",
                true,
                "Authentication",
                clientIP, userAgent, "", "", "",
                null, null, null, null, null);
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) { }

    @Override
    public void close() { }

    private AuthenticatorConfigModel findConfig(KeycloakSession session, String providerId) {
        RealmModel realm = session.getContext().getRealm();
        if (realm == null) return null;
        String flowId = realm.getBrowserFlow().getId();
        return findConfig(realm, flowId, providerId);
    }

    private AuthenticatorConfigModel findConfig(RealmModel realm, String flowId, String providerId) {
        List<AuthenticationExecutionModel> executions = realm.getAuthenticationExecutionsStream(flowId).collect(Collectors.toList());
        for (AuthenticationExecutionModel aem : executions) {
            if (aem.isAuthenticatorFlow()) {
                AuthenticatorConfigModel nested = findConfig(realm, aem.getFlowId(), providerId);
                if (nested != null) return nested;
            } else if (aem.getAuthenticator() != null && aem.getAuthenticator().equals(providerId)) {
                String configId = aem.getAuthenticatorConfig();
                if (configId != null) return realm.getAuthenticatorConfigById(configId);
            }
        }
        return null;
    }
}
