package io.guardiankey.keycloak;

import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.ws.rs.core.Response;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.theme.FreeMarkerException;
import org.keycloak.theme.FreeMarkerUtil;
import org.keycloak.theme.Theme;


// https://github.com/briantward/keycloak-custom/blob/master/providers/src/main/java/org/keycloak/custom/authentication/authenticators/SecretQuestionAuthenticator.java

public class GuardianKeyAuthenticator implements Authenticator, EventListenerProvider {
	
    public static final GuardianKeyAPI GKAPI = new GuardianKeyAPI();
	public KeycloakSession session;


	@Override
	public void close() { }

	@Override
	public void authenticate(AuthenticationFlowContext context) {

		String email;
		String clientIP="";
		String userAgent="";
		Map<String,String> config;
		KeycloakSession session;
		String username;
		String systemURL;
		try {
			config = context.getAuthenticatorConfig().getConfig();
			session = context.getSession();
			
			if(context.getUser()==null || context.getUser().getUsername() == null) {
				context.success();
				return;
			}
			
			GKAPI.setConfig(config);
			
			username=context.getUser().getUsername();
			systemURL = context.getRefreshExecutionUrl().getHost().toString();
		} catch (Exception e) {
			context.success();
			return;
		}
		
		try {
			 clientIP = context.getSession().getContext().getConnection().getRemoteAddr();
		} catch (Exception e) {	}
		
		try {
			List<String> userAgents = session.getContext().getRequestHeaders().getRequestHeader("User-agent");
			if(userAgents.size()>0)
				userAgent = userAgents.get(0);	
		} catch (Exception e) {	}
		
		boolean failed = false;
		
		if(context.getUser().getEmail()!=null) {
			email = context.getUser().getEmail();
		}else {
			email ="";
		}
		
		System.out.print("Sending sucessfuly attempt to GuardianKey.\n");
		if(config.get("guardiankey.sendonly").equals("true")) {
			GKAPI.sendEvent(session,username,email,failed,"Authentication", clientIP,userAgent);
		}else {
			Map<String,String> checkReturn = GKAPI.checkAccess(session,username,email,failed,"Authentication", clientIP,userAgent);
        	
			if(checkReturn.get("response").equals("BLOCK")) {
                 Response challenge = context.form()
							                .setError("Attempt blocked by GuardianKey.")
							                .createForm("error.ftl");
				 context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
				 return;
			}else if(checkReturn.get("response").equals("NOTIFY") || checkReturn.get("response").equals("HARD_NOTIFY")) {
				sendEmail(username,email,context,clientIP,systemURL,checkReturn);
			}
		}
		context.success();
		return;
	}

	private void sendEmail(String username, String email, AuthenticationFlowContext context, String clientIP, String systemURL, Map<String, String> checkReturn) {
		Map<String,String> config = context.getAuthenticatorConfig().getConfig();

		
		if(config.get("guardiankey.sendmails")==null || config.get("guardiankey.sendmails").equals("false"))
			return;
		
		String datetime = "recently";
        try {
	    	Date dateFromTime = new Date( (new Long(checkReturn.get("generatedTime"))) *1000L );
	    	DateFormat dateFormatter = new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US);
	    	datetime = dateFormatter.format(dateFromTime)+" (UTC)";
		} catch (Exception e) {	}
    	
        try {
        	Map<String,String> configSMTP = context.getRealm().getSmtpConfig();
        	KeycloakSession session = context.getSession();
        	UserModel user = context.getUser();
    		String panelURL = (config.containsKey("guardiankey.panelurl"))? config.get("guardiankey.panelurl") : "https://panel.guardiankey.io";
        	String subject = (config.get("guardiankey.emailsubject")!=null)? config.get("guardiankey.emailsubject") : "";
        	String textBody = "You cannot see this e-mail. Your client must support HTML e-mail messages.";
        	EmailSenderProvider emailSender = session.getProvider(EmailSenderProvider.class);
        	
        	Theme theme = session.theme().getTheme(Theme.Type.EMAIL);
        	
        	FreeMarkerUtil freeMarker = new FreeMarkerUtil();
        	String templateName = "guardiankey-security_alert.ftl";
        	
        	Map<String, Object> attributes = new HashMap<>();
        	String alertdevice = (checkReturn.containsKey("client_ua"))? checkReturn.get("client_ua") : "";
        	alertdevice = (checkReturn.containsKey("client_os"))? alertdevice+", "+checkReturn.get("client_os") : alertdevice;
        	String eventId = (checkReturn.containsKey("eventId"))? checkReturn.get("eventId") : "";
        	String token   = (checkReturn.containsKey("event_token"))? checkReturn.get("event_token") : "";
        	attributes.put("USERNAME",  username);
        	attributes.put("DATETIME",  datetime);
        	attributes.put("SYSTEM",    alertdevice);
        	attributes.put("LOCATION",  (checkReturn.containsKey("country"))? checkReturn.get("country") : "");
        	attributes.put("IPADDRESS", clientIP);
        	attributes.put("CHECKURL",  panelURL+"/events/viewresolve/"+eventId+"/"+token);
        	attributes.put("EVENTID",   eventId);
        	attributes.put("EVENTTOKEN",token);
        	attributes.put("SYSTEM_URL", systemURL);
        	String htmlBody = freeMarker.processTemplate(attributes, templateName, theme);
			emailSender.send(configSMTP, user, subject, textBody, htmlBody);
		} catch (EmailException e) { System.out.print("Failed to send e-mail."); 
		} catch (IOException e) { System.out.print("Failed to access theme files for sending e-mail.");
		} catch (FreeMarkerException e) { System.out.print("Failed to process the e-mail template. Is there a syntax error in your template?");
		}
	}

	@Override
	public void action(AuthenticationFlowContext context) {
	}

	@Override
	public boolean requiresUser() { return true; }

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {return true;}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) { }
	
	public void setConfig(Scope config) {
		if (config==null)
			return;
		
	}
	
	@Override
	public void onEvent(Event event) {
		if (event.getType().equals(EventType.LOGIN_ERROR)) {
			boolean failed = true;
			AuthenticatorConfigModel authConfig = getConfig(session, GuardianKeyAuthenticatorFactory.PROVIDER_ID);
			Map<String,String> config = authConfig.getConfig();
			GKAPI.setConfig(config);
			String clientIP = event.getIpAddress();
			String username=event.getUserId();
			KeycloakContext context = session.getContext();
			String userAgent="";
			try {
				List<String> userAgents = context.getRequestHeaders().getRequestHeader("User-agent");
				if(userAgents.size()>0)
					userAgent = userAgents.get(0);	
			} catch (Exception e) {	}
			
			if (event.getDetails() != null) {
                for (Map.Entry<String, String> e : event.getDetails().entrySet()) {
                    if(e.getKey().equals("username"))
                    	username=e.getValue();
                 }
            }
			if(username!=null)
			{
				System.out.print("Sending failed attempt to GuardianKey.\n");
				GKAPI.sendEvent(session,username,"",failed,"Authentication", clientIP,userAgent);
			}
		}
	}

	@Override
	public void onEvent(AdminEvent event, boolean includeRepresentation) {	}
	
	private AuthenticatorConfigModel getConfig(KeycloakSession session, String providerId) {
	    RealmModel realm = session.getContext().getRealm();
	    String flowId = realm.getBrowserFlow().getId();
	    return getConfig(realm, flowId, providerId);
	}

	private AuthenticatorConfigModel getConfig(RealmModel realm, String flowId, String providerId) {
	    AuthenticatorConfigModel configModel = null;
	    List<AuthenticationExecutionModel> laem = realm.getAuthenticationExecutions(flowId);
	    for (AuthenticationExecutionModel aem : laem) {
	        if (aem.isAuthenticatorFlow()) {
	            configModel = getConfig(realm, aem.getFlowId(), providerId);
	            if (configModel!= null) return configModel;
	        } else if (aem.getAuthenticator() != null && aem.getAuthenticator().equals(providerId)) {
	            configModel = realm.getAuthenticatorConfigById(aem.getAuthenticatorConfig());
	            break;
	        }
	    }
	    return configModel;
	}
}



