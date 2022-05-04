**Tested up to 18.0.0**

# 1. What is GuardianKey

GuardianKey is a solution to protect systems against authentication attacks. It uses Machine Learning to analyze the user's behavior, threat intelligence, and psychometrics (or behavioral biometrics) and provides an attack risk in real-time. 

The protected system (in the concrete case, KeyCloak, via this extension) sends the events via REST for the GuardianKey on each login attempt and can notify users or even block the high-risk events. Also, there is a panel that presents dashboards about login attempts. There are cloud and product versions. Also, there is a free service for small environments.

Beyond the security, the GuardianKey solution provides a good user experience, because the user is not required to provide extra information or to execute tasks during the login. It is a *painless high-security*.

For more information, check https://guardiankey.io

Below, we describe how you can use the KeyCloak's GuardianKey extension to access the GuardianKey engine in in cloud.

A video for this tutorial is available at https://youtu.be/R5QFcH4bXuA 

In **summary**, you should:

1. Register an user at https://panel.guardiankey.io/auth/register
2. Deploy the GuardianKey extension in your KeyCloak installation
3. Configure the extension
4. Check the events in the GuardianKey panel and protect your systems

More details in the sequel.

# 2. Before installing the KeyCloak extension

## 2.1. Registering in the GuardianKey's cloud service

The KeyCloak's GuardianKey extension does not register automatically in the cloud services, 
you must do this and get the deployment information (cryptographic keys, etc).

Just access the registering form at https://panel.guardiankey.io/auth/register and follow the instructions.

More details can be found at:
https://guardiankey.io/panel-documentation/#accessing-for-the-first-time

# 3. Deploying the extension in KeyCloak

## Instructions to deploying using Keycloak with Quarkus (most recents versions)
To deploy the extension, you must:

1. Download and move the `guardiankey.jar` file to the `providers` directory of your Keycloak installation and running 'build', for example:

```
$ wget https://github.com/guardiankey/guardiankey-plugin-keycloak/releases/tag/v0.9.3-beta
$ cp guardiankey.jar /opt/keycloak-18.0.0/providers/
$ cd /opt/keycloak-18.0.0/
$ ./bin/kc.sh build
```

2. Copy the e-mail template to your Keycloak theme, for example:

```
$ cd /opt/keycloak-18.0.0
$ cp ./lib/lib/main/org.keycloak.keycloak-themes-18.0.0.jar /tmp
$ mkdir /tmp/a
$ cd /tmp/a
$ unzip /tmp/org.keycloak.keycloak-themes-18.0.0.jar 
$ cp base /opt/keycloak-18.0.0/themes/custom
$ cd /opt/keycloak-18.0.0/themes/custom/email
$ wget https://raw.githubusercontent.com/pauloangelo/guardiankey-plugin-keycloak/master/extra/guardiankey-security_alert.ftl

```
3. Restart Keycloak service

(go to item 4)

## Instructions to deploying using Keycloak with WildFly (old versions)
To deploy the extension, you must:

1. Download and move the `guardiankey.jar` file to the `deployments` directory of your KeyCloak installation, for example:

```
$ wget https://github.com/pauloangelo/guardiankey-plugin-keycloak/releases/download/v0.9.1-beta/guardiankey.jar
$ cp guardiankey.jar /opt/jboss/keycloak/standalone/deployments/
```

2. Copy the e-mail template into the `email` directory of the theme used by your installation, for example:

```
$ wget https://raw.githubusercontent.com/pauloangelo/guardiankey-plugin-keycloak/master/extra/guardiankey-security_alert.ftl
$ cp guardiankey-security_alert.ftl /opt/jboss/keycloak/themes/keycloak/email/
```

It is not needed to restart services, JBoss will automatically deploy the files. 
In some seconds, the file `guardiankey.jar.deployed` should appear in the `deployments` directory. 
If you have a problem in this phase, it will appear a file named `guardiankey.jar.failed`. 
In this case, you can check its contents to have a clue about the problem.


3. Copy the e-mail template into the `email` directory of the theme used by your installation, for example:

```
$ wget https://raw.githubusercontent.com/pauloangelo/guardiankey-plugin-keycloak/master/extra/guardiankey-security_alert.ftl
$ cp guardiankey-security_alert.ftl /opt/jboss/keycloak/themes/keycloak/email/
```

It is not needed to restart services, JBoss will automatically deploy the files. 
In some seconds, the file `guardiankey.jar.deployed` should appear in the `deployments` directory. 
If you have a problem in this phase, it will appear a file named `guardiankey.jar.failed`. 
In this case, you can check its contents to have a clue about the problem.

# 4. Configuring the extension

## 4.1. E-mail configuration in the Realm

To enable GuardianKey to notify your users about suspicious authentication attempts, 
you have to configure the e-mail sending in your KeyCloak instance. 
Probably, you already did this in order to use KeyCloak. 
If no, in KeyCloak admin interface, go to "Realm settings", e-mail tab, and provide an SMTP server for e-mail sending.
For example, like in the screenshot presented below.

![Configuring the e-mail settings in KeyCloak](https://raw.githubusercontent.com/pauloangelo/guardiankey-plugin-keycloak/master/imgs/1-email.png)

### 4.1.2 - (just newer versions) Enable e-mail in Realm settings -> Themes, select "custom" theme.


## 4.2. Creating a browser flow

Currently, GuardianKey extension supports just Browser flows.
The built-in Browser flow provided by KeyCloak cannot be modified. 
So, you should copy this Browser flow to include the `GuardianKey Authenticator provider` in a new flow.

In KeyCloak, go to Authentication. In the tab `Flows`, select the `Browser` flow, 
click in the button `copy`, provide a new name, and confirm. 
Screen presented in the image below.

![Copy the Browser flow](https://raw.githubusercontent.com/pauloangelo/guardiankey-plugin-keycloak/master/imgs/2-copy_flow.png)

Now, select the newly created browser flow, click in the button `Add execution`, select the provider **GuardianKey Authenticator** and save.

The GuardianKey Authenticator must be set-up to **REQUIRED** and should be last in the list, such as in the image below.

![Adding the GuardianKey Authenticator provider](https://raw.githubusercontent.com/pauloangelo/guardiankey-plugin-keycloak/master/imgs/3-add_provider_to_flow.png)


## 4.3. Configuring the GuardianKey extension

You have to open the [GuardianKey's panel](https://panel.guardiankey.io) and get the deployment information
for your system. 
It can be found when viewing an Authgroup, `Deploy information` tab, such as in the image below.

![Getting the deployment information at the Panel](https://guardiankey.io/img-panel/authgroup_deploy_information.png)

To configure the GuardianKey extension, you should go to the created flow and click in the `Config` link that is inside the `Actions` 
menu of the `GuardianKey Authenticator` line in the flow. There will open a form like the one in the image below.

![Configuring the GuardianKey extension](https://raw.githubusercontent.com/pauloangelo/guardiankey-plugin-keycloak/master/imgs/4-configure_extension.png)

The Organization ID, AuthGroup ID, Key and IV are deployment information that can be found at GuardianKey's panel.
The other fields are described below.

- Alias: any name for your reference.
- Service name and Agent ID: are sent in events to GuardianKey to identify the service and sender. Suggest to keep "KeyCloak" and "KeyCloakServer".
- Reverse DNS: put ON to send reverse DNS information for the events. Recommend ON.
- Send e-mails: if ON, it may notify your users if the risk of the event is above the notify threshold defined in the policy configured in the GuardianKey's panel for your authgroup. We recommend to tell your users that they may receive e-mails, before enabling this feature.
- Panel URL and API URL: must be "https://panel.guardiankey.io" and "https://api.guardiankey.io" if you are using the GuardianKey in cloud.
- Send only: if ON, the extension will send events to GuardianKey and will **NOT** wait for the GuardianKey's response. So, the extension will not be able to BLOCK or NOTIFY users via e-mail.

## 4.4. Setting the GuardianKey flow as the Browser flow

You must set the GuardianKey flow as the `Browser flow` for your realm. 
In KeyCloak, go to Authentication and tab `Bindings`. Set the created flow for GuardianKey as
the `Browser flow` and save. See image below.

![Setting the GuardianKey flow as the Browser flow](https://raw.githubusercontent.com/pauloangelo/guardiankey-plugin-keycloak/master/imgs/5-set_GK_flow_as.png)


## 4.5. Adding an event listener 

GuardianKey also monitors the failed login attempts. To implement it in KeyCloak, it is needed to add an event listener.

In KeyCloak, go to `Events`, tab `Config`, and include the `guardiankey-event-listener` in the "Event Listeners" field (img below).

![Adding the GuardianKey event listener](https://raw.githubusercontent.com/pauloangelo/guardiankey-plugin-keycloak/master/imgs/6-add_GK_event_listener.png)

# 5. Testing

Finally, you can check if it's running. Just authenticate in a system that uses the KeyCloak realm and check if the event appears in the
GuardianKey's panel.

# 6. Getting help

If you have troubles, you can find help in the links below. You can also send an e-mail to contact@guardiankey.io.

- https://guardiankey.io/post/using-it/
- https://guardiankey.io/getting-help/
- https://guardiankey.io/panel-documentation/
- https://www.keycloak.org/documentation.html
- https://www.keycloak.org/community.html
 

