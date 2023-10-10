[![CodeQL](https://github.com/CSCfi/idp-authn-reverseproxy/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/CSCfi/idp-authn-reverseproxy/actions/workflows/codeql-analysis.yml)

# idp-authn-reverseproxy
This module is a Shibboleth Idp Authenticaton flow that outsources the authentication from a reverse proxy. 
## Build
```sh
mvn clean package
```
## Prerequisite for installation
- Shibboleth IdP 5.0.0+

## Installation
First you need extract the archive. Please not that you most likely *need* to change the owner and group information of the extracted files to suite your installation.
```sh
cd /opt/shibboleth-idp
tar -xf path/to/idp-authn-reverseproxy-distribution-2.0.0-bin.tar.gz --strip-components=1
```
rebuild the package
```sh
cd /opt/shibboleth-idp/bin
./build.sh
```
The module is now ready to be configured.
### Configuration
The authentication flow name is 'authn/reverseproxy'. See [https://wiki.shibboleth.net/confluence/display/IDP5/AuthenticationConfiguration](https://wiki.shibboleth.net/confluence/display/IDP5/AuthenticationConfiguration) how to configure the flow as active flow. The 'authn/reverseproxy' flow expects that Authenticating Authority is set using the proxy discovery described in [https://wiki.shibboleth.net/confluence/display/IDP5/AuthenticationConfiguration](https://wiki.shibboleth.net/confluence/display/IDP5/AuthenticationConfiguration). If Authenticating Authority is not used a default value must be set to reverseproxy.properties. The properties file must be updated to match the configuration of the reverse proxy installed for all properties.

#### mod_auth_openidc - Minimal setup instructions for mod_auth_openidc
Configure mod_auth_openidc as a relying party to a OP or OPs as descibed in [https://github.com/zmartzone/mod_auth_openidc](https://github.com/zmartzone/mod_auth_openidc).
Protect the location of the IdP passively and set REMOTE_USER to a header matching reverseproxy.properties.
```sh
#Passive protection of the idp endpoints
<Location /idp/>
   AuthType openid-connect
   Require valid-user
   OIDCUnAuthAction pass
   RequestHeader set OIDC_REMOTE_USER expr=%{REMOTE_USER}
</Location>
```
Pass the traffic to the protected idp endpoints. This is very much deployment specific.
```sh
#Pass all traffic to idp container
ProxyPass "/"  "http://idp:8080/"
ProxyPassReverse "/"  "http://idp:8080/"
```

#### Protecting the redirect
The Authenticating Authority is passed to reverse proxy callback url as request parameter. User is able to manipulate these parameters as any request parameters. This is not a concern if the reverse proxy always authenticates the user same way. With any of the more complicated setups this is however not true. By defining a predicate that is used to validate the authentication result the risk for such manipulation may be mitigated.

Assume the Authenticating Authority value is set as:

```sh
https:/upstream.op.com&auth_request_params=acr_values=https://refeds.org/profile/mfa
```

The user is expected to be authenticated by issuer _https:/upstream.op.com_ with acr _https://refeds.org/profile/mfa_. Both of these request values may be manipulated by the user and we have to make sure the response satisfies the intended request. This can be prevented by defining a validation script. 

reverseproxy.properties

```sh
reverseproxy.authentication_validator = reverseproxy.Validator
```

global.xml

```sh
        <bean id="reverseproxy.Validator" parent="shibboleth.Conditions.Scripted" factory-method="inlineScript"
          p:hideExceptions="false">
          <constructor-arg>
            <value>
              <![CDATA[
              logger = Java.type("org.slf4j.LoggerFactory").getLogger("fi.csc.shibboleth.authn.reverseproxy");
              logger.debug("External validator for reverseproxy authenticator");
              valid = true;
              authnContext = input.getSubcontext("net.shibboleth.idp.authn.context.AuthenticationContext");
              flowRequestContext = input.getSubcontext("net.shibboleth.idp.profile.context.SpringRequestContext").getRequestContext();
              reverseProxyContext = authnContext.getSubcontext("fi.csc.shibboleth.authn.context.ReverseProxyAuthenticationContext");
              receivedIssuer = reverseProxyContext.getHeaderClaims().get("OIDC_CLAIM_iss")[0];
              var receivedACR;
              values = reverseProxyContext.getHeaderClaims().get("OIDC_CLAIM_acr");
              if (values != null && values.size()>0){
                  receivedACR = values[0];
              }
              authority = authnContext.getAuthenticatingAuthority();
              if (authority == null) {
                  authority = flowRequestContext.getActiveFlow().getApplicationContext().getBean('fi.csc.shibboleth.authn.reverseproxy.authority_default');
              }
              splitAuthority = authority.split("acr_values=");
              var acr;
              if (splitAuthority.length == 2) {
                  acr = splitAuthority[1].split("&")[0];
              }
              authority = authority.split("&")[0];
              if (!(authority === receivedIssuer)) {
                  logger.error("External validator failed matching received authority {} with requested authority {}", receivedIssuer, authority);
                  valid = false;
              }
              if (acr != null && !(acr === receivedACR)) {
                  logger.error("External validator failed matching received acr {} with requested acr {}", receivedACR, acr);
                  valid = false;
              }
              valid;
              ]]>
            </value>
          </constructor-arg>
        </bean>
```
Note! The script must then be adjusted for any new parameters embedded to Authenticating Authority.
