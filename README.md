# idp-authn-reverseproxy
This module is a Shibboleth Idp Authenticaton flow that outsources the authentication from a reverse proxy. 
## Build
```sh
mvn clean package
```
## Prerequisite for installation
- Shibboleth IdP 4.0.0+
- [shibboleth-idp-oidc-extension](https://github.com/CSCfi/shibboleth-idp-oidc-extension/wiki) v2.0.0+

## Installation
First you need extract the archive. Please not that you most likely *need* to change the owner and group information of the extracted files to suite your installation.
```sh
cd /opt/shibboleth-idp
tar -xf path/to/idp-authn-reverseproxy-distribution-1.0.0-bin.tar.gz --strip-components=1
```
add reverseproxy.properties as one of the included property files  in the /opt/shibboleth-idp/conf/idp.propeties
```sh
# Load any additional property resources from a comma-delimited list
idp.additionalProperties=/conf/ldap.properties, /conf/saml-nameid.properties, /conf/services.properties, /conf/authn/duo.properties, /credentials/secrets.properties, /conf/oidc-subject.properties, /conf/idp-oidc.properties, /conf/authn/reverseproxy.properties
..
```
rebuild the package
```sh
cd /opt/shibboleth-idp/bin
./build.sh
```
The module is now ready to be configured.
### Configuration
The authentication flow name is 'authn/reverseproxy'. See [https://wiki.shibboleth.net/confluence/display/IDP4/AuthenticationConfiguration](https://wiki.shibboleth.net/confluence/display/IDP4/AuthenticationConfiguration) how to configure the flow as active flow. Note that flow does not support passing authentication requirements like requested authentication context class or forced authentication to the reverse proxy.

The 'authn/reverseproxy' flow expects that Authenticating Authority is set using the proxy discovery described in [https://wiki.shibboleth.net/confluence/display/IDP4/AuthenticationConfiguration](https://wiki.shibboleth.net/confluence/display/IDP4/AuthenticationConfiguration). If Authenticating Authority is not used a default value must be set to reverseproxy.properties. The properties file must be updated to match the configuration of the reverse proxy installed for all properties.

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
