/*
 * The MIT License
 * Copyright (c) 2020 CSC - IT Center for Science, http://www.csc.fi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package fi.csc.shibboleth.authn.reverseproxy.impl;

import java.util.List;
import java.util.Map.Entry;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.auth.Subject;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Predicates;

import fi.csc.shibboleth.authn.context.ReverseProxyAuthenticationContext;
import fi.csc.shibboleth.authn.reverseproxy.ReverseProxyPrincipal;
import net.shibboleth.idp.authn.AbstractValidationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.idp.profile.ActionSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * An action that checks for an {@link ReverseProxyAuthenticationContext} and produces an
 * {@link net.shibboleth.idp.authn.AuthenticationResult} or records error if the configured user attribute is not
 * existing in the context.
 * 
 * First header matching a pattern is set as {@link UsernamePrincipal} for the subject. All headers are populated as
 * {@link ReverseProxyPrincipal} for the subject. Just before creating otherwise acceptable authentication result the
 * action calls a predicate to make the final decision whether the result can be accepted.
 * 
 * @event {@link EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#INVALID_AUTHN_CTX}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * @pre
 * 
 *      <pre>
 *      ProfileRequestContext.getSubcontext(AuthenticationContext.class).getAttemptedFlow() != null
 *      </pre>
 * 
 * @post If AuthenticationContext.getSubcontext(ReverseProxyAuthenticationContext.class) != null, then an
 *       {@link net.shibboleth.idp.authn.AuthenticationResult} is saved to the {@link AuthenticationContext} on a
 *       successful login. On a failed login, the
 *       {@link AbstractValidationAction#handleError(ProfileRequestContext, AuthenticationContext, Exception, String)}
 *       method is called.
 */
public class ValidateReverseProxyAuthentication extends AbstractValidationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ValidateReverseProxyAuthentication.class);

    /** Pattern to match the name of the extracted header to be used as username. */
    private String usernamePattern = "REMOTE_USER";

    /** Username. */
    private String reverseProxyUsername;

    /** Context containing the result to validate. */
    @Nullable
    private ReverseProxyAuthenticationContext reverseProxyContext;

    /** Whether the authentication result is acceptable by external evaluation, usually a script. */
    @Nonnull
    private Predicate<ProfileRequestContext> authenticationAcceptablePredicate;

    /** Constructor. */
    public ValidateReverseProxyAuthentication() {
        authenticationAcceptablePredicate = Predicates.alwaysTrue();
    }

    /**
     * Set the pattern for matching the extracted header to be used as username. Default is 'REMOTE_USER'.
     * 
     * @param pattern Pattern for matching the extracted header to be used as username.
     */
    public void setUsernamePattern(String pattern) {
        usernamePattern = pattern;
    }

    /**
     * Set condition to determine whether the authentication result is acceptable.
     *
     * @param condition condition to apply
     */
    public void setAuthenticationAcceptablePredicate(@Nonnull final Predicate<ProfileRequestContext> condition) {
        authenticationAcceptablePredicate =
                Constraint.isNotNull(condition, "Authentication acceptable condition cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        if (!super.doPreExecute(profileRequestContext, authenticationContext)) {
            return false;
        }
        reverseProxyContext = authenticationContext.getSubcontext(ReverseProxyAuthenticationContext.class);
        if (reverseProxyContext == null) {
            log.error("{} ReverseProxyAuthenticationContext not set under AuthenticationContext", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_AUTHN_CTX);
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        outerloop: for (Entry<String, List<String>> headerClaim : reverseProxyContext.getHeaderClaims().entrySet()) {
            if (Pattern.matches(usernamePattern, (String) headerClaim.getKey())) {
                List<String> usernames = headerClaim.getValue();
                if (usernames == null) {
                    continue;
                }
                for (String username : usernames) {
                    if (username != null && !username.isEmpty()) {
                        log.debug("{} Username resolved from reverse proxy header claim {} as {}", getLogPrefix(),
                                headerClaim.getKey(), username);
                        reverseProxyUsername = username;
                        break outerloop;
                    }
                }

            }
        }
        if (reverseProxyUsername == null) {
            handleError(profileRequestContext, authenticationContext, AuthnEventIds.NO_CREDENTIALS,
                    AuthnEventIds.NO_CREDENTIALS);
            return;
        }
        if (authenticationAcceptablePredicate.test(profileRequestContext)) {
            buildAuthenticationResult(profileRequestContext, authenticationContext);
        } else {
            handleError(profileRequestContext, authenticationContext, AuthnEventIds.INVALID_CREDENTIALS,
                    AuthnEventIds.INVALID_CREDENTIALS);
            return;
        }

    }

    /** {@inheritDoc} */
    @Override
    protected Subject populateSubject(Subject subject) {
        subject.getPrincipals().add(new UsernamePrincipal(reverseProxyUsername));
        for (Entry<String, List<String>> headerClaim : reverseProxyContext.getHeaderClaims().entrySet()) {
            headerClaim.getValue().forEach(value -> {
                if (value != null && !value.isEmpty()) {
                    subject.getPrincipals().add(new ReverseProxyPrincipal(headerClaim.getKey(), value));
                }
            });
        }
        log.debug("{} Subject populated as {}", getLogPrefix(), reverseProxyUsername);
        return subject;
    }

}
