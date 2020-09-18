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

import java.util.Set;

import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import fi.csc.shibboleth.authn.context.ReverseProxyAuthenticationContext;
import net.shibboleth.idp.authn.AuthenticationFlowDescriptor;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import fi.csc.shibboleth.authn.reverseproxy.ReverseProxyPrincipal;

/**
 * Unit tests for {@link ValidateReverseProxyAuthentication}.
 */
public class ValidateReverseProxyAuthenticationTest {

    private RequestContext src;

    private ProfileRequestContext prc;

    private AuthenticationContext authCtx;

    private ReverseProxyAuthenticationContext rpCtx;

    private ValidateReverseProxyAuthentication action;

    @BeforeMethod
    public void initTests() throws ComponentInitializationException {
        action = new ValidateReverseProxyAuthentication();
        src = (new RequestContextBuilder()).buildRequestContext();
        prc = (new WebflowRequestContextProfileRequestContextLookup()).apply(this.src);
        authCtx = (AuthenticationContext) prc.addSubcontext(new AuthenticationContext(), true);
        AuthenticationFlowDescriptor descr = new AuthenticationFlowDescriptor();
        descr.setId("test1");
        authCtx.setAttemptedFlow(descr);
        rpCtx = (ReverseProxyAuthenticationContext) authCtx.addSubcontext(new ReverseProxyAuthenticationContext(),
                true);
        rpCtx.addHeaderClaim("REMOTE_USER", "dude");
        rpCtx.addHeaderClaim("CLAIM1", "claim1value1");
        rpCtx.addHeaderClaim("CLAIM1", "claim1value2");
        rpCtx.addHeaderClaim("CLAIM2", "claim2value");
    }

    @Test
    public void testSuccess() throws ComponentInitializationException {
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertProceedEvent(event);
        Set<UsernamePrincipal> usernamePrincipals =
                authCtx.getAuthenticationResult().getSubject().getPrincipals(UsernamePrincipal.class);
        Assert.assertEquals(usernamePrincipals.size(), 1);
        Assert.assertEquals(usernamePrincipals.iterator().next().getName(), "dude");
        Set<ReverseProxyPrincipal> reverseProxyPrincipals =
                authCtx.getAuthenticationResult().getSubject().getPrincipals(ReverseProxyPrincipal.class);
        Assert.assertEquals(reverseProxyPrincipals.size(), 4);

    }

    @Test
    public void testSuccessSetUsernameKey() throws ComponentInitializationException {
        action.setUsernamePattern("^CLAIM2");
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertProceedEvent(event);
        Set<UsernamePrincipal> usernamePrincipals =
                authCtx.getAuthenticationResult().getSubject().getPrincipals(UsernamePrincipal.class);
        Assert.assertEquals(usernamePrincipals.size(), 1);
    }

    @Test
    public void testFailMissingUsername() throws ComponentInitializationException {
        action.setUsernamePattern("^NONEXIST");
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

}
