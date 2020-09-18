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

import org.springframework.mock.web.MockHttpServletRequest;
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
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;

/**
 * Unit tests for {@link ExtractHeaderValuesFromRequest}.
 */
public class ExtractHeaderValuesFromRequestTest {

    private RequestContext src;

    private ProfileRequestContext prc;

    private AuthenticationContext authCtx;

    private ExtractHeaderValuesFromRequest action;

    @BeforeMethod
    public void initTests() throws ComponentInitializationException {
        action = new ExtractHeaderValuesFromRequest();
        action.setHttpServletRequest(new MockHttpServletRequest());
        ((MockHttpServletRequest) action.getHttpServletRequest()).addHeader("header1", "value1");
        ((MockHttpServletRequest) action.getHttpServletRequest()).addHeader("header2", "value2");
        ((MockHttpServletRequest) action.getHttpServletRequest()).addHeader("header3", "value3");
        src = (new RequestContextBuilder()).buildRequestContext();
        prc = (new WebflowRequestContextProfileRequestContextLookup()).apply(this.src);
        authCtx = (AuthenticationContext) prc.addSubcontext(new AuthenticationContext(), true);
    }

    @Test
    public void testSuccessAnyHeaders() throws ComponentInitializationException {
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertProceedEvent(event);
        ReverseProxyAuthenticationContext rpCtx = authCtx.getSubcontext(ReverseProxyAuthenticationContext.class);
        Assert.assertNotNull(rpCtx);
        Assert.assertEquals(rpCtx.getHeaderClaims().size(), 3);
        Assert.assertEquals(rpCtx.getHeaderClaims().get("header1").get(0), "value1");
        Assert.assertEquals(rpCtx.getHeaderClaims().get("header2").get(0), "value2");
        Assert.assertEquals(rpCtx.getHeaderClaims().get("header3").get(0), "value3");
    }

    @Test
    public void testSuccessPickHeaders() throws ComponentInitializationException {
        action.setHeaderPattern("^header[12].*");
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertProceedEvent(event);
        ReverseProxyAuthenticationContext rpCtx = authCtx.getSubcontext(ReverseProxyAuthenticationContext.class);
        Assert.assertNotNull(rpCtx);
        Assert.assertEquals(rpCtx.getHeaderClaims().size(), 2);
        Assert.assertEquals(rpCtx.getHeaderClaims().get("header1").get(0), "value1");
        Assert.assertEquals(rpCtx.getHeaderClaims().get("header2").get(0), "value2");
    }

    @Test
    public void testSuccessNoHeaders() throws ComponentInitializationException {
        action.setHttpServletRequest(new MockHttpServletRequest());
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertProceedEvent(event);
        ReverseProxyAuthenticationContext rpCtx = authCtx.getSubcontext(ReverseProxyAuthenticationContext.class);
        Assert.assertNotNull(rpCtx);
        Assert.assertEquals(rpCtx.getHeaderClaims().size(), 0);
    }

    @Test
    public void testNoServlet() throws ComponentInitializationException {
        action = new ExtractHeaderValuesFromRequest();
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

}
