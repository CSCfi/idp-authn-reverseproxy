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

import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;

import java.io.UnsupportedEncodingException;
import java.util.regex.Pattern;

import javax.annotation.Nonnull;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import fi.csc.shibboleth.authn.context.ReverseProxyAuthenticationContext;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Action extracts and populates selected http headers to {@link ReverseProxyAuthenticationContext}. This context is
 * then attached to {@link AuthenticationContext}.
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * @pre
 * 
 *      <pre>
 *      ProfileRequestContext.getSubcontext(AuthenticationContext.class, false) != null
 *      </pre>
 * 
 * @post If getHttpServletRequest() != null, selected HTTP headers with String values are extracted to populate a
 *       {@link ReverseProxyAuthenticationContext}.
 */
public class ExtractHeaderValuesFromRequest extends AbstractExtractionAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ExtractHeaderValuesFromRequest.class);

    /** Pattern to match the header names to be extracted. */
    private String headerPattern = ".*";

    /**
     * Set regex pattern for header names to be extracted. Default is match any ".*"
     * 
     * @param pattern regex pattern
     */
    public void setHeaderPattern(String pattern) {
        headerPattern = pattern;
    }

    /**
     * Set the encoding for headers. If not set to null, the header values are transformed into UTF-8.
     * 
     * @param encoding What to set.
     */
    public void setHeaderEncoding(final String encoding) {
        headerEncoding = encoding;
    }

    /** The encoding for headers. If not set to null, the header values are transformed into UTF-8. */
    private String headerEncoding;

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        final HttpServletRequest request = getHttpServletRequest();
        if (request == null) {
            log.debug("{} Profile action does not contain an HttpServletRequest", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }
        final ReverseProxyAuthenticationContext reverseProxyContext =
                (ReverseProxyAuthenticationContext) authenticationContext
                        .addSubcontext(new ReverseProxyAuthenticationContext(), true);

        request.getHeaderNames().asIterator().forEachRemaining(headerName -> {
            log.debug("{} Located header {} with value {}", getLogPrefix(), headerName,
                    request.getHeader((String) headerName));
            if (Pattern.matches(headerPattern, (String) headerName)) {
                try {
                    final String value = headerEncoding == null
                            ? applyTransforms(request.getHeader((String) headerName)) : applyTransforms(new String(
                                    request.getHeader((String) headerName).getBytes(headerEncoding), "UTF-8"));
                    log.debug("{} Extracted header {} with value {}", getLogPrefix(), headerName, value);
                    reverseProxyContext.addHeaderClaim((String) headerName, value);
                } catch (UnsupportedEncodingException e) {
                    log.error("{} Extraction failed for header", getLogPrefix(), e);
                }
            }

        });
    }
}
