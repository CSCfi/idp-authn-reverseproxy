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

package fi.csc.shibboleth.authn.context;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.opensaml.messaging.context.BaseContext;

/**
 * This context stores the extracted header values injected by Reverse Proxy.
 */
public class ReverseProxyAuthenticationContext extends BaseContext {

    /** Header values. */
    private Map<String, List<String>> headerClaims = new HashMap<String, List<String>>();

    /**
     * Add header value. Adding a value with a name already existing in the store does not override it.
     * 
     * @param name Header name.
     * @param value Header value.
     */
    public void addHeaderClaim(String name, String value) {
        if (!headerClaims.containsKey(name)) {
            headerClaims.put(name, new ArrayList<String>());
        }
        headerClaims.get(name).add(value);
    }

    /**
     * Get header values as unmodifiable map.
     * 
     * @return Header values as unmodifiable map
     */
    public Map<String, List<String>> getHeaderClaims() {
        return Collections.unmodifiableMap(headerClaims);
    }

}
