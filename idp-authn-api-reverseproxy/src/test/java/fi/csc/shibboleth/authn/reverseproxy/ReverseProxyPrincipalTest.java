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

package fi.csc.shibboleth.authn.reverseproxy;

import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

/**
 * Unit testing for {@link ReverseProxyPrincipal}.
 */
public class ReverseProxyPrincipalTest extends KeyValuePrincipalTest {

    @Override
    @BeforeTest
    @Test
    public void initTests() {
        super.initTests();
        principalClass = ReverseProxyPrincipal.class;
    }

    @Test
    public void testClone() throws Exception {
        super.assertKeyAndValue(new ReverseProxyPrincipal(key, value).clone());
    }

    @Test
    public void testEquals() throws Exception {
        ReverseProxyPrincipal principal1 = new ReverseProxyPrincipal(key, value);
        Object principal2 = new ReverseProxyPrincipal(key + KeyValuePrincipal.SEPARATOR + value);
        Object principal3 = new ReverseProxyPrincipal(key + "mock", value);
        Object principal4 = new ReverseProxyPrincipal(key, "mock" + value);
        Assert.assertTrue(principal1.equals(principal1));
        Assert.assertTrue(principal1.equals(principal2));
        Assert.assertFalse(principal1.equals(null));
        Assert.assertFalse(principal1.equals(principal3));
        Assert.assertFalse(principal1.equals(principal4));

    }

    @Test
    public void testHash() throws Exception {
        ReverseProxyPrincipal principal1 = new ReverseProxyPrincipal(key, value);
        ReverseProxyPrincipal principal2 = new ReverseProxyPrincipal(key + KeyValuePrincipal.SEPARATOR + value);
        ReverseProxyPrincipal principal3 = new ReverseProxyPrincipal(key, "mock" + value);
        Assert.assertEquals(principal1.hashCode(), principal2.hashCode());
        Assert.assertFalse(principal1.hashCode() == principal3.hashCode());
    }

    @Override
    public void initPrincipalClass() {
        principalClass = ReverseProxyPrincipal.class;
    }
}
