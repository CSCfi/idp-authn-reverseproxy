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

import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

/**
 * Unit tests for {@link ReverseProxyAuthenticationContext}.
 */
public class ReverseProxyAuthenticationContextTest {

    private ReverseProxyAuthenticationContext ctx;

    @BeforeTest
    public void initTest() {
        ctx = new ReverseProxyAuthenticationContext();
    }

    @Test
    public void testInitialization() {
        Assert.assertNotNull(ctx.getHeaderClaims());
        Assert.assertEquals(ctx.getHeaderClaims().size(), 2);
    }

    @Test
    public void testAdding() {
        ctx.addHeaderClaim("header1", "value1-1");
        ctx.addHeaderClaim("header1", "value1-2");
        ctx.addHeaderClaim("header2", "value2-1");
        Assert.assertEquals(ctx.getHeaderClaims().size(), 2);
        ctx.getHeaderClaims().entrySet().forEach(entry -> {
            Assert.assertEquals(entry.getValue().size(), entry.getKey().equals("header1") ? 2 : 1);
            Assert.assertEquals(entry.getValue().contains("value1-1"), entry.getKey().equals("header1") ? true : false);
            Assert.assertEquals(entry.getValue().contains("value1-2"), entry.getKey().equals("header1") ? true : false);
            Assert.assertEquals(entry.getValue().contains("value2-1"), entry.getKey().equals("header2") ? true : false);
        });
    }

    @Test(expectedExceptions = {UnsupportedOperationException.class})
    public void testImmutability() {
        ctx.getHeaderClaims().put("header1", null);
    }

}
