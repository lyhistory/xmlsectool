/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.shibboleth.tool.xmlsectool;

import java.security.interfaces.DSAPublicKey;

import org.opensaml.security.x509.X509Credential;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;

/**
 * Test for regression against DSA signing ability.
 */
public class XSTJ59Test extends BaseTest {

    XSTJ59Test() {
        super(XSTJ59Test.class);
    }
    
    /**
     * Test for regressions against earlier versions of xmlsectool using 1024-bit DSA and SHA-1 digest.
     * 
     * @throws Exception if something goes wrong.
     */
    @Test
    public void xstj59_1024_regression() throws Exception {
        // acquire a credential to sign with
        final X509Credential cred = getSigningCredential("dsa1024", "DSA", DSAPublicKey.class);

        // build command-line arguments
        final String[] args = {
                "--sign",
                "--inFile", "in.xml",
                "--outFile", "out.xml",
                "--certificate", "sign.crt",
                "--key", "sign.key",
                "--digest", "SHA-1",
                "--whitelistDigest", "SHA-1"
                };
        final CommandLineArguments cli = new CommandLineArguments();
        cli.parseCommandLineArguments(args);
        XMLSecTool.initLogging(cli);

        // check that the credential is of the right kind
        final DSAPublicKey key = (DSAPublicKey)cred.getPublicKey();
        Assert.assertEquals(key.getParams().getP().bitLength(), 1024);

        // acquire a document to sign
        final Document xml = readXMLDocument("in.xml");
        
        // perform signature operation
        XMLSecTool.sign(cli, cred, xml);
        
        // verify the signature using our own code for consistency
        XMLSecTool.verifySignature(cli, cred, xml);

        // compare with output from V1.x
        final Document out = readXMLDocument("out1024.xml");
        zapSignatureValues(xml);
        zapSignatureValues(out);
        assertXMLIdentical(out.getDocumentElement(), xml.getDocumentElement());
    }
}
