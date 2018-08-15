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

import java.security.interfaces.ECPublicKey;
import java.util.List;

import javax.xml.transform.dom.DOMSource;

import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.KeyValue;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.xml.ElementSupport;
import net.shibboleth.utilities.java.support.xml.SchemaBuilder.SchemaLanguage;

/**
 *
 */
public class XST4050Test extends BaseTest {

    XST4050Test() {
        super(XST4050Test.class);
    }
    
    @Test
    public void xst4050_KeyInfo() throws Exception {
        // acquire an Elliptic Curve credential to sign with
        final X509Credential cred = getSigningCredential("sign", "EC", ECPublicKey.class);

        // build command-line arguments
        final String[] args = {
                "--sign",
                "--inFile", "in.xml",
                "--outFile", "out.xml",
                "--certificate", "sign.crt",
                "--key", "sign.key"
                };
        final CommandLineArguments cli = new CommandLineArguments();
        cli.parseCommandLineArguments(args);
        XMLSecTool.initLogging(cli);

        // acquire a document to sign
        final Document xml = readXMLDocument("in.xml");
        
        // perform signature operation
        XMLSecTool.sign(cli, cred, xml);
        
        // verify the signature using our own code for consistency
        XMLSecTool.verifySignature(cli, cred, xml);

        // take a careful look at the signature
        final Element signatureElement = XMLSecTool.getSignatureElement(xml);
        final Element keyInfoElement = ElementSupport.getFirstChildElement(signatureElement,
                KeyInfo.DEFAULT_ELEMENT_NAME);
        final List<Element> keyInfoChildren = ElementSupport.getChildElements(keyInfoElement);
        Assert.assertFalse(keyInfoChildren.isEmpty());
        final List<Element> keyValues = ElementSupport.getChildElements(keyInfoElement, KeyValue.DEFAULT_ELEMENT_NAME);
//        for (final Element keyValue : keyValues) {
//            Assert.assertNotNull(ElementSupport.getFirstChildElement(keyValue), "empty KeyValue element");
//        }
        final String[] args2 = {
                "--verifySignature",
                "--inFile", "in.xml",
                "--certificate", "sign.crt"
                };
        final CommandLineArguments cli2 = new CommandLineArguments();
        cli2.parseCommandLineArguments(args2);
        final Document xml2 = readXMLDocument("out.xml");
        XMLSecTool.verifySignature(cli2, cred, xml2);
        
    }

}
