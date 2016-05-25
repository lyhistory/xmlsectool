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

public class XSTJ51 extends BaseTest {

    XSTJ51() {
        super(XSTJ51.class);
    }
    
    @Test
    public void xstj51_KeyInfo() throws Exception {
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
        XmlSecTool.initLogging(cli);

        // check that the credential is of the right kind

        // acquire a document to sign
        final Document xml = readXMLDocument("in.xml");
        
        // perform signature operation
        XmlSecTool.sign(cli, cred, xml);
        
        // verify the signature using our own code for consistency
        XmlSecTool.verifySignature(cli, cred, xml);

        // take a careful look at the signature
        final Element signatureElement = XmlSecTool.getSignatureElement(xml);
        final Element keyInfoElement = ElementSupport.getFirstChildElement(signatureElement,
                KeyInfo.DEFAULT_ELEMENT_NAME);
        final List<Element> keyInfoChildren = ElementSupport.getChildElements(keyInfoElement);
        Assert.assertFalse(keyInfoChildren.isEmpty());
        final List<Element> keyValues = ElementSupport.getChildElements(keyInfoElement, KeyValue.DEFAULT_ELEMENT_NAME);
        for (final Element keyValue : keyValues) {
            Assert.assertNotNull(ElementSupport.getFirstChildElement(keyValue), "empty KeyValue element");
        }

        // validate the resulting XML; this will also show up any error
        final SchemaValidator validator = new SchemaValidator(SchemaLanguage.XML, getSchemaDirectory());
        validator.validate(new DOMSource(xml));
    }
}
