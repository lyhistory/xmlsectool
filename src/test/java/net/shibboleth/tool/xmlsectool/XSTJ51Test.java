package net.shibboleth.tool.xmlsectool;

import java.io.File;
import java.security.PublicKey;
import java.util.List;

import javax.xml.transform.dom.DOMSource;

import org.opensaml.core.config.InitializationService;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.KeyValue;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.xml.ElementSupport;
import net.shibboleth.utilities.java.support.xml.SchemaBuilder.SchemaLanguage;

public class XSTJ51Test extends BaseTest {

    XSTJ51Test() {
        super(XSTJ51Test.class);
    }
    
    @Test
    public void testKeyInfo() throws Exception {
        // acquire an Elliptic Curve credential to sign with
        final File certFile = classRelativeFile("cert.crt");
        final File keyFile = classRelativeFile("key.key");

        // build command-line arguments
        final String[] args = {
                "--sign",
                "--inFile", "in.xml",
                "--outFile", "out.xml",
                "--certificate", certFile.toString(),
                "--key", keyFile.toString()
                };
        final CommandLineArguments cli = new CommandLineArguments();
        cli.parseCommandLineArguments(args);
        XmlSecTool.initLogging(cli);
        InitializationService.initialize();

        // check that the credential is of the right kind
        final BasicX509Credential cred = XmlSecTool.getCredential(cli);
        final PublicKey pk = cred.getPublicKey();
        Assert.assertEquals(pk.getAlgorithm(), "EC");
        Assert.assertTrue(pk instanceof java.security.interfaces.ECPublicKey);

        // acquire a document to sign
        final Document xml = readXMLDocument("in.xml");
        
        // perform signature operation
        XmlSecTool.sign(cli,  xml);
        
        // verify the signature using our own code for consistency
        XmlSecTool.verifySignature(cli, xml);

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
