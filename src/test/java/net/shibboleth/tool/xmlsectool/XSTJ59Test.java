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
        XmlSecTool.initLogging(cli);

        // check that the credential is of the right kind
        final DSAPublicKey key = (DSAPublicKey)cred.getPublicKey();
        Assert.assertEquals(key.getParams().getP().bitLength(), 1024);

        // acquire a document to sign
        final Document xml = readXMLDocument("in.xml");
        
        // perform signature operation
        XmlSecTool.sign(cli, cred, xml);
        
        // verify the signature using our own code for consistency
        XmlSecTool.verifySignature(cli, cred, xml);

        // compare with output from V1.x
        final Document out = readXMLDocument("out1024.xml");
        zapSignatureValues(xml);
        zapSignatureValues(out);
        assertXMLIdentical(out.getDocumentElement(), xml.getDocumentElement());
    }
}
