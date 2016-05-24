package net.shibboleth.tool.xmlsectool;

import java.io.File;
import java.security.PublicKey;

import org.opensaml.security.x509.BasicX509Credential;
import org.testng.Assert;
import org.testng.annotations.Test;

public class XSTJ51Test extends BaseTest {

    XSTJ51Test() {
        super(XSTJ51Test.class);
    }

    @Test
    public void testInstance() throws Exception {
        final File file = packageRelativeFile("ecsign384.crt");
        final BasicX509Credential cred = CredentialHelper.getFileBasedCredentials(null, null, file.getPath());
        final PublicKey pk = cred.getPublicKey();
        Assert.assertEquals(pk.getAlgorithm(), "EC");
        if (pk instanceof java.security.interfaces.DSAPublicKey) {
            Assert.fail("should not have been a DSAPublicKey");
        } else if (pk instanceof java.security.interfaces.RSAPublicKey) {
            Assert.fail("should not have been a RSAPublicKey");
        }
        Assert.assertTrue(pk instanceof java.security.interfaces.ECPublicKey);
    }
}
