package net.shibboleth.tool.xmlsectool;

import org.testng.Assert;
import org.testng.annotations.Test;

import net.shibboleth.tool.xmlsectool.XmlSecToolCommandLineArguments.DigestChoice;

public class XmlSecToolCommandLineArgumentsTest {

	@Test
	public void xstj34_sign_with_SHA256() throws Exception{
		final String[] args = {
				"--sign",
				"--inFile", "in.xml",
				"--outFile", "out.xml",
				"--certificate", "example.crt",
				"--key", "example.key"
				};
		final XmlSecToolCommandLineArguments cli = new XmlSecToolCommandLineArguments();
		cli.parseCommandLineArguments(args);
		final DigestChoice digest = cli.getDigest();
		Assert.assertNotNull(digest);
		Assert.assertSame(digest, DigestChoice.SHA256);
	}
}
