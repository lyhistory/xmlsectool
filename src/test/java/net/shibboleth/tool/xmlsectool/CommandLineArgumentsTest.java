package net.shibboleth.tool.xmlsectool;

import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.testng.Assert;
import org.testng.annotations.Test;

public class CommandLineArgumentsTest {

	@Test
	public void xstj34_sign_with_SHA256() throws Exception {
		final String[] args = {
				"--sign",
				"--inFile", "in.xml",
				"--outFile", "out.xml",
				"--certificate", "example.crt",
				"--key", "example.key"
				};
		final CommandLineArguments cli = new CommandLineArguments();
		cli.parseCommandLineArguments(args);
		final DigestChoice digest = cli.getDigest();
		Assert.assertNotNull(digest);
		Assert.assertSame(digest, DigestChoice.SHA256);
	}
	
	@Test
	public void xstj39_default_blacklist_SHA1() throws Exception {
		final String[] args = {
				"--sign",
				"--inFile", "in.xml",
				"--outFile", "out.xml",
				"--certificate", "example.crt",
				"--key", "example.key"
				};
		final CommandLineArguments cli = new CommandLineArguments();
		cli.parseCommandLineArguments(args);
		final Blacklist blacklist = cli.getBlacklist();
		Assert.assertTrue(blacklist.isBlacklistedDigest(SignatureConstants.ALGO_ID_DIGEST_SHA1));
		Assert.assertTrue(blacklist.isBlacklistedSignature(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1));
		Assert.assertTrue(blacklist.isBlacklistedSignature(SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA1));
	}
}
