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

import java.io.PrintStream;
import java.util.List;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;

/** Command line arguments for the {@link XMLSecTool} command line tool. */
public class CommandLineArguments {

    /*
     * Checkstyle: JavadocVariable OFF
     * Checkstyle: JavadocMethod OFF
     */

    /** Prefix for all command-line option names. Separated out to make it easer to replicate the old usage text. */
    private static final String OPT = "--";

    // Command-line option names, in their order of first appearance in the usage text
    private static final String HELP_ARG = "help";
    private static final String SIGN_ARG = "sign";
    private static final String V_SIG_ARG = "verifySignature";
    private static final String V_SCHEMA_ARG = "validateSchema";
    private static final String IN_FILE_ARG = "inFile";
    private static final String IN_URL_ARG = "inUrl";
    private static final String BASE64_IN_ARG = "base64DecodeInput";
    private static final String BASE64_OUT_ARG = "base64EncodeOutput";
    private static final String INFLATE_IN_ARG = "inflateInput";
    private static final String GUNZIP_IN_ARG = "gunzipInput";
    private static final String HTTP_PROXY_ARG = "httpProxy";
    private static final String HTTP_PROXY_PORT_ARG = "httpProxyPort";
    private static final String HTTP_PROXY_USERNAME_ARG = "httpProxyUsername";
    private static final String HTTP_PROXY_PASSWORD_ARG = "httpProxyPassword";
    private static final String SCHEMA_XSD_LANG_ARG = "xsd";
    private static final String SCHEMA_RNG_LANG_ARG = "relaxng";
    private static final String SCHEMA_DIR_ARG = "schemaDirectory";
    private static final String SIG_REF_ID_ATT_ARG = "referenceIdAttributeName";
    private static final String SIG_POS_ARG = "signaturePosition";
    private static final String DIGEST_ARG = "digest";
    private static final String DIGEST_ALGORITHM_ARG = "digestAlgorithm";
    private static final String SIGNATURE_ALGORITHM_ARG = "signatureAlgorithm";
    private static final String KI_KEY_NAME_ARG = "keyInfoKeyName";
    private static final String KI_CRL_ARG = "keyInfoCRL";
    private static final String CERT_ARG = "certificate";
    private static final String KEY_ARG = "key";
    private static final String KEY_PASSWORD_ARG = "keyPassword";
    private static final String KEYSTORE_ARG = "keystore";
    private static final String KEYSTORE_PASSWORD_ARG = "keystorePassword";
    private static final String KEYSTORE_TYPE_ARG = "keystoreType";
    private static final String KEYSTORE_PROVIDER_ARG = "keystoreProvider";
    private static final String PKCS11_CONFIG_ARG = "pkcs11Config";
    private static final String CLEAR_BLACKLIST_ARG = "clearBlacklist";
    private static final String BLACKLIST_DIGEST_ARG = "blacklistDigest";
    private static final String WHITELIST_DIGEST_ARG = "whitelistDigest";
    private static final String LIST_BLACKLIST_ARG = "listBlacklist";
    private static final String OUT_FILE_ARG = "outFile";
    private static final String DEFLATE_OUT_ARG = "deflateOutput";
    private static final String GZIP_OUT_ARG = "gzipOutput";
    private static final String VERBOSE_ARG = "verbose";
    private static final String QUIET_ARG = "quiet";
    private static final String LOG_CONFIG_ARG = "logConfig";

    // Actions
    @Parameter(names = OPT + SIGN_ARG)
    private boolean sign;

    @Parameter(names = OPT + V_SCHEMA_ARG)
    private boolean schemaValidate;

    @Parameter(names = OPT + V_SIG_ARG)
    private boolean signatureVerify;

    // Input
    @Parameter(names = OPT + IN_FILE_ARG)
    private String inFile;

    @Parameter(names = OPT + IN_URL_ARG)
    private String inUrl;

    @Parameter(names = OPT + BASE64_IN_ARG)
    private boolean base64DecodeInput;

    @Parameter(names = OPT + INFLATE_IN_ARG)
    private boolean inflateInput;

    @Parameter(names = OPT + GUNZIP_IN_ARG)
    private boolean gunzipInput;

    @Parameter(names = OPT + HTTP_PROXY_ARG)
    private String httpProxy;

    @Parameter(names = OPT + HTTP_PROXY_PORT_ARG)
    private int httpProxyPort = 80;

    @Parameter(names = OPT + HTTP_PROXY_USERNAME_ARG)
    private String httpProxyUsername;

    @Parameter(names = OPT + HTTP_PROXY_PASSWORD_ARG)
    private String httpProxyPassword;

    // Schema Validation
    @Parameter(names = OPT + SCHEMA_DIR_ARG)
    private String schemaDirectory;

    @Parameter(names = OPT + SCHEMA_XSD_LANG_ARG)
    private boolean xsdSchema;

    @Parameter(names = OPT + SCHEMA_RNG_LANG_ARG)
    private boolean rngSchema;

    // Signature
    @Parameter(names = OPT + SIG_REF_ID_ATT_ARG)
    private String refIdAttributeName;

    @Parameter(names = OPT + SIG_POS_ARG)
    private String signaturePosition;

    /**
     * Digest algorithm choice for all algorithms.
     */
    private DigestChoice digest;
    
    /**
     * Selected digest algorithm choice name for all algorithms.
     */
    @Parameter(names = OPT + DIGEST_ARG)
    private String digestName;
    
    /**
     * Digest algorithm URI directly specified on the command line.
     */
    @Parameter(names = OPT + DIGEST_ALGORITHM_ARG)
    private String digestAlgorithm;
    
    /**
     * Signature algorithm URI directly specified on the command line.
     */
    @Parameter(names = OPT + SIGNATURE_ALGORITHM_ARG)
    private String signatureAlgorithm;

    @Parameter(names = OPT + KI_KEY_NAME_ARG)
    private List<String> kiKeyNames;

    @Parameter(names = OPT + KI_CRL_ARG)
    private List<String> kiCrls;

    // Output
    @Parameter(names = OPT + OUT_FILE_ARG)
    private String outFile;

    @Parameter(names = OPT + BASE64_OUT_ARG)
    private boolean base64EncodeOutput;

    @Parameter(names = OPT + DEFLATE_OUT_ARG)
    private boolean deflateOutput;

    @Parameter(names = OPT + GZIP_OUT_ARG)
    private boolean gzipOutput;

    // Key/Cert Data
    @Parameter(names = OPT + CERT_ARG)
    private String cert;

    @Parameter(names = OPT + KEY_ARG)
    private String key;

    @Parameter(names = OPT + KEY_PASSWORD_ARG)
    private String keyPassword;

    @Parameter(names = OPT + KEYSTORE_ARG)
    private String keystore;

    @Parameter(names = OPT + KEYSTORE_PASSWORD_ARG)
    private String keystorePassword;

    @Parameter(names = OPT + KEYSTORE_TYPE_ARG)
    private String keystoreType;

    @Parameter(names = OPT + KEYSTORE_PROVIDER_ARG)
    private String keystoreProvider;

    @Parameter(names = OPT + PKCS11_CONFIG_ARG)
    private String pkcs11Config;

    // Blacklisting
    
    /**
     * Local blacklist of signature and digest algorithms.
     */
    private final Blacklist blacklist = new Blacklist();
    
    /**
     * Option requesting that the signature verification
     * blacklists be cleared.
     */
    @Parameter(names = OPT + CLEAR_BLACKLIST_ARG)
    private boolean clearBlacklist;
        
    /**
     * Option requesting that the signature verification
     * blacklists be listed.
     */
    @Parameter(names = OPT + LIST_BLACKLIST_ARG)
    private boolean listBlacklist;

    @Parameter(names = OPT + BLACKLIST_DIGEST_ARG)
    private List<String> blacklistDigestNames;

    @Parameter(names = OPT + WHITELIST_DIGEST_ARG)
    private List<String> whitelistDigestNames;
    
    // Logging
    @Parameter(names = OPT + VERBOSE_ARG)
    private boolean verbose;

    @Parameter(names = OPT + QUIET_ARG)
    private boolean quiet;

    @Parameter(names = OPT + LOG_CONFIG_ARG)
    private String logConfig;

    // Help
    @Parameter(names = HELP_ARG, help = true)
    private boolean help;

    public void parseCommandLineArguments(final String[] args) {
        try {
            final JCommander jc = new JCommander(this);
            jc.parse(args);

            if (!xsdSchema && !rngSchema) {
                xsdSchema = true;
            }

            validateCommandLineArguments();
            processBlacklistOptions();
        } catch (final ParameterException e) {
            errorAndExit(e.getMessage());
        }
    }
    
    /**
     * Handle options related to setting up the blacklist.
     * 
     * These are --clearBlacklist, --blacklistDigest and --whitelistDigest.
     */
    private void processBlacklistOptions() {
        if (clearBlacklist) {
            blacklist.clear();
        }

        if (blacklistDigestNames != null) {
            for (final String name : blacklistDigestNames) {
                final DigestChoice dig = DigestChoice.find(name);
                if (dig == null) {
                    errorAndExit("digest choice \"" + name + "\" was not recognised");
                }
                blacklist.addDigest(dig);
            }
        }

        if (whitelistDigestNames != null) {
            for (final String name : whitelistDigestNames) {
                final DigestChoice dig = DigestChoice.find(name);
                if (dig == null) {
                    errorAndExit("digest choice \"" + name + "\" was not recognised");
                }
                blacklist.removeDigest(dig);
            }
        }
    }

    public String getHttpProxy() {
        return httpProxy;
    }

    public int getHttpProxyPort() {
        return httpProxyPort;
    }

    public String getHttpProxyUsername() {
        return httpProxyUsername;
    }

    public String getHttpProxyPassword() {
        return httpProxyPassword;
    }

    public boolean doSign() {
        return sign;
    }

    public boolean doSchemaValidation() {
        return schemaValidate;
    }

    public boolean doSignatureVerify() {
        return signatureVerify;
    }

    public String getReferenceIdAttributeName() {
        return refIdAttributeName;
    }

    public String getSignaturePosition() {
        return signaturePosition;
    }

    /**
     * Returns the choice of digest algorithm.
     * 
     * @return selected digest algorithm
     */
    public DigestChoice getDigest() {
        return digest;
    }
    
    /**
     * Returns the digest algorithm URI if specified on the command line.
     * 
     * @return a digest algorithm identifier, or <code>null</code>.
     */
    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }
    
    /**
     * Returns the signature algorithm URI if specified on the command line.
     * 
     * @return a signature algorithm identifier, or <code>null</code>.
     */
    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }
    
    public List<String> getKeyInfoKeyNames() {
        return kiKeyNames;
    }

    public List<String> getKeyInfoCrls() {
        return kiCrls;
    }

    public String getInputFile() {
        return inFile;
    }

    public String getInputUrl() {
        return inUrl;
    }

    public boolean isBase64DecodeInput() {
        return base64DecodeInput;
    }

    public boolean isInflateInput() {
        return inflateInput;
    }

    public boolean isGunzipInput() {
        return gunzipInput;
    }

    public String getSchemaDirectory() {
        return schemaDirectory;
    }

    public boolean isXsdSchema() {
        return xsdSchema;
    }

    public boolean isRngSchema() {
        return rngSchema;
    }

    public String getOutputFile() {
        return outFile;
    }

    public boolean isBase64EncodedOutput() {
        return base64EncodeOutput;
    }

    public boolean isDeflateOutput() {
        return deflateOutput;
    }

    public boolean isGzipOutput() {
        return gzipOutput;
    }

    public String getCertificate() {
        return cert;
    }

    public String getKey() {
        return key;
    }

    public String getKeyPassword() {
        return keyPassword;
    }

    public String getKeystore() {
        return keystore;
    }

    public String getKeystorePassword() {
        return keystorePassword;
    }

    public String getKeystoreType() {
        return keystoreType;
    }

    public String getKeystoreProvider() {
        return keystoreProvider;
    }

    public String getPkcs11Config() {
        return pkcs11Config;
    }
    
    /**
     * Returns the signature verification algorithm blacklist.
     * 
     * @return algorithm blacklist
     */
    public Blacklist getBlacklist() {
        return blacklist;
    }
    
    /**
     * Indicates whether the option to list the blacklist has been selected.
     * 
     * @return <code>true</code> if option selected
     */
    public boolean doListBlacklist() {
        return listBlacklist;
    }
    
    public boolean doVerboseOutput() {
        return verbose;
    }

    public boolean doQuietOutput() {
        return quiet;
    }

    public String getLoggingConfiguration() {
        return logConfig;
    }

    public boolean doHelp() {
        return help;
    }

    private void validateCommandLineArguments() {
        if (doHelp()) {
            return;
        }

        if (doListBlacklist()) {
            return;
        }
        
        if (!doSchemaValidation() && !doSignatureVerify() && !doSign()) {
            errorAndExit("No action was specified");
        }

        if ((getInputFile() == null && getInputUrl() == null) || (getInputFile() != null && getInputUrl() != null)) {
            errorAndExit("One, and only one, document input method must be specified");
        }

        if (isInflateInput() && isGunzipInput()) {
            errorAndExit((new StringBuilder("Options ")).append(INFLATE_IN_ARG).append(" and ")
                    .append(GUNZIP_IN_ARG).append(" are mutually exclusive").toString());
        }

        if (doSchemaValidation()) {
            if (getSchemaDirectory() == null) {
                errorAndExit(SCHEMA_DIR_ARG + " option is required");
            }

            if (isXsdSchema() && isRngSchema()) {
                errorAndExit("XML Schema and RelaxNG languages may not be used simultaneously");
            }
        }

        if (doSign() && doSignatureVerify()) {
            errorAndExit("The signing and signature verification actions are mutually exclusive");
        }

        if (doSign() || doSignatureVerify()) {
            if (getCertificate() == null && getPkcs11Config() == null && getKeystore() == null) {
                errorAndExit("No credential source was given, unable to perform signature operation");
            }

        }

        if (digestName != null) {
            digest = DigestChoice.find(digestName);
            if (digest == null) {
                errorAndExit("digest choice \"" + digestName + "\" was not recognised");
            }
        } else {
            digest = DigestChoice.SHA256;
        }
        
        if (doSign()) {
            if (getKey() == null) {
                errorAndExit(KEY_ARG + " option is required");
            }

            if ((getKeystore() != null || getPkcs11Config() != null) && getKeyPassword() == null) {
                errorAndExit(KEY_PASSWORD_ARG + " option is required");
            }

            if (getOutputFile() == null) {
                errorAndExit("No output location specified");
            }
        }

        if (isDeflateOutput() && isGzipOutput()) {
            errorAndExit((new StringBuilder("Options ")).append(DEFLATE_OUT_ARG).append(" and ")
                    .append(GZIP_OUT_ARG).append(" are mutually exclusive").toString());
        }

        if (doVerboseOutput() && doQuietOutput()) {
            errorAndExit("Verbose and quiet output are mutually exclusive");
        }

    }

    /**
     * Print command line help instructions.
     * 
     * @param out location where to print the output
     */
    // Checkstyle: MethodLength OFF
    public void printHelp(final PrintStream out) {
        out.println("XML Security Tool");
        out.println("Provides a command line interface for schema validating, signing, " +
                "and signature validating an XML file.");
        out.println();
        out.println("==== Command Line Options ====");
        out.println();
        out.println(String.format("  --%-20s %s", HELP_ARG, "Prints this help information"));
        out.println();
        out.println("Action Options - '" + SIGN_ARG + "' and '" + V_SIG_ARG
                + "' are mutually exclusive.  At least one option is required.");
        out.println(String.format("  --%-20s %s", V_SCHEMA_ARG, "Schema validate the document."));
        out.println(String.format("  --%-20s %s", SIGN_ARG, "Sign the XML document."));
        out.println(String.format("  --%-20s %s", V_SIG_ARG, "Check the signature on a signed document."));

        out.println();
        out.println("Data Input Options - '" + IN_FILE_ARG + "' and '" + IN_URL_ARG
                + "' are mutually exclusive, one is required.");
        out.println(String.format("  --%-20s %s", IN_FILE_ARG,
                "Specifies the file from which the XML document will be read."));
        out.println(String.format("  --%-20s %s", IN_URL_ARG,
                "Specifies the URL from which the XML document will be read. HTTPS certificates are not validated."));
        out.println(String.format("  --%-20s %s", BASE64_IN_ARG,
                "Base64 decodes input.  Useful when reading in data produced with the " + BASE64_OUT_ARG
                        + " option"));
        out.println(String.format("  --%-20s %s", INFLATE_IN_ARG,
                "Inflates a file created with the \"deflate\" compression algorithm.  This property is ignored if "
                        + IN_URL_ARG
                        + " is used.  Instead the returned headers determine if content was deflated"));
        out.println(String.format("  --%-20s %s", GUNZIP_IN_ARG,
                "Inflates a file created with the \"gzip\" compression algorithm.  This property is ignored if "
                        + IN_URL_ARG
                        + " is used.  Instead the returned headers determine if content was gzip'ed"));

        out.println(String.format("  --%-20s %s", HTTP_PROXY_ARG,
                "HTTP proxy address used when fetching URL-based input files."));
        out.println(String.format("  --%-20s %s", HTTP_PROXY_PORT_ARG, "HTTP proxy port. (default: 80)"));
        out.println(String.format("  --%-20s %s", HTTP_PROXY_USERNAME_ARG,
                "Username used to authenticate to the HTTP proxy."));
        out.println(String.format("  --%-20s %s", HTTP_PROXY_PASSWORD_ARG,
                "Password used to authenticate to the HTTP proxy."));

        out.println();
        out.println("Schema Validation Option - '" + SCHEMA_XSD_LANG_ARG + "' (default) and '"
                + SCHEMA_RNG_LANG_ARG + "' are mutually exclusive option.");
        out.println(String.format("  --%-20s %s", SCHEMA_DIR_ARG,
                "Specifies a schema file or directory of schema files.  Subdirectories are also read."));
        out.println(String.format("  --%-20s %s", SCHEMA_XSD_LANG_ARG,
                "Indicates schema files are W3 XML Schema 1.0 files (.xsd)."));
        out.println(String.format("  --%-20s %s", SCHEMA_RNG_LANG_ARG,
                "Indicates schema files are OASIS RELAX NG files (.rng)."));

        out.println();
        out.println("Signature Creation Options");
        out.println(String.format(
                "  --%-20s %s",
                SIG_REF_ID_ATT_ARG,
                "Specifies the name of the attribute on the document element "
                        + "whose value is used as the URI reference of the signature.  If omitted, "
                        + "a null reference URI is used."));
        out.println(String.format("  --%-20s %s", SIG_POS_ARG,
                "Specifies, by 1-based index, which element to place the signature BEFORE.  "
                        + "'FIRST' may be used to indicate that the signature goes BEFORE the first element. "
                        + "'LAST' may be used to indicate that the signature goes AFTER the last element."
                        + " (default value: FIRST)"));
        out.println(String.format("  --%-20s %s", DIGEST_ARG,
                "Specifies the name of the digest algorithm to use: SHA-1, SHA-256 (default), SHA-384, SHA-512."
                        + "  For RSA and EC credentials, dictates both the digest and signature algorithms."));
        out.println(String.format("  --%-20s %s", DIGEST_ALGORITHM_ARG,
                "Specifies the URI of the digest algorithm to use; overrides --"
                        + DIGEST_ARG + "."));
        out.println(String.format("  --%-20s %s", SIGNATURE_ALGORITHM_ARG,
                "Specifies the URI of the signature algorithm to use; overrides --"
                        + DIGEST_ARG + "."));
        out.println(String.format("  --%-20s %s", KI_KEY_NAME_ARG,
                "Specifies a key name to be included in the key info.  Option may be used more than once."));
        out.println(String.format("  --%-20s %s", KI_CRL_ARG,
                "Specifies a file path for a CRL to be included in the key info.  "
                        + "Option may be used more than once."));

        out.println();
        out.println("PEM/DER Encoded Certificate/Key Options - "
                + "these options are mutually exclusive with the Keystore and PKCS#11 options. "
                + "The '" + CERT_ARG + "' option is required for signature verification. "
                + "The '" + CERT_ARG + "' and '" + KEY_ARG
                    + "' options are required for signing.");
        out.println(String.format("  --%-20s %s", CERT_ARG,
                "Specifies the file from which the signing, or validation, certificate is read."));
        out.println(String.format("  --%-20s %s", KEY_ARG,
                "Specifies the file from which the signing key is read."));
        out.println(String.format("  --%-20s %s", KEY_PASSWORD_ARG,
                "Specifies the password for the signing key."));

        out.println();
        out.println("Keystore Certificate/Key Options - "
                + "these options are mutually exclusive with the PEM/DER and PKCS#11 options."
                + " Options '"
                + KEYSTORE_ARG
                + "', '"
                + KEY_ARG
                + "', and '"
                + KEY_PASSWORD_ARG + "' are required.");
        out.println(String.format("  --%-20s %s", KEYSTORE_ARG, "Specifies the keystore file."));
        out.println(String.format("  --%-20s %s", KEYSTORE_PASSWORD_ARG,
                "Specifies the password for the keystore. If not provided then the key password is used."));
        out.println(String.format("  --%-20s %s", KEYSTORE_TYPE_ARG, "Specifies the type of the keystore."));
        out.println(String.format("  --%-20s %s", KEYSTORE_PROVIDER_ARG,
                "Specifies the keystore provider class to use instead of the default one for the JVM."));
        out.println(String.format("  --%-20s %s", KEY_ARG,
                "Specifies the key alias for the signing key is read."));
        out.println(String.format("  --%-20s %s", KEY_PASSWORD_ARG,
                "Specifies the password for the signing key. Keystore password used if none is given."));

        out.println();
        out.println("PKCS#11 Device Certificate/Key Options - "
                + "these options are mutually exclusive with the PEM/DER and Keystore options."
                + " Options '"
                + PKCS11_CONFIG_ARG
                + "' and '"
                + KEY_ARG
                + "' are required. Option '"
                + KEY_PASSWORD_ARG
                + "' required when signing and, with some PKCS#11 devices, during signature verification.");
        out.println(String.format("  --%-20s %s", PKCS11_CONFIG_ARG, "The PKCS#11 token configuration file."));
        out.println(String.format("  --%-20s %s", KEY_ARG,
                "Specifies the key alias for the signing key is read."));
        out.println(String.format("  --%-20s %s", KEY_PASSWORD_ARG, "Specifies the pin for the signing key."));
        out.println(String.format(
                "  --%-20s %s",
                KEYSTORE_PROVIDER_ARG,
                "The fully qualified class name of the PKCS#11 keystore provider implementation. "
                + "(e.g., sun.security.pkcs11.SunPKCS11)"));

        out.println();
        out.println("Signature verification algorithm blacklist options:");
        out.println(String.format("  --%-20s %s", CLEAR_BLACKLIST_ARG,
                "Clear the algorithm blacklist."));
        out.println(String.format("  --%-20s %s", BLACKLIST_DIGEST_ARG,
                "Blacklist a digest by name (e.g., \"SHA-1\").  Can be used any number of times."));
        out.println(String.format("  --%-20s %s", WHITELIST_DIGEST_ARG,
                "Whitelist a digest by name (e.g., \"SHA-1\").  Can be used any number of times."));
        out.println(String.format("  --%-20s %s", LIST_BLACKLIST_ARG,
                "List the contents of the algorithm blacklist."));
        
        out.println();
        out.println("Data Output Options - Option '" + OUT_FILE_ARG + "' is required.");
        out.println(String.format("  --%-20s %s", OUT_FILE_ARG,
                "Specifies the file to which the signed XML document will be written."));
        out.println(String.format("  --%-20s %s", BASE64_OUT_ARG,
                "Base64 encode the output. Ensures signed content isn't corrupted."));
        out.println(String.format("  --%-20s %s", DEFLATE_OUT_ARG, "Deflate compresses the output."));
        out.println(String.format("  --%-20s %s", GZIP_OUT_ARG, "GZip compresses the output."));

        out.println();
        out.println("Logging Options - these options are mutually exclusive");
        out.println(String.format("  --%-20s %s", VERBOSE_ARG, "Turn on verbose messages."));
        out.println(String.format("  --%-20s %s", QUIET_ARG,
                "Do not write any messages to STDERR or STDOUT."));
        out.println(String.format("  --%-20s %s", LOG_CONFIG_ARG,
                "Specifies a logback configuration file to use to configure logging."));
        out.println();
    }

    // Checkstyle: MethodLength ON

    /**
     * Prints the error message to STDERR and then exits.
     * 
     * @param error the error message
     */
    private void errorAndExit(final String error) {
        System.err.println(error);
        System.err.flush();
        System.out.println();
        printHelp(System.out);
        System.out.flush();
        throw new Terminator(ReturnCode.RC_INIT);
    }
}