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

package edu.internet2.middleware.security;

import jargs.gnu.CmdLineParser;
import jargs.gnu.CmdLineParser.OptionException;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.Vector;

import org.opensaml.xml.signature.SignatureConstants;

/** Command line arguments for the {@link XmlSecTool} command line tool. */
public class XmlSecToolCommandLineArguments {

    /**
     * A blacklist of digest and signature algorithms we should not accept during
     * signature verification.
     */
    public class Blacklist {
        
        /**
         * Ordered set of blacklisted digest algorithm URIs.
         */
        private final Set<String> digestBlacklist = new TreeSet<String>();
        
        /**
         * Ordered set of blacklisted signature algorithm URIs.
         */
        private final Set<String> signatureBlacklist = new TreeSet<String>();
        
        /**
         * Constructor.
         *
         * Initializes the blacklist with those algorithms that should be
         * blacklisted by default.
         */
        public Blacklist() {
            addDigestAlgorithm(SignatureConstants.ALGO_ID_DIGEST_NOT_RECOMMENDED_MD5);
            addSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_NOT_RECOMMENDED_RSA_MD5);
        }
        
        /**
         * Blacklist an individual digest algorithm.
         * 
         * @param uri algorithm URI to blacklist
         */
        private void addDigestAlgorithm(String uri) {
            digestBlacklist.add(uri);
        }
        
        /**
         * Blacklist an individual signature algorithm.
         * 
         * @param uri algorithm URI to blacklist
         */
        private void addSignatureAlgorithm(String uri) {
            signatureBlacklist.add(uri);
        }
        
        /**
         * Blacklist the digest and signature algorithms associated with
         * a {@link DigestChoice}.
         * 
         * @param digestChoice {@link DigestChoice} to add to blacklist
         */
        public void addDigest(DigestChoice digestChoice) {
            addDigestAlgorithm(digestChoice.getDigestAlgorithm());
            addSignatureAlgorithm(digestChoice.getRsaAlgorithm());
            addSignatureAlgorithm(digestChoice.getEcdsaAlgorithm());
        }
        
        /**
         * Returns <code>true</code> if the indicated algorithm URI is blacklisted for
         * use as a digest algorithm.
         * 
         * @param alg digest algorithm URI to check
         * @return <code>true</code> if the algorithm is blacklisted
         */
        public boolean isBlacklistedDigest(String alg) {
            return digestBlacklist.contains(alg);
        }
        
        /**
         * Returns <code>true</code> if the indicated algorithm URI is blacklisted for
         * use as a signature algorithm.
         * 
         * @param alg signature algorithm URI to check
         * @return <code>true</code> if the algorithm is blacklisted
         */
        public boolean isBlacklistedSignature(String alg) {
            return signatureBlacklist.contains(alg);
        }
        
        /**
         * Returns an unmodifiable view on the set of blacklisted digest algorithms.
         * 
         * @return set of blacklisted algorithms
         */
        public Collection<String> getDigestBlacklist() {
            return Collections.unmodifiableCollection(digestBlacklist);
        }
        
        /**
         * Returns an unmodifiable view on the set of blacklisted signature algorithms.
         * 
         * @return set of blacklisted algorithms
         */
        public Collection<String> getSignatureBlacklist() {
            return Collections.unmodifiableCollection(signatureBlacklist);
        }
        
        /**
         * Empties the digest and signature blacklists.
         */
        public void clear() {
            digestBlacklist.clear();
            signatureBlacklist.clear();
        }
    }
    
    /**
     * The digest method to use in the various signature algorithms.
     */
    public static enum DigestChoice {

        /**
         * SHA-1 digest.
         */
        SHA1("SHA-1",
                SignatureConstants.ALGO_ID_DIGEST_SHA1,
                SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1,
                SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA1),
        
        /**
         * SHA-256 digest.
         */
        SHA256("SHA-256",
                SignatureConstants.ALGO_ID_DIGEST_SHA256,
                SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256,
                SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA256),
        
        /**
         * SHA-384 digest.
         */
        SHA384("SHA-384",
                SignatureConstants.ALGO_ID_DIGEST_SHA384,
                SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA384,
                SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA384),
        
        /**
         * SHA-512 digest.
         */
        SHA512("SHA-512",
                SignatureConstants.ALGO_ID_DIGEST_SHA512,
                SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512,
                SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA512);
        
        /**
         * Other name (with hyphens, etc.) used as an alternative to the enum name.
         */
        private final String otherName;
        
        /**
         * Digest algorithm.
         */
        private final String digestAlgorithm;
        
        /**
         * RSA signature algorithm.
         */
        private final String rsaAlgorithm;
        
        /**
         * ECDSA signature algorithm.
         */
        private final String ecdsaAlgorithm;
        
        /**
         * Constructor.
         * 
         * @param otherNameArg an alternative name for the enum.
         * @param digestArg digest algorithm URI
         * @param rsaArg RSA signature algorithm URI
         * @param ecdsaArg ECDSA signature algorithm URI
         */
        private DigestChoice(final String otherNameArg,
                final String digestArg, final String rsaArg, final String ecdsaArg) {
            otherName = otherNameArg;
            digestAlgorithm = digestArg;
            rsaAlgorithm = rsaArg;
            ecdsaAlgorithm = ecdsaArg;
        }
        
        /**
         * Returns the digest algorithm URI for this digest choice.
         * 
         * @return algorithm URI
         */
        public String getDigestAlgorithm() {
            return digestAlgorithm;
        }
        
        /**
         * Returns the RSA signature algorithm URI for this digest choice.
         * 
         * @return algorithm URI
         */
        public String getRsaAlgorithm() {
            return rsaAlgorithm;
        }
        
        /**
         * Returns the ECDSA signature algorithm URI for this digest choice.
         * 
         * @return algorithm URI
         */
        public String getEcdsaAlgorithm() {
            return ecdsaAlgorithm;
        }
        
        /**
         * Indicates whether the enum can be called by the provided name.
         * 
         * The name is compared ignoring case against the enum name and
         * against the "other" name.
         * 
         * @param name name to check against
         * @return <code>true</code> if and only if the enum can be called by the provided name
         */
        public boolean hasName(final String name) {
            if (name.equalsIgnoreCase(name())) {
                return true;
            }
            if (name.equalsIgnoreCase(otherName)) {
                return true;
            }
            return false;
        }

        /**
         * Finds the {@link DigestChoice} for a given digest name.
         * 
         * @param name name of the digest to be found
         * 
         * @return {@link DigestChoice} represented by the name
         */
        public static DigestChoice find(String name) {
            for (DigestChoice choice: values()) {
                if (choice.hasName(name)) {
                    return choice;
                }
            }
            return null;
        }

    }
    
    // Actions
    private boolean sign;

    private CmdLineParser.Option SIGN_ARG;

    private boolean schemaValidate;

    private CmdLineParser.Option V_SCHEMA_ARG;

    private boolean signatureVerify;

    private CmdLineParser.Option V_SIG_ARG;

    // Input
    private String inFile;

    private CmdLineParser.Option IN_FILE_ARG;

    private String inUrl;

    private CmdLineParser.Option IN_URL_ARG;

    private boolean base64DecodeInput;

    private CmdLineParser.Option BASE64_IN_ARG;

    private boolean inflateInput;

    private CmdLineParser.Option INFLATE_IN_ARG;

    private boolean gunzipInput;

    private CmdLineParser.Option GUNZIP_IN_ARG;

    private String httpProxy;

    private CmdLineParser.Option HTTP_PROXY_ARG;

    private int httpProxyPort;

    private CmdLineParser.Option HTTP_PROXY_PORT_ARG;

    private String httpProxyUsername;

    private CmdLineParser.Option HTTP_PROXY_USERNAME_ARG;

    private String httpProxyPassword;

    private CmdLineParser.Option HTTP_PROXY_PASSWORD_ARG;

    // Schema Validation
    private String schemaDirectory;

    private CmdLineParser.Option SCHEMA_DIR_ARG;

    private boolean xsdSchema;

    private CmdLineParser.Option SCHEMA_XSD_LANG_ARG;

    private boolean rngSchema;

    private CmdLineParser.Option SCHEMA_RNG_LANG_ARG;

    // Signature
    private boolean signatureRequired;

    private CmdLineParser.Option SIG_REQUIRED_ARG;

    private String refIdAttributeName;

    private CmdLineParser.Option SIG_REF_ID_ATT_ARG;

    private String signaturePosition;

    private CmdLineParser.Option SIG_POS_ARG;

    private List<String> inclusiveNamespacePrefixs;

    private CmdLineParser.Option SIG_INC_PREFIX_ARG;

    /**
     * Digest algorithm choice for all algorithms.
     */
    private DigestChoice digest;
    
    /**
     * Selected digest algorithm choice name for all algorithms.
     */
    private String digestName;
    
    /**
     * Command line option specifying the digest algorithm to be
     * used in the various signature algorithms in a convenient
     * short form.
     */
    private CmdLineParser.Option digestArg;
    
    /**
     * Digest algorithm URI directly specified on the command line.
     */
    private String digestAlgorithm;
    
    /**
     * Command line option specifying the digest algorithm URI.
     */
    private CmdLineParser.Option digestAlgorithmArg;
    
    /**
     * Signature algorithm URI directly specified on the command line.
     */
    private String signatureAlgorithm;
    
    /**
     * Command line option specifying the signature algorithm URI.
     */
    private CmdLineParser.Option signatureAlgorithmArg;

    private List<String> kiKeyNames;

    private CmdLineParser.Option KI_KEY_NAME_ARG;

    private List<String> kiCrls;

    private CmdLineParser.Option KI_CRL_ARG;

    // Output
    private String outFile;

    private CmdLineParser.Option OUT_FILE_ARG;

    private boolean base64EncodeOutput;

    private CmdLineParser.Option BASE64_OUT_ARG;

    private boolean deflateOutput;

    private CmdLineParser.Option DEFLATE_OUT_ARG;

    private boolean gzipOutput;

    private CmdLineParser.Option GZIP_OUT_ARG;

    // Key/Cert Data
    private String cert;

    private CmdLineParser.Option CERT_ARG;

    private String key;

    private CmdLineParser.Option KEY_ARG;

    private String keyPassword;

    private CmdLineParser.Option KEY_PASSWORD_ARG;

    private String keystore;

    private CmdLineParser.Option KEYSTORE_ARG;

    private String keystorePassword;

    private CmdLineParser.Option KEYSTORE_PASSWORD_ARG;

    private String keystoreType;

    private CmdLineParser.Option KEYSTORE_TYPE_ARG;

    private String keystoreProvider;

    private CmdLineParser.Option KEYSTORE_PROVIDER_ARG;

    private String pkcs11Config;

    private CmdLineParser.Option PKCS11_CONFIG_ARG;

    // Blacklisting
    
    /**
     * Local blacklist of signature and digest algorithms.
     */
    private final Blacklist blacklist = new Blacklist();
    
    /**
     * Option requesting that the signature verification
     * blacklists be cleared.
     */
    private boolean clearBlacklist;
    
    /**
     * Command line option requesting that the signature
     * verification blacklists be cleared.
     */
    private CmdLineParser.Option clearBlacklistArg;
    
    /**
     * Option requesting that the signature verification
     * blacklists be listed.
     */
    private boolean listBlacklist;
    
    /**
     * Command line option requesting that the signature
     * verification blacklists be listed.
     */
    private CmdLineParser.Option listBlacklistArg;
    
    /**
     * Collection of digest choices to be blacklisted.
     */
    private final Collection<DigestChoice> blacklistDigests = new ArrayList<DigestChoice>();
    
    /**
     * Command line option indicating digests to be
     * blacklisted.
     */
    private CmdLineParser.Option blacklistDigestArg;
    
    // Logging
    private boolean verbose;

    private CmdLineParser.Option VERBOSE_ARG;

    private boolean quiet;

    private CmdLineParser.Option QUIET_ARG;

    private String logConfig;

    private CmdLineParser.Option LOG_CONFIG_ARG;

    // Help
    private boolean help;

    private CmdLineParser.Option HELP_ARG;

    private CmdLineParser cliParser;

    public XmlSecToolCommandLineArguments(String[] args) {
        cliParser = new CmdLineParser();

        SIGN_ARG = cliParser.addBooleanOption("sign");
        V_SCHEMA_ARG = cliParser.addBooleanOption("validateSchema");
        V_SIG_ARG = cliParser.addBooleanOption("verifySignature");
        IN_FILE_ARG = cliParser.addStringOption("inFile");
        IN_URL_ARG = cliParser.addStringOption("inUrl");
        BASE64_IN_ARG = cliParser.addBooleanOption("base64DecodeInput");
        INFLATE_IN_ARG = cliParser.addBooleanOption("inflateInput");
        GUNZIP_IN_ARG = cliParser.addBooleanOption("gunzipInput");
        HTTP_PROXY_ARG = cliParser.addStringOption("httpProxy");
        HTTP_PROXY_PORT_ARG = cliParser.addIntegerOption("httpProxyPort");
        HTTP_PROXY_USERNAME_ARG = cliParser.addStringOption("httpProxyUsername");
        HTTP_PROXY_PASSWORD_ARG = cliParser.addStringOption("httpProxyPassword");
        SCHEMA_DIR_ARG = cliParser.addStringOption("schemaDirectory");
        SCHEMA_XSD_LANG_ARG = cliParser.addBooleanOption("xsd");
        SCHEMA_RNG_LANG_ARG = cliParser.addBooleanOption("relaxng");
        SIG_REQUIRED_ARG = cliParser.addBooleanOption("signatureRequired");
        SIG_REF_ID_ATT_ARG = cliParser.addStringOption("referenceIdAttributeName");
        SIG_POS_ARG = cliParser.addStringOption("signaturePosition");
        SIG_INC_PREFIX_ARG = cliParser.addStringOption("inclusiveNamespacePrefix");
        digestArg = cliParser.addStringOption("digest");
        digestAlgorithmArg = cliParser.addStringOption("digestAlgorithm");
        signatureAlgorithmArg = cliParser.addStringOption("signatureAlgorithm");
        KI_KEY_NAME_ARG = cliParser.addStringOption("keyInfoKeyName");
        KI_CRL_ARG = cliParser.addStringOption("keyInfoCRL");
        OUT_FILE_ARG = cliParser.addStringOption("outFile");
        BASE64_OUT_ARG = cliParser.addBooleanOption("base64EncodeOutput");
        DEFLATE_OUT_ARG = cliParser.addBooleanOption("deflateOutput");
        GZIP_OUT_ARG = cliParser.addBooleanOption("gzipOutput");
        CERT_ARG = cliParser.addStringOption("certificate");
        KEY_ARG = cliParser.addStringOption("key");
        KEY_PASSWORD_ARG = cliParser.addStringOption("keyPassword");
        KEYSTORE_ARG = cliParser.addStringOption("keystore");
        KEYSTORE_PASSWORD_ARG = cliParser.addStringOption("keystorePassword");
        KEYSTORE_TYPE_ARG = cliParser.addStringOption("keystoreType");
        KEYSTORE_PROVIDER_ARG = cliParser.addStringOption("keystoreProvider");
        PKCS11_CONFIG_ARG = cliParser.addStringOption("pkcs11Config");
        clearBlacklistArg = cliParser.addBooleanOption("clearBlacklist");
        listBlacklistArg = cliParser.addBooleanOption("listBlacklist");
        blacklistDigestArg = cliParser.addStringOption("blacklistDigest");
        VERBOSE_ARG = cliParser.addBooleanOption("verbose");
        QUIET_ARG = cliParser.addBooleanOption("quiet");
        LOG_CONFIG_ARG = cliParser.addStringOption("logConfig");
        HELP_ARG = cliParser.addBooleanOption("help");
    }

    public void parseCommandLineArguments(String[] args) {
        try {
            cliParser.parse(args);

            sign = (Boolean) cliParser.getOptionValue(SIGN_ARG, Boolean.FALSE);
            schemaValidate = (Boolean) cliParser.getOptionValue(V_SCHEMA_ARG, Boolean.FALSE);
            signatureVerify = (Boolean) cliParser.getOptionValue(V_SIG_ARG, Boolean.FALSE);
            inFile = (String) cliParser.getOptionValue(IN_FILE_ARG);
            inUrl = (String) cliParser.getOptionValue(IN_URL_ARG);
            base64DecodeInput = ((Boolean) cliParser.getOptionValue(BASE64_IN_ARG, Boolean.FALSE)).booleanValue();
            inflateInput = ((Boolean) cliParser.getOptionValue(INFLATE_IN_ARG, Boolean.FALSE)).booleanValue();
            gunzipInput = ((Boolean) cliParser.getOptionValue(GUNZIP_IN_ARG, Boolean.FALSE)).booleanValue();
            schemaDirectory = (String) cliParser.getOptionValue(SCHEMA_DIR_ARG);
            xsdSchema = (Boolean) cliParser.getOptionValue(SCHEMA_XSD_LANG_ARG, Boolean.FALSE);
            rngSchema = (Boolean) cliParser.getOptionValue(SCHEMA_RNG_LANG_ARG, Boolean.FALSE);
            if (!xsdSchema && !rngSchema) {
                xsdSchema = true;
            }
            signatureRequired = (Boolean) cliParser.getOptionValue(SIG_REQUIRED_ARG, Boolean.TRUE);
            refIdAttributeName = (String) cliParser.getOptionValue(SIG_REF_ID_ATT_ARG);
            signaturePosition = (String) cliParser.getOptionValue(SIG_POS_ARG);
            inclusiveNamespacePrefixs = (List<String>) cliParser.getOptionValues(SIG_INC_PREFIX_ARG);
            digestName = (String) cliParser.getOptionValue(digestArg);
            digestAlgorithm = (String) cliParser.getOptionValue(digestAlgorithmArg);
            signatureAlgorithm = (String) cliParser.getOptionValue(signatureAlgorithmArg);
            kiKeyNames = (List<String>) cliParser.getOptionValues(KI_KEY_NAME_ARG);
            kiCrls = (List<String>) cliParser.getOptionValues(KI_CRL_ARG);
            outFile = (String) cliParser.getOptionValue(OUT_FILE_ARG);
            base64EncodeOutput = (Boolean) cliParser.getOptionValue(BASE64_OUT_ARG, Boolean.FALSE);
            deflateOutput = ((Boolean) cliParser.getOptionValue(DEFLATE_OUT_ARG, Boolean.FALSE)).booleanValue();
            gzipOutput = ((Boolean) cliParser.getOptionValue(GZIP_OUT_ARG, Boolean.FALSE)).booleanValue();
            httpProxy = (String) cliParser.getOptionValue(HTTP_PROXY_ARG);
            httpProxyPort = (Integer) cliParser.getOptionValue(HTTP_PROXY_PORT_ARG, 80);
            httpProxyUsername = (String) cliParser.getOptionValue(HTTP_PROXY_USERNAME_ARG);
            httpProxyPassword = (String) cliParser.getOptionValue(HTTP_PROXY_PASSWORD_ARG);
            cert = (String) cliParser.getOptionValue(CERT_ARG);
            key = (String) cliParser.getOptionValue(KEY_ARG);
            keyPassword = (String) cliParser.getOptionValue(KEY_PASSWORD_ARG);
            keystore = (String) cliParser.getOptionValue(KEYSTORE_ARG);
            keystorePassword = (String) cliParser.getOptionValue(KEYSTORE_PASSWORD_ARG);
            keystoreType = (String) cliParser.getOptionValue(KEYSTORE_TYPE_ARG);
            keystoreProvider = (String) cliParser.getOptionValue(KEYSTORE_PROVIDER_ARG);
            pkcs11Config = (String) cliParser.getOptionValue(PKCS11_CONFIG_ARG);
            clearBlacklist = ((Boolean) cliParser.getOptionValue(clearBlacklistArg, Boolean.FALSE)).booleanValue();
            listBlacklist = ((Boolean) cliParser.getOptionValue(listBlacklistArg, Boolean.FALSE)).booleanValue();
            Vector blacklistedDigestVector = cliParser.getOptionValues(blacklistDigestArg);
            for (Object digestNameObject: blacklistedDigestVector) {
                String name = (String)digestNameObject;
                DigestChoice dig = DigestChoice.find(name);
                if (dig == null) {
                    errorAndExit("digest choice \"" + name + "\" was not recognised");
                }
                blacklistDigests.add(dig);
            }
            verbose = (Boolean) cliParser.getOptionValue(VERBOSE_ARG, Boolean.FALSE);
            quiet = (Boolean) cliParser.getOptionValue(QUIET_ARG, Boolean.FALSE);
            logConfig = (String) cliParser.getOptionValue(LOG_CONFIG_ARG);
            help = (Boolean) cliParser.getOptionValue(HELP_ARG, false);
            validateCommandLineArguments();
        } catch (OptionException e) {
            errorAndExit(e.getMessage());
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

    public boolean isSignatureRequired() {
        return signatureRequired;
    }

    public String getReferenceIdAttributeName() {
        return refIdAttributeName;
    }

    public String getSignaturePosition() {
        return signaturePosition;
    }

    public List<String> getInclusiveNamespacePrefixs() {
        return inclusiveNamespacePrefixs;
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
     * Indicates whether the option to clear the blacklist has been selected.
     * 
     * @return <code>true</code> if option selected
     */
    public boolean doClearBlacklist() {
        return clearBlacklist;
    }
    
    /**
     * Indicates whether the option to list the blacklist has been selected.
     * 
     * @return <code>true</code> if option selected
     */
    public boolean doListBlacklist() {
        return listBlacklist;
    }
    
    /**
     * Returns the digests designated to be blacklisted on the command line.
     * 
     * @return collection of {@link DigestChoice}s to be blacklisted
     */
    public Collection<DigestChoice> getBlacklistDigests() {
        return blacklistDigests;
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
            errorAndExit((new StringBuilder("Options ")).append(INFLATE_IN_ARG.longForm()).append(" and ")
                    .append(GUNZIP_IN_ARG.longForm()).append(" are mutually exclusive").toString());
        }

        if (doSchemaValidation()) {
            if (getSchemaDirectory() == null) {
                errorAndExit(SCHEMA_DIR_ARG.longForm() + " option is required");
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
            digest = DigestChoice.SHA1;
        }
        
        if (doSign()) {
            if (getKey() == null) {
                errorAndExit(KEY_ARG.longForm() + " option is required");
            }

            if ((getKeystore() != null || getPkcs11Config() != null) && getKeyPassword() == null) {
                errorAndExit(KEY_PASSWORD_ARG.longForm() + " option is required");
            }

            if (getOutputFile() == null) {
                errorAndExit("No output location specified");
            }
        }

        if (isDeflateOutput() && isGzipOutput()) {
            errorAndExit((new StringBuilder("Options ")).append(DEFLATE_OUT_ARG.longForm()).append(" and ")
                    .append(GZIP_OUT_ARG.longForm()).append(" are mutually exclusive").toString());
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
    public void printHelp(PrintStream out) {
        out.println("XML Security Tool");
        out.println("Provides a command line interface for schema validating, signing, and signature validating an XML file.");
        out.println();
        out.println("==== Command Line Options ====");
        out.println();
        out.println(String.format("  --%-20s %s", HELP_ARG.longForm(), "Prints this help information"));
        out.println();
        out.println("Action Options - '" + SIGN_ARG.longForm() + "' and '" + V_SIG_ARG.longForm()
                + "' are mutually exclusive.  At least one option is required.");
        out.println(String.format("  --%-20s %s", V_SCHEMA_ARG.longForm(), "Schema validate the document."));
        out.println(String.format("  --%-20s %s", SIGN_ARG.longForm(), "Sign the XML document."));
        out.println(String.format("  --%-20s %s", V_SIG_ARG.longForm(), "Check the signature on a signed document."));

        out.println();
        out.println("Data Input Options - '" + IN_FILE_ARG.longForm() + "' and '" + IN_URL_ARG.longForm()
                + "' are mutually exclusive, one is required.");
        out.println(String.format("  --%-20s %s", IN_FILE_ARG.longForm(),
                "Specifies the file from which the XML document will be read."));
        out.println(String.format("  --%-20s %s", IN_URL_ARG.longForm(),
                "Specifies the URL from which the XML document will be read. HTTPS certificates are not validated."));
        out.println(String.format("  --%-20s %s", BASE64_IN_ARG.longForm(),
                "Base64 decodes input.  Useful when reading in data produced with the " + BASE64_OUT_ARG.longForm()
                        + " option"));
        out.println(String.format("  --%-20s %s", INFLATE_IN_ARG.longForm(),
                "Inflates a file created with the \"deflate\" compression algorithm.  This property is ignored if "
                        + IN_URL_ARG.longForm()
                        + " is used.  Instead the returned headers determine if content was deflated"));
        out.println(String.format("  --%-20s %s", GUNZIP_IN_ARG.longForm(),
                "Inflates a file created with the \"gzip\" compression algorithm.  This property is ignored if "
                        + IN_URL_ARG.longForm()
                        + " is used.  Instead the returned headers determine if content was gzip'ed"));

        out.println(String.format("  --%-20s %s", HTTP_PROXY_ARG.longForm(),
                "HTTP proxy address used when fetching URL-based input files."));
        out.println(String.format("  --%-20s %s", HTTP_PROXY_PORT_ARG.longForm(), "HTTP proxy port. (default: 80)"));
        out.println(String.format("  --%-20s %s", HTTP_PROXY_USERNAME_ARG.longForm(),
                "Username used to authenticate to the HTTP proxy."));
        out.println(String.format("  --%-20s %s", HTTP_PROXY_PASSWORD_ARG.longForm(),
                "Password used to authenticate to the HTTP proxy."));

        out.println();
        out.println("Schema Validation Option - '" + SCHEMA_XSD_LANG_ARG.longForm() + "' (default) and '"
                + SCHEMA_RNG_LANG_ARG.longForm() + "' are mutually exclusive option.");
        out.println(String.format("  --%-20s %s", SCHEMA_DIR_ARG.longForm(),
                "Specifies a schema file or directory of schema files.  Subdirectories are also read."));
        out.println(String.format("  --%-20s %s", SCHEMA_XSD_LANG_ARG.longForm(),
                "Indicates schema files are W3 XML Schema 1.0 files (.xsd)."));
        out.println(String.format("  --%-20s %s", SCHEMA_RNG_LANG_ARG.longForm(),
                "Indicates schema files are OASIS RELAX NG files (.rng)."));

        out.println();
        out.println("Signature Creation Options");
        out.println(String.format(
                "  --%-20s %s",
                SIG_REF_ID_ATT_ARG.longForm(),
                "Specifies the name of the attribute on the document element "
                        + "whose value is used as the URI reference of the signature.  If omitted, "
                        + "a null reference URI is used."));
        out.println(String.format("  --%-20s %s", SIG_POS_ARG.longForm(),
                "Specifies, by 1-based index, which element to place the signature BEFORE.  "
                        + "'FIRST' may be used to indicate that the signature goes BEFORE the first element. "
                        + "'LAST' may be used to indicate that the signature goes AFTER the last element."
                        + " (default value: FIRST)"));
        // out.println(String.format("  --%-20s %s", SIG_INC_PREFIX_ARG.longForm(),
        // "Specifies an inclusive namespace by prefix.  Option may be used more than once."));
        out.println(String.format("  --%-20s %s", digestArg.longForm(),
                "Specifies the name of the digest algorithm to use: SHA-1 (default), SHA-256, SHA-384, SHA-512."
                        + "  For RSA and EC credentials, dictates both the digest and signature algorithms."));
        out.println(String.format("  --%-20s %s", digestAlgorithmArg.longForm(),
                "Specifies the URI of the digest algorithm to use; overrides --"
                        + digestArg.longForm() + "."));
        out.println(String.format("  --%-20s %s", signatureAlgorithmArg.longForm(),
                "Specifies the URI of the signature algorithm to use; overrides --"
                        + digestArg.longForm() + "."));
        out.println(String.format("  --%-20s %s", KI_KEY_NAME_ARG.longForm(),
                "Specifies a key name to be included in the key info.  Option may be used more than once."));
        out.println(String.format("  --%-20s %s", KI_CRL_ARG.longForm(),
                "Specifies a file path for a CRL to be included in the key info.  Option may be used more than once."));

        out.println();
        out.println("Signature Verification Options");
        out.println(String.format("  --%-20s %s", SIG_REQUIRED_ARG.longForm(),
                "Treat unsigned documents as an error.  (default: true)"));

        out.println();
        out.println("PEM/DER Encoded Certificate/Key Options - "
                + "these options are mutually exclusive with the Keystore and PKCS#11 options. "
                + "The '" + CERT_ARG.longForm() + "' option is required for signature verification. "
                + "The '" + CERT_ARG.longForm() + "' and '" + KEY_ARG.longForm()
                    + "' options are required for signing.");
        out.println(String.format("  --%-20s %s", CERT_ARG.longForm(),
                "Specifies the file from which the signing, or validation, certificate is read."));
        out.println(String.format("  --%-20s %s", KEY_ARG.longForm(),
                "Specifies the file from which the signing key is read."));
        out.println(String.format("  --%-20s %s", KEY_PASSWORD_ARG.longForm(),
                "Specifies the password for the signing key."));

        out.println();
        out.println("Keystore Certificate/Key Options - these options are mutually exclusive with the PEM/DER and PKCS#11 options."
                + " Options '"
                + KEYSTORE_ARG.longForm()
                + "', '"
                + KEY_ARG.longForm()
                + "', and '"
                + KEY_PASSWORD_ARG.longForm() + "' are required.");
        out.println(String.format("  --%-20s %s", KEYSTORE_ARG.longForm(), "Specifies the keystore file."));
        out.println(String.format("  --%-20s %s", KEYSTORE_PASSWORD_ARG.longForm(),
                "Specifies the password for the keystore. If not provided then the key password is used."));
        out.println(String.format("  --%-20s %s", KEYSTORE_TYPE_ARG.longForm(), "Specifies the type of the keystore."));
        out.println(String.format("  --%-20s %s", KEYSTORE_PROVIDER_ARG.longForm(),
                "Specifies the keystore provider class to use instead of the default one for the JVM."));
        out.println(String.format("  --%-20s %s", KEY_ARG.longForm(),
                "Specifies the key alias for the signing key is read."));
        out.println(String.format("  --%-20s %s", KEY_PASSWORD_ARG.longForm(),
                "Specifies the password for the signing key. Keystore password used if none is given."));

        out.println();
        out.println("PKCS#11 Device Certificate/Key Options - these options are mutually exclusive with the PEM/DER and Keystore options."
                + " Options '"
                + PKCS11_CONFIG_ARG.longForm()
                + "' and '"
                + KEY_ARG.longForm()
                + "' are required. Option '"
                + KEY_PASSWORD_ARG.longForm()
                + "' required when signing and, with some PKCS#11 devices, during signature verification.");
        out.println(String.format("  --%-20s %s", PKCS11_CONFIG_ARG.longForm(), "The PKCS#11 token configuration file."));
        out.println(String.format("  --%-20s %s", KEY_ARG.longForm(),
                "Specifies the key alias for the signing key is read."));
        out.println(String.format("  --%-20s %s", KEY_PASSWORD_ARG.longForm(), "Specifies the pin for the signing key."));
        out.println(String.format(
                "  --%-20s %s",
                KEYSTORE_PROVIDER_ARG.longForm(),
                "The fully qualified class name of the PKCS#11 keystore provider implementation. (e.g., sun.security.pkcs11.SunPKCS11)"));

        out.println();
        out.println("Signature verification algorithm blacklist options:");
        out.println(String.format("  --%-20s %s", clearBlacklistArg.longForm(),
                "Clear the algorithm blacklist."));
        out.println(String.format("  --%-20s %s", blacklistDigestArg.longForm(),
                "Blacklist a digest by name (e.g., \"SHA-1\").  Can be used any number of times."));
        out.println(String.format("  --%-20s %s", listBlacklistArg.longForm(),
                "List the contents of the algorithm blacklist."));
        
        out.println();
        out.println("Data Output Options - Option '" + OUT_FILE_ARG.longForm() + "' is required.");
        out.println(String.format("  --%-20s %s", OUT_FILE_ARG.longForm(),
                "Specifies the file to which the signed XML document will be written."));
        out.println(String.format("  --%-20s %s", BASE64_OUT_ARG.longForm(),
                "Base64 encode the output. Ensures signed content isn't corrupted."));
        out.println(String.format("  --%-20s %s", DEFLATE_OUT_ARG.longForm(), "Deflate compresses the output."));
        out.println(String.format("  --%-20s %s", GZIP_OUT_ARG.longForm(), "GZip compresses the output."));

        out.println();
        out.println("Logging Options - these options are mutually exclusive");
        out.println(String.format("  --%-20s %s", VERBOSE_ARG.longForm(), "Turn on verbose messages."));
        out.println(String.format("  --%-20s %s", QUIET_ARG.longForm(),
                "Do not write any messages to STDERR or STDOUT."));
        out.println(String.format("  --%-20s %s", LOG_CONFIG_ARG.longForm(),
                "Specifies a logback configuration file to use to configure logging."));
        out.println();
    }

    /**
     * Prints the error message to STDERR and then exits.
     * 
     * @param error the error message
     */
    private void errorAndExit(String error) {
        System.err.println(error);
        System.err.flush();
        System.out.println();
        printHelp(System.out);
        System.out.flush();
        System.exit(XmlSecTool.RC_INIT);
    }
}