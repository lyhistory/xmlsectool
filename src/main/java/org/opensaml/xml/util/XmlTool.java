/*
 * Copyright 2009 University Corporation for Advanced Internet Development, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.opensaml.xml.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.Validator;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.KeyName;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.Transforms;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.opensaml.ws.soap.client.http.TLSProtocolSocketFactory;
import org.opensaml.xml.schema.SchemaBuilder;
import org.opensaml.xml.schema.SchemaBuilder.SchemaLanguage;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509Util;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import edu.internet2.middleware.shibboleth.DelegateToApplicationX509TrustManager;

public final class XmlTool {

    /** Return code indicating command completed successfully, {@value} . */
    public static final int RC_OK = 0;

    /** Return code indicating an initialization error, {@value} . */
    public static final int RC_INIT = 1;

    /** Return code indicating an error reading files, {@value} . */
    public static final int RC_IO = 2;

    /** Return code indicating the input XML was not well formed, {@value} . */
    public static final int RC_MALFORMED_XML = 3;

    /** Return code indicating input XML was not valid, {@value} . */
    public static final int RC_INVALID_XML = 4;

    /** Return code indicating indicating an error validating the XML, {@value} . */
    public static final int RC_INVALID_XS = 5;

    /** Return code indicating an error reading the credentials, {@value} . */
    public static final int RC_INVALID_CRED = 6;

    /** Return code indicating indicating that signing or signature verification failed, {@value} . */
    public static final int RC_SIG = 7;

    /** Return code indicating an unknown error occurred, {@value} . */
    public static final int RC_UNKNOWN = -1;

    /** Class logger. */
    private static Logger log;

    /**
     * @param args
     */
    public static void main(String[] args) {
        XmlToolCommandLineArguments cli = new XmlToolCommandLineArguments(args);
        cli.parseCommandLineArguments(args);

        if (cli.doHelp()) {
            cli.printHelp(System.out);
            System.exit(RC_OK);
        }

        initLogging(cli);
        try {
            org.apache.xml.security.Init.init();
            DefaultBootstrap.bootstrap();
        } catch (Throwable e) {
            log.error("Unable to initialize OpenSAML and XML security libraries", e);
            System.exit(RC_INIT);
        }

        try {
            Document xml = parseXML(cli);

            if (cli.doSchemaValidation()) {
                schemaValidate(cli, xml);
            }

            if (cli.doSign()) {
                sign(cli, xml);
            }

            if (cli.doSignatureVerify()) {
                verifySignature(cli, xml);
            }

            if (cli.getOutputFile() != null) {
                writeDocument(cli, xml);
            }

        } catch (Throwable t) {
            log.error("Unknown error", t);
            System.exit(RC_UNKNOWN);
        }
    }

    /**
     * Parses the input XML from its source and converts it to a DOM document.
     * 
     * @param cli command line arguments
     * 
     * @return the parsed DOM document
     */
    protected static Document parseXML(XmlToolCommandLineArguments cli) {
        InputStream xmlInputStream;
        if (cli.getInputFile() != null) {
            xmlInputStream = getXmlInputStreamFromFile(cli);
        } else {
            xmlInputStream = getXmlInputStreamFromUrl(cli);
        }

        DocumentBuilder xmlParser = getParser(cli);

        try {
            log.debug("Parsing XML input stream");
            Document xmlDoc = xmlParser.parse(xmlInputStream);
            log.info("XML document parsed and is well-formed.");
            return xmlDoc;
        } catch (IOException e) {
            log.error("Error reading XML document from input source", e);
            System.exit(RC_IO);
        } catch (SAXException e) {
            log.error("XML document was not well formed", e);
            System.exit(RC_MALFORMED_XML);
        }

        return null;
    }

    /**
     * Creates an input stream that reads the input XML from a file.
     * 
     * @param cli command line arguments
     * 
     * @return XML input stream
     */
    protected static InputStream getXmlInputStreamFromFile(XmlToolCommandLineArguments cli) {
        try {
            log.info("Reading XML document from file '{}'", cli.getInputFile());
            File inputFile = new File(cli.getInputFile());
            if (!inputFile.exists()) {
                log.error("Input file '{}' does not exist", cli.getInputFile());
                System.exit(RC_IO);
            }
            if (inputFile.isDirectory()) {
                log.error("Input file '{}' is a directory", cli.getInputFile());
                System.exit(RC_IO);
            }
            if (!inputFile.canRead()) {
                log.error("Input file '{}' can not be read", cli.getInputFile());
                System.exit(RC_IO);
            }
            return new FileInputStream(cli.getInputFile());
        } catch (FileNotFoundException e) {
            log.error("Unable to read input file '{}'", cli.getInputFile(), e);
            System.exit(RC_IO);
        }

        return null;
    }

    /**
     * Creates an input stream that reads the input XML from an HTTP URL.
     * 
     * @param cli command line arguments
     * 
     * @return XML input stream
     */
    protected static InputStream getXmlInputStreamFromUrl(XmlToolCommandLineArguments cli) {
        log.info("Reading XML document from URL '{}'", cli.getInputUrl());
        HttpClientBuilder httpClientBuilder = new HttpClientBuilder();
        httpClientBuilder.setHttpsProtocolSocketFactory(new TLSProtocolSocketFactory(null,
                new DelegateToApplicationX509TrustManager()));

        if (cli.getHttpProxy() != null) {
            httpClientBuilder.setProxyHost(cli.getHttpProxy());
            httpClientBuilder.setProxyPort(cli.getHttpProxyPort());
            httpClientBuilder.setProxyUsername(cli.getHttpProxyUsername());
            httpClientBuilder.setProxyPassword(cli.getHttpProxyPassword());
        }

        GetMethod getMethod = new GetMethod(cli.getInputUrl());
        try {
            HttpClient httpClient = httpClientBuilder.buildClient();
            httpClient.executeMethod(getMethod);
            if (getMethod.getStatusCode() != HttpStatus.SC_OK) {
                log.error("Non-ok status code '{}' returned by '{}'", getMethod.getStatusCode(), cli.getInputUrl());
                System.exit(RC_IO);
            }
            return getMethod.getResponseBodyAsStream();
        } catch (IOException e) {
            log.error("Unable to read XML document from '{}'", cli.getInputUrl(), e);
            System.exit(RC_IO);
        }

        return null;
    }

    /**
     * Constructs a DOM parser used to parse the input XML.
     * 
     * @param cli command line arguments
     * 
     * @return the DOM parser
     */
    protected static DocumentBuilder getParser(XmlToolCommandLineArguments cli) {
        log.debug("Building DOM parser");
        DocumentBuilderFactory newFactory = DocumentBuilderFactory.newInstance();
        newFactory.setCoalescing(false);
        newFactory.setExpandEntityReferences(true);
        newFactory.setIgnoringComments(false);
        newFactory.setIgnoringElementContentWhitespace(false);
        newFactory.setNamespaceAware(true);
        newFactory.setValidating(false);
        newFactory.setXIncludeAware(false);

        try {
            return newFactory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            log.error("Unable to create XML parser", e);
            System.exit(RC_UNKNOWN);
        }

        return null;
    }

    /**
     * Validates the SAML document against the SAML 1.1 and 2.0 schema.
     * 
     * @param cli command line arguments
     * @param xml document to validate
     */
    protected static void schemaValidate(XmlToolCommandLineArguments cli, Document xml) {
        File schemaFileOrDirectory = new File(cli.getSchemaDirectory());
        try {
            Schema schema;
            if (cli.isXsdSchema()) {
                log.debug("Building W3 XML Schema from file/directory '{}'", schemaFileOrDirectory.getAbsolutePath());
                schema = SchemaBuilder.buildSchema(SchemaLanguage.XML, schemaFileOrDirectory);
            } else {
                log.debug("Building RELAX NG Schema from file/directory '{}'", schemaFileOrDirectory.getAbsolutePath());
                schema = SchemaBuilder.buildSchema(SchemaLanguage.RELAX, schemaFileOrDirectory);
            }

            Validator validator = schema.newValidator();
            log.debug("Schema validating XML document");
            validator.validate(new DOMSource(xml));
            log.info("XML document is schema valid");
        } catch (SAXException e) {
            log.error("Invalid XML schema files, unable to validate XML", e);
            System.exit(RC_INVALID_XS);
        } catch (Exception e) {
            log.error("XML is not schema valid", e);
            System.exit(RC_INVALID_XML);
        }
    }

    /**
     * Signs and outputs the signed SAML document.
     * 
     * @param cli command line arguments
     * @param xml document to be signed
     */
    protected static void sign(XmlToolCommandLineArguments cli, Document xml) {
        log.debug("Preparing to sign document");
        Element documentRoot = xml.getDocumentElement();
        Element signatureElement;

        signatureElement = getSignatureElement(xml);
        if (signatureElement != null) {
            log.error("XML document is already signed");
            System.exit(RC_SIG);
        }

        BasicX509Credential signingCredential = getCredential(cli);

        SecurityConfiguration securityConfig = Configuration.getGlobalSecurityConfiguration();
        String signatureAlgorithm = securityConfig.getSignatureAlgorithmURI(signingCredential);
        boolean hmac = SecurityHelper.isHMAC(signatureAlgorithm);
        Integer hmacOutputLength = securityConfig.getSignatureHMACOutputLength();
        String c14nAlgorithm = SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;

        try {
            XMLSignature signature = null;
            if (hmac) {
                signature = new XMLSignature(xml, "#", signatureAlgorithm, hmacOutputLength, c14nAlgorithm);
            } else {
                signature = new XMLSignature(xml, "#", signatureAlgorithm, c14nAlgorithm);
            }

            populateKeyInfo(xml, signature.getKeyInfo(), signingCredential);

            Transforms contentTransforms = new Transforms(xml);
            contentTransforms.addTransform(SignatureConstants.TRANSFORM_ENVELOPED_SIGNATURE);
            contentTransforms.addTransform(SignatureConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
            signature.addDocument(getSignatureReferenceUri(cli, documentRoot), contentTransforms,
                    SignatureConstants.ALGO_ID_DIGEST_SHA1);

            log.debug("Creating Signature DOM element");
            signatureElement = signature.getElement();

            addSignatureELement(cli, documentRoot, signatureElement);
            signature.sign(SecurityHelper.extractSigningKey(signingCredential));
            log.info("XML document successfully signed");
        } catch (XMLSecurityException e) {
            log.error("Unable to create XML document signature", e);
            System.exit(RC_SIG);
        }
    }

    /**
     * Populates an XML signature's KeyInfo with X.509 credential information.
     * 
     * @param doc XML document in which the elements will be rooted
     * @param keyInfo the KeyInfo to be populated
     * @param credential the credential
     */
    protected static void populateKeyInfo(Document doc, KeyInfo keyInfo, BasicX509Credential credential) {
        KeyName keyName;
        if (credential.getKeyNames() != null) {
            for (String name : credential.getKeyNames()) {
                keyName = new KeyName(doc, name);
                keyInfo.add(keyName);
            }
        }

        keyInfo.add(credential.getPublicKey());

        X509Data x509Data = new X509Data(doc);
        keyInfo.add(x509Data);

        try {
            for (X509Certificate cert : credential.getEntityCertificateChain()) {
                x509Data.addCertificate(cert);
            }

            if (credential.getCRLs() != null) {
                for (X509CRL crl : credential.getCRLs()) {
                    x509Data.addCRL(crl.getEncoded());
                }
            }
        } catch (XMLSecurityException e) {
            log.error("Unable to constructor signature KeyInfo", e);
            System.exit(RC_UNKNOWN);
        } catch (CRLException e) {

        }
    }

    /**
     * Gets the reference of the URI to use for the signature. If a reference attribute name is given, is present on the
     * document root element, and contains a value, that value is used. Otherwise an empty string is used.
     * 
     * @param cli command line arguments
     * @param rootElement document root element
     * 
     * @return the signature reference URI, never null
     */
    protected static String getSignatureReferenceUri(XmlToolCommandLineArguments cli, Element rootElement) {
        String reference = "";
        if (cli.getReferenceIdAttributeName() != null) {
            Attr referenceAttribute = (Attr) rootElement.getAttributes()
                    .getNamedItem(cli.getReferenceIdAttributeName());
            if (referenceAttribute != null) {
                reference = DatatypeHelper.safeTrim(referenceAttribute.getValue());
                if (reference.length() > 0) {
                    reference = "#" + reference;
                }
            }
        }

        return reference;
    }

    /**
     * Adds the signature element at the appropriate place in the document.
     * 
     * @param cli command line argument
     * @param root element to which the signature will be added as a child
     * @param signature signature to be added to the document's root element
     */
    protected static void addSignatureELement(XmlToolCommandLineArguments cli, Element root, Element signature) {
        if ("FIRST".equalsIgnoreCase(cli.getSignaturePosition()) || cli.getSignaturePosition() == null) {
            root.insertBefore(signature, root.getFirstChild());
            return;
        }

        if ("LAST".equalsIgnoreCase(cli.getSignaturePosition())) {
            root.appendChild(signature);
            return;
        }

        try {
            NodeList children = root.getChildNodes();
            int position = Integer.parseInt(cli.getSignaturePosition());
            boolean signatureInserted = false;
            if (children.getLength() > position) {
                int elementCount = 0;
                for (int i = 0; i < children.getLength(); i++) {
                    if (children.item(i).getNodeType() == Node.ELEMENT_NODE) {
                        elementCount++;
                        if (elementCount == position) {
                            root.insertBefore(signature, children.item(i));
                            signatureInserted = true;
                        }
                    }
                }
            }

            if (!signatureInserted) {
                root.appendChild(signature);
            }
        } catch (NumberFormatException e) {
            log.error("Invalid signature position: " + cli.getSignaturePosition());
            System.exit(RC_SIG);
        }
    }

    /**
     * Verifies that the signature on a document is valid.
     * 
     * @param cli command line argument
     * @param xmlDocument document whose signature will be validated
     */
    protected static void verifySignature(XmlToolCommandLineArguments cli, Document xmlDocument) {
        Element signatureElement = getSignatureElement(xmlDocument);
        if (signatureElement == null) {
            if (cli.isSignatureRequired()) {
                log.error("Signature required but XML document is not signed");
                System.exit(RC_SIG);
            } else {
                log.info("XML document is not signed, no verification performed");
                return;
            }
        }
        log.debug("XML document cotnained Signature element\n{}", XMLHelper.prettyPrintXML(signatureElement));

        log.debug("Creating XML security library XMLSignature object");
        XMLSignature signature = null;
        try {
            signature = new XMLSignature(signatureElement, "");
        } catch (XMLSecurityException e) {
            log.error("Unable to read XML signature", e);
            System.exit(RC_SIG);
        }

        Key verificationKey = SecurityHelper.extractVerificationKey(getCredential(cli));
        log.debug("Verifying XML signature with key\n{}", Base64.encodeBytes(verificationKey.getEncoded()));
        try {
            if (signature.checkSignatureValue(verificationKey)) {
                log.info("XML document signature verified.");
            } else {
                log.error("XML document signature verification failed");
                System.exit(RC_SIG);
            }
        } catch (XMLSignatureException e) {
            log.error("XML document signature verification failed with an error", e);
            System.exit(RC_SIG);
        }
    }

    /**
     * Gets the signature element from the document. The signature must be a child of the document root.
     * 
     * @param xmlDoc document from which to pull the signature
     * 
     * @return the signature element, or null
     */
    protected static Element getSignatureElement(Document xmlDoc) {
        List<Element> sigElements = XMLHelper.getChildElementsByTagNameNS(xmlDoc.getDocumentElement(),
                Signature.DEFAULT_ELEMENT_NAME.getNamespaceURI(), Signature.DEFAULT_ELEMENT_NAME.getLocalPart());

        if (sigElements.isEmpty()) {
            return null;
        }

        if (sigElements.size() > 1) {
            log.error("XML document contained more than on signature, unable to process");
            System.exit(RC_SIG);
        }

        return sigElements.get(0);
    }

    /**
     * Gets the credentials used for signing and signature verification.
     * 
     * @param cli command line arguments
     * 
     * @return the credentials
     */
    protected static BasicX509Credential getCredential(XmlToolCommandLineArguments cli) {
        BasicX509Credential credential = null;
        if (cli.getCertificate() != null) {
            try {
                credential = CredentialHelper.getFileBasedCredentials(cli.getKey(), cli.getKeyPassword(),
                        cli.getCertificate());
            } catch (KeyException e) {
                log.error("Unable to read key file " + cli.getKey(), e);
                System.exit(RC_IO);
            } catch (CertificateException e) {
                log.error("Unable to read certificate file " + cli.getKey(), e);
                System.exit(RC_IO);
            }
        } else if (cli.getPkcs11Config() != null) {
            try {
                credential = CredentialHelper.getPKCS11Credential(cli.getKeystore(), cli.getPkcs11Config(),
                        cli.getKey(), cli.getKeyPassword());
            } catch (IOException e) {
                log.error("Error accessing PKCS11 store", e);
                System.exit(RC_IO);
            } catch (GeneralSecurityException e) {
                log.error("Unable to recover key entry from PKCS11 store", e);
                System.exit(RC_IO);
            }
        } else {
            try {
                credential = CredentialHelper.getKeystoreCredential(cli.getKeystore(), cli.getKeystorePassword(),
                        cli.getKeystoreProvider(), cli.getKeystoreType(), cli.getKey(), cli.getKeyPassword());
            } catch (IOException e) {
                log.error("Unable to read keystore " + cli.getKeystore(), e);
                System.exit(RC_IO);
            } catch (GeneralSecurityException e) {
                log.error("Unable to recover key entry from keystore", e);
                System.exit(RC_IO);
            }
        }

        if (cli.getKeyInfoKeyNames() != null) {
            credential.getKeyNames().addAll(cli.getKeyInfoKeyNames());
        }
        credential.setCRLs(getCRLs(cli));

        return credential;
    }

    /**
     * Gets the CRLs referenced on the command line, if any.
     * 
     * @param cli command line arguments
     * 
     * @return collection of CRLs
     */
    protected static Collection<X509CRL> getCRLs(XmlToolCommandLineArguments cli) {
        List<String> keyInfoCrls = cli.getKeyInfoCrls();
        if (keyInfoCrls == null || keyInfoCrls.isEmpty()) {
            return Collections.emptyList();
        }

        ArrayList<X509CRL> crls = new ArrayList<X509CRL>();
        File crlFile = null;
        try {
            for (String crlFilePath : keyInfoCrls) {
                crlFile = new File(crlFilePath);
                if (!crlFile.exists() || !crlFile.canRead()) {
                    log.error("Unable to read CRL file " + crlFilePath);
                    System.exit(RC_INVALID_CRED);
                }
                crls.addAll(X509Util.decodeCRLs(crlFile));
            }
        } catch (CRLException e) {
            log.error("Unable to parse CRL file " + crlFile.getAbsolutePath(), e);
            System.exit(RC_INVALID_CRED);
        }

        return crls;
    }

    /**
     * Writes a DOM element to the output file.
     * 
     * @param cli command line arguments
     * @param xml the XML element to output
     */
    protected static void writeDocument(XmlToolCommandLineArguments cli, Node xml) {
        try {
            log.debug("Attempting to write output to file {}", cli.getOutputFile());
            File file = new File(cli.getOutputFile());
            if (file.exists() && file.isDirectory()) {
                log.error("Output file {} is a directory", cli.getOutputFile());
                System.exit(RC_IO);
            }
            file.createNewFile();
            if (!file.canWrite()) {
                log.error("Unable to write to output file {}", cli.getOutputFile());
                System.exit(RC_IO);
            }

            OutputStream output;
            if (cli.isBase64EncodedOutput()) {
                log.debug("Base64 encoding output to file");
                output = new Base64.OutputStream(new FileOutputStream(cli.getOutputFile()));
            } else {
                output = new FileOutputStream(cli.getOutputFile());
            }

            log.debug("Writting XML document to output file {}", cli.getOutputFile());
            XMLHelper.writeNode(xml, output);
            output.flush();
            output.close();
            log.info("XML document written to file {}", file.getAbsolutePath());
        } catch (IOException e) {
            log.error("Unable to write document to file {}", cli.getOutputFile(), e);
            System.exit(RC_IO);
        }
    }

    /**
     * Initialize the logging subsystem.
     * 
     * @param cli command line arguments
     */
    protected static void initLogging(XmlToolCommandLineArguments cli) {
        if (cli.getLoggingConfiguration() != null) {
            System.setProperty("logback.configurationFile", cli.getLoggingConfiguration());
        } else if (cli.doVerboseOutput()) {
            System.setProperty("logback.configurationFile", "logger-verbose.xml");
        } else if (cli.doQuietOutput()) {
            System.setProperty("logback.configurationFile", "logger-quiet.xml");
        } else {
            System.setProperty("logback.configurationFile", "logger-normal.xml");
        }

        log = LoggerFactory.getLogger(XmlTool.class);
    }
}