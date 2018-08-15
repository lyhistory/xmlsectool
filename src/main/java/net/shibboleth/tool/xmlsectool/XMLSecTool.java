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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyException;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.InflaterInputStream;

import javax.annotation.Nonnull;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.codec.binary.Base64OutputStream;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.KeyName;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.signature.reference.ReferenceData;
import org.apache.xml.security.signature.reference.ReferenceSubTreeData;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.opensaml.core.config.InitializationException;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.security.x509.X509Support;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import net.shibboleth.utilities.java.support.xml.AttributeSupport;
import net.shibboleth.utilities.java.support.xml.ElementSupport;
import net.shibboleth.utilities.java.support.xml.SchemaBuilder.SchemaLanguage;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;

/**
 *  A command line tool for checking an XML file for well-formedness and validity as well as
 *  signing and checking signatures.
 */
public final class XMLSecTool {

    /** Class logger. */
    private static Logger log;

    /** Constructor. */
    private XMLSecTool() {}

    /**
     * Main command-line entry point.
     * 
     * @param args command-line arguments
     */
    public static void main(final String[] args) {
        try {
            final CommandLineArguments cli = new CommandLineArguments();
            cli.parseCommandLineArguments(args);
            initLogging(cli);

            try {
                InitializationSupport.initialize();
            } catch (final InitializationException e) {
                log.error("Unable to initialize OpenSAML library", e);
                throw new Terminator(ReturnCode.RC_INIT);
            }

            if (cli.doHelp()) {
                cli.printHelp(System.out);
                return;
            }
            
            if (cli.doListBlacklist()) {
                cli.getBlacklist().list(System.out);
                return;
            }

            final Document xml = parseXML(cli);

            if (cli.doSchemaValidation()) {
                schemaValidate(cli, xml);
            }

            if (cli.doSign()) {
                final X509Credential cred = getCredential(cli);
                sign(cli, cred, xml);
            }

            if (cli.doSignatureVerify()) {
                final X509Credential cred = getCredential(cli);
                verifySignature(cli, cred, xml);
            }

            if (cli.getOutputFile() != null) {
                writeDocument(cli, xml);
            }

        } catch (final Terminator t) {
            System.exit(t.getExitCode());
        } catch (final Throwable t) {
            log.error("Unknown error", t);
            System.exit(ReturnCode.RC_UNKNOWN.getCode());
        }
    }

    /**
     * Parses the input XML from its source and converts it to a DOM document.
     * 
     * @param cli command line arguments
     * 
     * @return the parsed DOM document
     */
    protected static Document parseXML(final CommandLineArguments cli) {
        final InputStream xmlInputStream;
        if (cli.getInputFile() != null) {
            xmlInputStream = getXmlInputStreamFromFile(cli);
        } else {
            xmlInputStream = getXmlInputStreamFromUrl(cli);
        }

        final DocumentBuilder xmlParser = getParser();
        try {
            log.debug("Parsing XML input stream");
            final Document xmlDoc = xmlParser.parse(xmlInputStream);
            log.info("XML document parsed and is well-formed.");
            return xmlDoc;
        } catch (final IOException e) {
            log.error("Error reading XML document from input source", e);
            throw new Terminator(ReturnCode.RC_IO);
        } catch (final SAXException e) {
            log.error("XML document was not well formed", e);
            throw new Terminator(ReturnCode.RC_MALFORMED_XML);
        }
    }

    /**
     * Creates an input stream that reads the input XML from a file.
     * 
     * @param cli command line arguments
     * 
     * @return XML input stream
     */
    protected static InputStream getXmlInputStreamFromFile(final CommandLineArguments cli) {
        try {
            log.info("Reading XML document from file '{}'", cli.getInputFile());
            final File inputFile = new File(cli.getInputFile());
            if (!inputFile.exists()) {
                log.error("Input file '{}' does not exist", cli.getInputFile());
                throw new Terminator(ReturnCode.RC_IO);
            }
            if (inputFile.isDirectory()) {
                log.error("Input file '{}' is a directory", cli.getInputFile());
                throw new Terminator(ReturnCode.RC_IO);
            }
            if (!inputFile.canRead()) {
                log.error("Input file '{}' can not be read", cli.getInputFile());
                throw new Terminator(ReturnCode.RC_IO);
            }

            InputStream ins = new FileInputStream(cli.getInputFile());
            if (cli.isBase64DecodeInput()) {
                log.debug("Passing input file through Base64 decoder.");
                ins = new Base64InputStream(ins);
            }
            if (cli.isInflateInput()) {
                log.debug("Passing input file data through Inflater decompression filter");
                ins = new InflaterInputStream(ins);
            }
            if (cli.isGunzipInput()) {
                log.debug("Passing input file data through GZip decompression filter");
                ins = new GZIPInputStream(ins);
            }

            return ins;
        } catch (final IOException e) {
            log.error("Unable to read input file '{}'", cli.getInputFile(), e);
            throw new Terminator(ReturnCode.RC_IO);
        }
    }

    /**
     * Creates an input stream that reads the input XML from an HTTP URL.
     * 
     * @param cli command line arguments
     * 
     * @return XML input stream
     */
    protected static InputStream getXmlInputStreamFromUrl(final CommandLineArguments cli) {
        log.info("Reading XML document from URL '{}'", cli.getInputUrl());
        final HttpClientBuilder httpClientBuilder = new HttpClientBuilder();
        httpClientBuilder.setConnectionDisregardTLSCertificate(true);
        if (cli.getHttpProxy() != null) {
            httpClientBuilder.setConnectionProxyHost(cli.getHttpProxy());
            httpClientBuilder.setConnectionProxyPort(cli.getHttpProxyPort());
            httpClientBuilder.setConnectionProxyUsername(cli.getHttpProxyUsername());
            httpClientBuilder.setConnectionProxyPassword(cli.getHttpProxyPassword());
        }
        final HttpGet getMethod = new HttpGet(cli.getInputUrl());
        getMethod.setHeader("Accept-Encoding", "gzip,deflate");
        try {
            final HttpClient httpClient = httpClientBuilder.buildClient();
            final HttpResponse response = httpClient.execute(getMethod);
            final int status = response.getStatusLine().getStatusCode();
            if (status != 200) {
                log.error("Non-ok status code '" + Integer.valueOf(status) + "' returned by '"
                        + cli.getInputUrl() + "'");
                throw new Terminator(ReturnCode.RC_IO);
            }
            InputStream ins = response.getEntity().getContent();
            final Header contentEncodingHeader = response.getFirstHeader("Content-Encoding");
            if (contentEncodingHeader != null) {
                final String contentEncoding = contentEncodingHeader.getValue();
                if ("deflate".equalsIgnoreCase(contentEncoding)) {
                    log.debug("Passing input file data through Inflater decompression filter");
                    ins = new InflaterInputStream(ins);
                }
                if ("gzip".equalsIgnoreCase(contentEncoding)) {
                    log.debug("Passing input file data through GZip decompression filter");
                    ins = new GZIPInputStream(ins);
                }
            }
            if (cli.isBase64DecodeInput()) {
                log.debug("Passing input file through Base64 decoder.");
                ins = new Base64InputStream(ins);
            }
            return ins;
        } catch (final IOException e) {
            log.error("Unable to read XML document from " + cli.getInputUrl(), e);
        } catch (final Exception e) {
            log.error("error building an HTTP client instance for " + cli.getInputUrl(), e);
        }
        throw new Terminator(ReturnCode.RC_IO);
    }

    /**
     * Constructs a DOM parser used to parse the input XML.
     * 
     * @return the DOM parser
     */
    protected static DocumentBuilder getParser() {
        log.debug("Building DOM parser");
        final DocumentBuilderFactory newFactory = DocumentBuilderFactory.newInstance();
        newFactory.setCoalescing(false);
        newFactory.setExpandEntityReferences(true);
        newFactory.setIgnoringComments(false);
        newFactory.setIgnoringElementContentWhitespace(false);
        newFactory.setNamespaceAware(true);
        newFactory.setValidating(false);
        newFactory.setXIncludeAware(false);

        try {
            return newFactory.newDocumentBuilder();
        } catch (final ParserConfigurationException e) {
            log.error("Unable to create XML parser", e);
            throw new Terminator(ReturnCode.RC_UNKNOWN);
        }
    }

    /**
     * Validates the document against the schema source indicated by the CLI arguments.
     * 
     * @param cli command line arguments
     * @param xml document to validate
     */
    protected static void schemaValidate(final CommandLineArguments cli, final Document xml) {
        final SchemaLanguage schemaLanguage = cli.isXsdSchema() ? SchemaLanguage.XML : SchemaLanguage.RELAX;
        final File schemaFileOrDirectory = new File(cli.getSchemaDirectory());
        final SchemaValidator validator;
        try {
            log.debug("Building W3 XML Schema from file/directory '{}'", schemaFileOrDirectory.getAbsolutePath());
            validator = new SchemaValidator(schemaLanguage, schemaFileOrDirectory);
        } catch (final SAXException e) {
            log.error("Invalid XML schema files, unable to validate XML", e);
            throw new Terminator(ReturnCode.RC_INVALID_XS);
        }
        
        try {
            log.debug("Schema validating XML document");
            validator.validate(new DOMSource(xml));
            log.info("XML document is schema valid");
        } catch (final SAXException e) {
            log.error("XML is not schema valid", e);
            throw new Terminator(ReturnCode.RC_INVALID_XML);
        } catch (final IOException e) {
            log.error("internal error: I/O exception while validating XML", e);
            throw new Terminator(ReturnCode.RC_INVALID_XML);
        }
    }

    /**
     * Signs a document.
     * 
     * @param cli command line arguments
     * @param signingCredential credential to use for signing
     * @param xml document to be signed
     */
    protected static void sign(@Nonnull final CommandLineArguments cli,
            @Nonnull final X509Credential signingCredential, @Nonnull final Document xml) {
        log.debug("Preparing to sign document");
        final Element documentRoot = xml.getDocumentElement();
        Element signatureElement = getSignatureElement(xml);
        if (signatureElement != null) {
            log.error("XML document is already signed");
            throw new Terminator(ReturnCode.RC_SIG);
        }

        /*
         * Determine the signature algorithm to use.
         */
        final String signatureAlgorithm = determineSignatureAlgorithm(cli, signingCredential);
        log.debug("signature algorithm {} selected from credential+digest", signatureAlgorithm);
        final SignatureSigningConfiguration securityConfig =
                SecurityConfigurationSupport.getGlobalSignatureSigningConfiguration();
        final boolean hmac = AlgorithmSupport.isHMAC(signatureAlgorithm);
        final Integer hmacOutputLength = securityConfig.getSignatureHMACOutputLength();
        
        /*
         * Determine the digest algorithm:
         * 
         *    * if the CLI digestAlgorithm option has been used, it takes precedence.
         *    * fall back to the shorthand digest choice.
         */
        String digestAlgorithm = cli.getDigestAlgorithm();
        if (digestAlgorithm == null) {
            digestAlgorithm = cli.getDigest().getDigestAlgorithm();
        }
        
        final String c14nAlgorithm = SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;

        try {
            final XMLSignature signature;
            if (hmac) {
                signature = new XMLSignature(xml, "#", signatureAlgorithm, hmacOutputLength, c14nAlgorithm);
            } else {
                signature = new XMLSignature(xml, "#", signatureAlgorithm, c14nAlgorithm);
            }

            populateKeyInfo(xml, signature.getKeyInfo(), signingCredential);

            final Transforms contentTransforms = new Transforms(xml);
            contentTransforms.addTransform(SignatureConstants.TRANSFORM_ENVELOPED_SIGNATURE);
            contentTransforms.addTransform(SignatureConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
            signature.addDocument(getSignatureReferenceUri(cli, documentRoot), contentTransforms,
                    digestAlgorithm);

            log.debug("Creating Signature DOM element");
            signatureElement = signature.getElement();

            addSignatureELement(cli, documentRoot, signatureElement);
            signature.sign(CredentialSupport.extractSigningKey(signingCredential));
            log.info("XML document successfully signed");
        } catch (final XMLSecurityException e) {
            log.error("Unable to create XML document signature", e);
            throw new Terminator(ReturnCode.RC_SIG);
        }
    }
    
    /**
     * Determine the signature algorithm to use.
     * 
     * <ul>
     * <li>if the CLI signatureAlgorithm has been used, it takes precedence.
     * <li>for RSA or ECDSA credentials, use an algorithm dependent on the digest algorithm chosen
     * <li>for DSA, always use DSA + SHA-1
     * </ul>
     * 
     * @param cli command line arguments
     * @param signingCredential credential to use for signing
     * @return algorithm URI as a {@link String}
     */
    protected static String determineSignatureAlgorithm(@Nonnull final CommandLineArguments cli,
            @Nonnull final X509Credential signingCredential) {
        
        if (cli.getSignatureAlgorithm() != null) {
            return cli.getSignatureAlgorithm();
        }

        final String credentialAlgorithm = signingCredential.getPublicKey().getAlgorithm();
        log.debug("credential public key algorithm is {}", credentialAlgorithm);
        switch (credentialAlgorithm) {
            case "RSA":
                return cli.getDigest().getRSAAlgorithm();
                
            case "EC":
                return cli.getDigest().getECDSAAlgorithm();
                
            case "DSA":
                return SignatureConstants.ALGO_ID_SIGNATURE_DSA_SHA1;
                
            default:
                log.error("unimplemented signing credential type: {}", credentialAlgorithm);
                throw new Terminator(ReturnCode.RC_SIG);
        }
    }

    /**
     * Populates an XML signature's KeyInfo with X.509 credential information.
     * 
     * @param doc XML document in which the elements will be rooted
     * @param keyInfo the KeyInfo to be populated
     * @param credential the credential
     */
    protected static void populateKeyInfo(final Document doc, final KeyInfo keyInfo,
            final X509Credential credential) {
        if (credential.getKeyNames() != null) {
            for (final String name : credential.getKeyNames()) {
                final KeyName keyName = new KeyName(doc, name);
                keyInfo.add(keyName);
            }
        }

        /*
         * XSTJ-51: Santuario doesn't handle adding KeyValue elements correctly
         * for anything other than the DSA and RSA cases. If you hand it anything else,
         * it generates an empty and therefore schema-invalid KeyValue.
         * 
         * Avoid this by only adding the public key to the KeyInfo if we know that
         * Santuario will do the right thing.
         */
        final PublicKey pk = credential.getPublicKey();
        if (pk instanceof RSAPublicKey || pk instanceof DSAPublicKey) {
            keyInfo.add(pk);
        } else if (pk instanceof ECPublicKey) {
            try {
                ASN1StreamParser parser = new ASN1StreamParser(pk.getEncoded());
                DERSequence seq = (DERSequence) parser.readObject().toASN1Primitive();
                DERSequence innerSeq = (DERSequence) seq.getObjectAt(0).toASN1Primitive();
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) innerSeq.getObjectAt(1).toASN1Primitive();
                DERBitString key = (DERBitString) seq.getObjectAt(1).toASN1Primitive();

                Element ECKeyValue = doc.createElement("ds:ECDSAKeyValue");
                ECKeyValue.setAttribute("xmlns", "http://www.w3.org/2001/04/xmldsig-more#");
                Element DomainParameters = doc.createElement("ds:DomainParameters");
                Element NamedCurve = doc.createElement("ds:NamedCurve");
                NamedCurve.setAttribute("URI", "urn:oid:"+oid.getId());
                DomainParameters.appendChild(NamedCurve);
                ECKeyValue.appendChild(DomainParameters);
                
                Element PublicKey = doc.createElement("ds:PublicKey");
                Element PublicKeyX = doc.createElement("ds:X");
                PublicKeyX.setAttribute("Value", ((ECPublicKey) pk).getW().getAffineX().toString());
                Element PublicKeyY = doc.createElement("ds:Y");
                PublicKeyY.setAttribute("Value", ((ECPublicKey) pk).getW().getAffineY().toString());
//                PublicKey.setTextContent(Base64.encodeBase64String(key.getBytes()));
                PublicKey.appendChild(PublicKeyX);
                PublicKey.appendChild(PublicKeyY);
                ECKeyValue.appendChild(PublicKey);
                keyInfo.addKeyValue(ECKeyValue);
            } catch (IOException e) {
                // 
            }
        } else {
            log.debug("not adding KeyValue for unsupported credential of type " + pk.getAlgorithm());
        }

        final X509Data x509Data = new X509Data(doc);
        keyInfo.add(x509Data);

        try {
            for (final X509Certificate cert : credential.getEntityCertificateChain()) {
                x509Data.addCertificate(cert);
            }

            if (credential.getCRLs() != null) {
                for (final X509CRL crl : credential.getCRLs()) {
                    x509Data.addCRL(crl.getEncoded());
                }
            }
        } catch (final XMLSecurityException e) {
            log.error("Unable to constructor signature KeyInfo", e);
            throw new Terminator(ReturnCode.RC_UNKNOWN);
        } catch (final CRLException e) {

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
    protected static String getSignatureReferenceUri(final CommandLineArguments cli,
            final Element rootElement) {
        String reference = "";
        if (cli.getReferenceIdAttributeName() != null) {
            final Attr referenceAttribute =
                    (Attr) rootElement.getAttributes().getNamedItem(cli.getReferenceIdAttributeName());
            if (referenceAttribute != null) {
                // Mark the reference attribute as a valid ID attribute
                rootElement.setIdAttributeNode(referenceAttribute, true);
                reference = StringSupport.trim(referenceAttribute.getValue());
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
    protected static void addSignatureELement(final CommandLineArguments cli,
            final Element root, final Element signature) {
        if ("FIRST".equalsIgnoreCase(cli.getSignaturePosition()) || cli.getSignaturePosition() == null) {
            root.insertBefore(signature, root.getFirstChild());
            return;
        }

        if ("LAST".equalsIgnoreCase(cli.getSignaturePosition())) {
            root.appendChild(signature);
            return;
        }

        try {
            final NodeList children = root.getChildNodes();
            final int position = Integer.parseInt(cli.getSignaturePosition());
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
        } catch (final NumberFormatException e) {
            log.error("Invalid signature position: " + cli.getSignaturePosition());
            throw new Terminator(ReturnCode.RC_SIG);
        }
    }

    /**
     * Reconcile the given reference with the document element, by making sure that
     * the appropriate attribute is marked as an ID attribute.
     * 
     * @param docElement document element whose appropriate attribute should be marked
     * @param reference reference which references the document element
     */
    protected static void markIdAttribute(final Element docElement, final Reference reference) {
        final String referenceUri = reference.getURI();
        
        /*
         * If the reference is empty, it implicitly references the document element
         * and no attribute is being referenced.
         */
        if (referenceUri == null || referenceUri.trim().isEmpty()) {
            log.debug("reference was empty; no ID marking required");
            return;
        }
        
        /*
         * If something has already identified an ID element, don't interfere
         */
        if (AttributeSupport.getIdAttribute(docElement) != null ) {
            log.debug("document element already has an ID attribute");
            return;
        }

        /*
         * The reference must be a fragment reference, from which we extract the
         * ID value.
         */
        if (!referenceUri.startsWith("#")) {
            log.error("Signature Reference URI was not a document fragment reference: " + referenceUri);
            throw new Terminator(ReturnCode.RC_SIG);
        }
        final String id = referenceUri.substring(1);

        /*
         * Now look for the attribute which holds the ID value, and mark it as the ID attribute.
         */
        final NamedNodeMap attributes = docElement.getAttributes();
        for (int i = 0; i < attributes.getLength(); i++) {
            final Attr attribute = (Attr) attributes.item(i);
            if (id.equals(attribute.getValue())) {
                log.debug("marking ID attribute {}", attribute.getName());
                docElement.setIdAttributeNode(attribute, true);
                return;
            }
        }
        
        /*
         * No attribute on the document element has the referenced ID value.
         * Signature validation will fail later, but let's give a warning here
         * as well to help people debug their signature code.
         */
        log.warn("did not find a document element attribute with value '{}'", id);
    }
    
    /**
     * Verifies that the signature on a document is valid.
     * 
     * @param cli command line argument
     * @param credential credential to use for validation
     * @param xmlDocument document whose signature will be validated
     */
    protected static void verifySignature(final CommandLineArguments cli,
            @Nonnull final X509Credential credential,
            final Document xmlDocument) {
        final Element signatureElement = getSignatureElement(xmlDocument);
        if (signatureElement == null) {
            log.error("Signature required but XML document is not signed");
            throw new Terminator(ReturnCode.RC_SIG);
        }
        log.debug("XML document contained Signature element\n{}", SerializeSupport.prettyPrintXML(signatureElement));

        log.debug("Creating XML security library XMLSignature object");
        final XMLSignature signature;
        try {
            signature = new XMLSignature(signatureElement, "");
        } catch (final XMLSecurityException e) {
            log.error("Unable to read XML signature", e);
            throw new Terminator(ReturnCode.RC_SIG);
        }

        if (signature.getObjectLength() != 0) {
            log.error("Signature contained an Object element, this is not allowed");
            throw new Terminator(ReturnCode.RC_SIG);
        }

        final Reference ref = extractReference(signature);
        markIdAttribute(xmlDocument.getDocumentElement(), ref);
        
        // check reference digest algorithm against blacklist
        try {
            final String alg = ref.getMessageDigestAlgorithm().getAlgorithmURI();
            log.debug("blacklist checking digest {}", alg);
            if (cli.getBlacklist().isBlacklistedDigest(alg)) {
                log.error("Digest algorithm {} is blacklisted", alg);
                throw new Terminator(ReturnCode.RC_SIG);
            }
        } catch (final XMLSignatureException e) {
            log.error("unable to retrieve signature digest algorithm", e);
            throw new Terminator(ReturnCode.RC_SIG);
        }
        
        // check signature algorithm against blacklist
        final String alg = signature.getSignedInfo().getSignatureMethodURI();
        log.debug("blacklist checking signature method {}", alg);
        if (cli.getBlacklist().isBlacklistedSignature(alg)) {
            log.error("Signature algorithm {} is blacklisted", alg);
            throw new Terminator(ReturnCode.RC_SIG);
        }        

        final Key verificationKey = CredentialSupport.extractVerificationKey(credential);
        log.debug("Verifying XML signature with key\n{}", Base64.encodeBase64String(verificationKey.getEncoded()));
        try {
            if (signature.checkSignatureValue(verificationKey)) {
                /*
                 * Now that the signature has been verified, we need to check that the
                 * XML signature layer resolved the reference to the correct element
                 * (always the document element) and that only appropriate transforms have
                 * been applied.
                 * 
                 * Note that we need to re-extract the reference from the signature at
                 * this point, we can't use one from before the signature validation.
                 */
                validateSignatureReference(xmlDocument, extractReference(signature));
                log.info("XML document signature verified.");
            } else {
                log.error("XML document signature verification failed");
                throw new Terminator(ReturnCode.RC_SIG);
            }
        } catch (final XMLSignatureException e) {
            log.error("XML document signature verification failed with an error", e);
            throw new Terminator(ReturnCode.RC_SIG);
        }
    }

    /**
     * Extract the reference within the provided XML signature while ensuring that there
     * is only one such reference.
     * 
     * @param signature signature to extract the reference from
     * @return the extracted reference
     */
    protected static Reference extractReference(final XMLSignature signature) {
        final int numReferences = signature.getSignedInfo().getLength();
        if (numReferences != 1) {
            log.error("Signature SignedInfo had invalid number of References: " + numReferences);
            throw new Terminator(ReturnCode.RC_SIG);
        }

        final Reference ref;
        try {
            ref = signature.getSignedInfo().item(0);
        } catch (final XMLSecurityException e) {
            log.error("Apache XML Security exception obtaining Reference", e);
            throw new Terminator(ReturnCode.RC_SIG);
        }
        if (ref == null) {
            log.error("Signature Reference was null");
            throw new Terminator(ReturnCode.RC_SIG);
        }
        return ref;
    }
    
    /**
     * Validates the reference within the XML signature by performing the following checks.
     * <ul>
     * <li>check that the XML signature layer resolves that reference to the same element as the DOM layer does</li>
     * <li>check that only enveloped and, optionally, exclusive canonicalization transforms are used</li>
     * </ul>
     * 
     * @param xmlDocument current XML document
     * @param ref reference to be verified
     */
    protected static void validateSignatureReference(final Document xmlDocument, final Reference ref) {
        validateSignatureReferenceUri(xmlDocument, ref);
        validateSignatureTransforms(ref);
    }

    /**
     * Validates that the element resolved by the signature validation layer is the same as the
     * element resolved by the DOM layer.
     * 
     * @param xmlDocument the signed document
     * @param reference the reference to be validated
     */
    protected static void validateSignatureReferenceUri(final Document xmlDocument, final Reference reference) {
        final ReferenceData refData = reference.getReferenceData();
        if (refData instanceof ReferenceSubTreeData) {
            final ReferenceSubTreeData subTree = (ReferenceSubTreeData) refData;
            final Node root = subTree.getRoot();
            Node resolvedSignedNode = root;
            if (root.getNodeType() == Node.DOCUMENT_NODE) {
                resolvedSignedNode = ((Document)root).getDocumentElement();
            }

            final Element expectedSignedNode = xmlDocument.getDocumentElement();

            if (!expectedSignedNode.isSameNode(resolvedSignedNode)) {
                log.error("Signature Reference URI \"" + reference.getURI()
                        + "\" was resolved to a node other than the document element");
                throw new Terminator(ReturnCode.RC_SIG);
            }
        } else {
            log.error("Signature Reference URI did not resolve to a subtree");
            throw new Terminator(ReturnCode.RC_SIG);
        }
    }

    /**
     * Validate the transforms included in the Signature Reference.
     * 
     * The Reference may contain at most 2 transforms. One of them must be the Enveloped signature transform. An
     * Exclusive Canonicalization transform (with or without comments) may also be present. No other transforms are
     * allowed.
     * 
     * @param reference the Signature reference containing the transforms to evaluate
     */
    protected static void validateSignatureTransforms(final Reference reference) {
        Transforms transforms = null;
        try {
            transforms = reference.getTransforms();
        } catch (final XMLSecurityException e) {
            log.error("Apache XML Security error obtaining Transforms instance", e);
            throw new Terminator(ReturnCode.RC_SIG);
        }

        if (transforms == null) {
            log.error("Error obtaining Transforms instance, null was returned");
            throw new Terminator(ReturnCode.RC_SIG);
        }

        final int numTransforms = transforms.getLength();
        if (numTransforms > 2) {
            log.error("Invalid number of Transforms was present: " + numTransforms);
            throw new Terminator(ReturnCode.RC_SIG);
        }

        boolean sawEnveloped = false;
        for (int i = 0; i < numTransforms; i++) {
            Transform transform = null;
            try {
                transform = transforms.item(i);
            } catch (final TransformationException e) {
                log.error("Error obtaining transform instance", e);
                throw new Terminator(ReturnCode.RC_SIG);
            }
            final String uri = transform.getURI();
            if (Transforms.TRANSFORM_ENVELOPED_SIGNATURE.equals(uri)) {
                log.debug("Saw Enveloped signature transform");
                sawEnveloped = true;
            } else if (Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS.equals(uri)
                    || Transforms.TRANSFORM_C14N_EXCL_WITH_COMMENTS.equals(uri)) {
                log.debug("Saw Exclusive C14N signature transform");
            } else {
                log.error("Saw invalid signature transform: " + uri);
                throw new Terminator(ReturnCode.RC_SIG);
            }
        }

        if (!sawEnveloped) {
            log.error("Signature was missing the required Enveloped signature transform");
            throw new Terminator(ReturnCode.RC_SIG);
        }
    }

    /**
     * Gets the signature element from the document. The signature must be a child of the document root.
     * 
     * @param xmlDoc document from which to pull the signature
     * 
     * @return the signature element, or null
     */
    protected static Element getSignatureElement(final Document xmlDoc) {
        final List<Element> sigElements =
                ElementSupport
                        .getChildElementsByTagNameNS(xmlDoc.getDocumentElement(),
                                Signature.DEFAULT_ELEMENT_NAME.getNamespaceURI(),
                                Signature.DEFAULT_ELEMENT_NAME.getLocalPart());

        if (sigElements.isEmpty()) {
            return null;
        }

        if (sigElements.size() > 1) {
            log.error("XML document contained more than one signature, unable to process");
            throw new Terminator(ReturnCode.RC_SIG);
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
    protected static X509Credential getCredential(final CommandLineArguments cli) {
        final BasicX509Credential credential;
        if (cli.getCertificate() != null) {
            try {
                credential =
                        CredentialHelper.getFileBasedCredentials(cli.getKey(), cli.getKeyPassword(),
                                cli.getCertificate());
            } catch (final KeyException e) {
                log.error("Unable to read key file " + cli.getKey(), e);
                throw new Terminator(ReturnCode.RC_IO);
            } catch (final CertificateException e) {
                log.error("Unable to read certificate file " + cli.getKey(), e);
                throw new Terminator(ReturnCode.RC_IO);
            }
        } else if (cli.getPkcs11Config() != null) {
            try {
                credential =
                        CredentialHelper.getPKCS11Credential(cli.getKeystoreProvider(),
                                cli.getPkcs11Config(), cli.getKey(), cli.getKeyPassword());
            } catch (final IOException e) {
                log.error("Error accessing PKCS11 store", e);
                throw new Terminator(ReturnCode.RC_IO);
            } catch (final GeneralSecurityException e) {
                log.error("Unable to recover key entry from PKCS11 store", e);
                throw new Terminator(ReturnCode.RC_IO);
            }
        } else {
            try {
                credential =
                        CredentialHelper.getKeystoreCredential(cli.getKeystore(), cli.getKeystorePassword(),
                                cli.getKeystoreProvider(), cli.getKeystoreType(), cli.getKey(), cli.getKeyPassword());
            } catch (final IOException e) {
                log.error("Unable to read keystore " + cli.getKeystore(), e);
                throw new Terminator(ReturnCode.RC_IO);
            } catch (final GeneralSecurityException e) {
                log.error("Unable to recover key entry from keystore", e);
                throw new Terminator(ReturnCode.RC_IO);
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
    protected static Collection<X509CRL> getCRLs(final CommandLineArguments cli) {
        final List<String> keyInfoCrls = cli.getKeyInfoCrls();
        if (keyInfoCrls == null || keyInfoCrls.isEmpty()) {
            return Collections.emptyList();
        }

        final ArrayList<X509CRL> crls = new ArrayList<X509CRL>();
        File crlFile = null;
        try {
            for (final String crlFilePath : keyInfoCrls) {
                crlFile = new File(crlFilePath);
                if (!crlFile.exists() || !crlFile.canRead()) {
                    log.error("Unable to read CRL file " + crlFilePath);
                    throw new Terminator(ReturnCode.RC_INVALID_CRED);
                }
                crls.addAll(X509Support.decodeCRLs(crlFile));
            }
        } catch (final CRLException e) {
            log.error("Unable to parse CRL file " + crlFile.getAbsolutePath(), e);
            throw new Terminator(ReturnCode.RC_INVALID_CRED);
        }

        return crls;
    }

    /**
     * Writes a DOM element to the output file.
     * 
     * @param cli command line arguments
     * @param xml the XML element to output
     */
    protected static void writeDocument(final CommandLineArguments cli, final Node xml) {
        try {
            log.debug("Attempting to write output to file {}", cli.getOutputFile());
            final File file = new File(cli.getOutputFile());
            if (file.exists() && file.isDirectory()) {
                log.error("Output file " + cli.getOutputFile() + " is a directory");
                throw new Terminator(ReturnCode.RC_IO);
            }
            file.createNewFile();
            if (!file.canWrite()) {
                log.error("Unable to write to output file " + cli.getOutputFile());
                throw new Terminator(ReturnCode.RC_IO);
            }

            OutputStream out = new FileOutputStream(cli.getOutputFile());
            if (cli.isBase64EncodedOutput()) {
                log.debug("Base64 encoding output to file");
                out = new Base64OutputStream(out);
            }
            if (cli.isDeflateOutput()) {
                log.debug("Deflate compressing output to file");
                out = new DeflaterOutputStream(out);
            }
            if (cli.isGzipOutput()) {
                log.debug("GZip compressing output to file");
                out = new GZIPOutputStream(out);
            }

            log.debug("Writing XML document to output file {}", cli.getOutputFile());
            try {
                final TransformerFactory tfac = TransformerFactory.newInstance();
                final Transformer serializer = tfac.newTransformer();
                serializer.setOutputProperty("encoding", "UTF-8");
                //serializer.setOutputProperty(OutputKeys.INDENT, "yes");
                serializer.transform(new DOMSource(xml), new StreamResult(out));
            } catch (final TransformerException e) {
                log.error("Unable to write out XML", e);
                throw new Terminator(ReturnCode.RC_IO);
            }
            out.flush();
            out.close();
            log.info("XML document written to file {}", file.getAbsolutePath());
        } catch (final IOException e) {
            log.error("Unable to write document to file " + cli.getOutputFile(), e);
            throw new Terminator(ReturnCode.RC_IO);
        }
    }

    /**
     * Initialize the logging subsystem.
     * 
     * @param cli command line arguments
     */
    protected static void initLogging(final CommandLineArguments cli) {
        if (cli.getLoggingConfiguration() != null) {
            System.setProperty("logback.configurationFile", cli.getLoggingConfiguration());
        } else if (cli.doVerboseOutput()) {
            System.setProperty("logback.configurationFile", "logger-verbose.xml");
        } else if (cli.doQuietOutput()) {
            System.setProperty("logback.configurationFile", "logger-quiet.xml");
        } else {
            System.setProperty("logback.configurationFile", "logger-normal.xml");
        }

        log = LoggerFactory.getLogger(XMLSecTool.class);
    }
}