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
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.opensaml.security.crypto.KeySupport;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Support;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Helper class for reading in cryptographic credentials. */
public final class CredentialHelper {

    /** Class logger. */
    private static final Logger LOG = LoggerFactory.getLogger(CredentialHelper.class);
    
    /** Constructor. */
    private CredentialHelper() {}

    /**
     * Reads in the X509 credentials from the filesystem.
     * 
     * @param keyFile path to the private key file
     * @param keyPassword password for the private key, may be null
     * @param certificateFile path to the certificate file associated with the private key
     * 
     * @return the credentials
     * 
     * @throws CertificateException if there is a problem decoding the certificate
     * @throws KeyException if there is a problem decoding the private key
     */
    protected static BasicX509Credential getFileBasedCredentials(final String keyFile, final String keyPassword,
            final String certificateFile) throws KeyException, CertificateException {
        LOG.debug("Reading PEM/DER encoded credentials from the filesystem");

        // First, read the certificate
        LOG.debug("Reading certificates from file {}", certificateFile);
        final Collection<X509Certificate> certificates = X509Support.decodeCertificates(new File(certificateFile));
        final X509Certificate entityCertificate = certificates.iterator().next();
        final BasicX509Credential credential = new BasicX509Credential(entityCertificate);
        credential.setEntityCertificateChain(certificates);
        LOG.debug("Certificates successfully read");
        
        if (keyFile != null) {
            LOG.debug("Reading private key from file {}", keyFile);
            if (keyPassword == null) {
                credential.setPrivateKey(KeySupport.decodePrivateKey(new File(keyFile), null));
            } else {
                credential.setPrivateKey(KeySupport.decodePrivateKey(new File(keyFile), keyPassword.toCharArray()));
            }
            LOG.debug("Private key succesfully read");
        }

        return credential;
    }

    /**
     * Reads in the X509 credentials from a keystore.
     * 
     * @param keystorePath path the keystore file
     * @param keystorePassword keystore password
     * @param keystoreProvider keystore providr identifier
     * @param keystoreType keystore type
     * @param keyAlias private key alias
     * @param keyPassword private key password, may not be null
     * 
     * @return the credentials
     * 
     * @throws IOException if there was a problem reading the keystore
     * @throws GeneralSecurityException if there was a problem 
     */
    protected static BasicX509Credential getKeystoreCredential(final String keystorePath,
            final String keystorePassword, final String keystoreProvider, final String keystoreType,
            final String keyAlias, final String keyPassword) throws IOException,
            GeneralSecurityException {
        LOG.debug("Reading credentials from keystore");

        String storeType = keystoreType;
        if (storeType == null) {
            storeType = KeyStore.getDefaultType();
        }

        String storePassword = keystorePassword;
        if (storePassword == null) {
            storePassword = keyPassword;
        }

        final KeyStore keystore;
        if (keystoreProvider != null) {
            keystore = KeyStore.getInstance(storeType, keystoreProvider);
        } else {
            keystore = KeyStore.getInstance(storeType);
        }
        keystore.load(new FileInputStream(keystorePath), storePassword.toCharArray());

        return getCredentialFromKeystore(keystore, keyAlias, keyPassword);
    }

    /**
     * Reads in the X509 credentials from a PKCS11 source.
     * 
     * @param keystoreProvider keystore provider class
     * @param pkcs11Config PKCS11 configuration file used by the keystore provider
     * @param keyAlias private key keystore alias
     * @param keyPassword private key password, may not be null
     * 
     * @return the credentials
     * 
     * @throws IOException if it is not possible to read the keystore
     * @throws GeneralSecurityException if there is a problem loading the keystore, or loading the credential from it
     */
    @SuppressWarnings("unchecked")
    protected static BasicX509Credential getPKCS11Credential(final String keystoreProvider, final String pkcs11Config,
            final String keyAlias, final String keyPassword) throws IOException, GeneralSecurityException {
        LOG.debug("Install PKCS11 provider");

        KeyStore keystore = null;
        try {
            if (keystoreProvider != null) {
                LOG.debug("Creating PKCS11 keystore with provider {} and configuration file {}", keystoreProvider,
                        pkcs11Config);
                final Class<Provider> providerClass =
                        (Class<Provider>) CredentialHelper.class.getClassLoader().loadClass(keystoreProvider);
                final Constructor<Provider> providerConstructor = providerClass.getConstructor(String.class);
                final Provider pkcs11Provider = providerConstructor.newInstance(pkcs11Config);
                pkcs11Provider.load(new FileInputStream(pkcs11Config));
                Security.addProvider(pkcs11Provider);
                keystore = KeyStore.getInstance("PKCS11", pkcs11Provider);
            } else {
                LOG.debug("Creating PKCS11 keystore with system wide provider and configuration file");
                keystore = KeyStore.getInstance("PKCS11");
            }
        } catch (final ClassNotFoundException e) {
            LOG.error((new StringBuilder("Unable to load keystore provider class: ")).append(keystoreProvider)
                    .toString());
            throw new Terminator(ReturnCode.RC_INIT);
        } catch (final NoSuchMethodException e) {
            LOG.error("Keystore provider class does not provide a String-argument constructor");
            throw new Terminator(ReturnCode.RC_INIT);
        } catch (final Exception e) {
            LOG.error("Unable to read PKCS11 keystore", e);
            throw new IOException("Unable to read PKCS11 keystore", e);
        }

        LOG.debug("Initializing PKCS11 keystore");
        keystore.load(null, keyPassword.toCharArray());
        return getCredentialFromKeystore(keystore, keyAlias, keyPassword);
    }

    /**
     * Gets a credential from the given store.
     * 
     * @param keystore keystore from which to extract the credentials
     * @param keyAlias keystore key alias
     * @param keyPassword private key password
     * 
     * @return the extracted credential
     * 
     * @throws GeneralSecurityException if there is a problem getting the credential from the keystore,
     *      or if the credential is not of a known type 
     */
    protected static BasicX509Credential getCredentialFromKeystore(final KeyStore keystore, final String keyAlias,
            final String keyPassword) throws GeneralSecurityException {

        final KeyStore.Entry keyEntry = keystore.getEntry(keyAlias,
                new KeyStore.PasswordProtection(keyPassword.toCharArray()));
        if (keyEntry == null) {
            throw new KeyStoreException("entry '" + keyAlias + "' not found in keystore");
        }

        final BasicX509Credential credential;
        if (keyEntry instanceof PrivateKeyEntry) {
            final PrivateKeyEntry privKeyEntry = (PrivateKeyEntry) keyEntry;
            final List certChain = Arrays.asList(privKeyEntry.getCertificateChain());
            credential = new BasicX509Credential((X509Certificate) privKeyEntry.getCertificate());
            credential.setEntityCertificateChain(certChain);
            credential.setPrivateKey(privKeyEntry.getPrivateKey());
        } else if (keyEntry instanceof TrustedCertificateEntry) {
            final TrustedCertificateEntry certEntry = (TrustedCertificateEntry) keyEntry;
            credential = new BasicX509Credential((X509Certificate) certEntry.getTrustedCertificate());
        } else {
            // unknown kind of Keystore.Entry
            throw new CertificateException("unknown type of key entry in keystore");
        }

        LOG.debug("Successfully read credentials from keystore");
        return credential;
    }
}