
package org.opensaml.xml.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CredentialHelper {

    private static final Logger LOG = LoggerFactory.getLogger(CredentialHelper.class);

    /**
     * Reads in the X509 credentials from the filesystem.
     * 
     * @param keyFile path to the private key file
     * @param keyPassword password for the private key, may be null
     * @param certificateFile path to the certificate file associated with the private key
     * 
     * @return the credentials
     */
    protected static BasicX509Credential getFileBasedCredentials(String keyFile, String keyPassword,
            String certificateFile) throws KeyException, CertificateException {
        BasicX509Credential credential = new BasicX509Credential();
        LOG.debug("Reading PEM/DER encoded credentials from the filesystem");
        if (keyFile != null) {
            LOG.debug("Reading private key from file {}", keyFile);
            credential.setPrivateKey(SecurityHelper.decodePrivateKey(new File(keyFile), keyPassword.toCharArray()));
            LOG.debug("Private key succesfully read");
        }
        LOG.debug("Reading certificates from file {}", certificateFile);
        credential.setEntityCertificateChain(X509Util.decodeCertificate(new File(certificateFile)));
        credential.setEntityCertificate(credential.getEntityCertificateChain().iterator().next());
        credential.setPublicKey(credential.getEntityCertificate().getPublicKey());
        LOG.debug("Certificates successfully");

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
     * @param keyPassword private key password
     * 
     * @return the credentials
     */
    protected static BasicX509Credential getKeystoreCredential(String keystorePath, String keystorePassword,
            String keystoreProvider, String keystoreType, String keyAlias, String keyPassword) throws IOException,
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

        KeyStore keystore;
        if (keystoreProvider != null) {
            keystore = KeyStore.getInstance(storeType, keystoreProvider);
        } else {
            keystore = KeyStore.getInstance(storeType);
        }
        keystore.load(new FileInputStream(keystorePath), storePassword.toCharArray());

        if (keyPassword == null) {
            keyPassword = keystorePassword;
        }

        return getCredentialFromKeystore(keystore, keyAlias, keyPassword);
    }

    /**
     * Reads in the X509 credentials from a PKCS11 source.
     * 
     * @param keystoreProvider keystore provider class
     * @param pkcs11Config PKCS11 configuration file used by the keystore provider
     * @param keyAlias private key keystore alias
     * @param keyPassword private key password
     * 
     * @return the credentials
     */
    @SuppressWarnings("unchecked")
    protected static BasicX509Credential getPKCS11Credential(String keystoreProvider, String pkcs11Config,
            String keyAlias, String keyPassword) throws IOException, GeneralSecurityException {
        LOG.debug("Install PKCS11 provider");

        KeyStore keystore = null;
        try {
            if (keystoreProvider != null) {
                LOG.debug("Creating PKCS11 keystore with provider {} and configuration file {}", keystoreProvider,
                        pkcs11Config);
                Class<Provider> providerClass = (Class<Provider>) XmlTool.class.getClassLoader().loadClass(
                        keystoreProvider);
                Constructor<Provider> providerConstructor = providerClass.getConstructor(String.class);
                Provider pkcs11Provider = providerConstructor.newInstance(pkcs11Config);
                pkcs11Provider.load(new FileInputStream(pkcs11Config));
                Security.addProvider(pkcs11Provider);
                keystore = KeyStore.getInstance("PKCS11", pkcs11Provider);
            } else {
                LOG.debug("Creating PKCS11 keystore with system wide provider and configuration file");
                keystore = KeyStore.getInstance("PKCS11");
            }
        } catch (ClassNotFoundException e) {
            // TODO
        } catch (NoSuchMethodException e) {
            // TODO
        } catch (InstantiationException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
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
     */
    @SuppressWarnings("unchecked")
    protected static BasicX509Credential getCredentialFromKeystore(KeyStore keystore, String keyAlias,
            String keyPassword) throws GeneralSecurityException {

        KeyStore.Entry keyEntry = keystore.getEntry(keyAlias,
                new KeyStore.PasswordProtection(keyPassword.toCharArray()));

        BasicX509Credential credential = new BasicX509Credential();
        if (keyEntry instanceof PrivateKeyEntry) {
            PrivateKeyEntry privKeyEntry = (PrivateKeyEntry) keyEntry;
            List certChain = Arrays.asList(privKeyEntry.getCertificateChain());
            credential.setEntityCertificate((X509Certificate) privKeyEntry.getCertificate());
            credential.setEntityCertificateChain(certChain);
            credential.setPrivateKey(privKeyEntry.getPrivateKey());
            credential.setPublicKey(privKeyEntry.getCertificate().getPublicKey());
        } else if (keyEntry instanceof KeyStore.TrustedCertificateEntry) {
            KeyStore.TrustedCertificateEntry certEntry = (KeyStore.TrustedCertificateEntry) keyEntry;
            credential.setEntityCertificate((X509Certificate) certEntry.getTrustedCertificate());
            credential.setPublicKey(credential.getEntityCertificate().getPublicKey());
        }

        LOG.debug("Successfully read credentials from keystore");
        return credential;
    }
}