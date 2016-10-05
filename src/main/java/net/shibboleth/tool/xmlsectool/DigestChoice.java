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

import org.opensaml.xmlsec.signature.support.SignatureConstants;

/**
 * The digest method to use in the various signature algorithms.
 */
public enum DigestChoice {

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
    public String getRSAAlgorithm() {
        return rsaAlgorithm;
    }
    
    /**
     * Returns the ECDSA signature algorithm URI for this digest choice.
     * 
     * @return algorithm URI
     */
    public String getECDSAAlgorithm() {
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
    public static DigestChoice find(final String name) {
        for (final DigestChoice choice: values()) {
            if (choice.hasName(name)) {
                return choice;
            }
        }
        return null;
    }

}
