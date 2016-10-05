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

import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;

/**
 * Support class to assist in initializing the environment in which the command-line application runs.
 */
public final class InitializationSupport {
    
    /** Remember whether we have already been initialized. */
    private static boolean initialized;
    
    /** Constructor. */
    private InitializationSupport() {
    }

    /**
     * Do we have an ECC provider available?
     * 
     * @return <code>true</code> if and only if we have an ECC provider available
     */
    private static boolean haveECCProvider() {
        try {
            Signature.getInstance("SHA256withECDSA");
            return true;
        } catch (final NoSuchAlgorithmException e) {
            return false;
        }
    }
    
    /**
     * Add an instance of the Bouncy Castle provider to the end of the provider list.
     */
    private static void addBouncyCastleProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    /**
     * Initialize the environment.
     * 
     * @throws InitializationException if the OpenSAML environment cannot be initialized
     */
    public static void initialize() throws InitializationException {
        
        // we only need to do this once, even for multiple tests
        if (initialized) {
            return;
        }

        // make sure that we have an ECC signature provider available
        if (!haveECCProvider()) {
            addBouncyCastleProvider();
        }
        
        // initialize OpenSAML
        InitializationService.initialize();
        
        initialized = true;
    }
}
