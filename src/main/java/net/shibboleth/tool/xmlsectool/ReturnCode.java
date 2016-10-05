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

/**
 * Return codes for the command-line application.
 */
public enum ReturnCode {

    /** Return code indicating command completed successfully, 0. */
    RC_OK(0),

    /** Return code indicating an initialization error, 1. */
    RC_INIT(1),

    /** Return code indicating an error reading files, 2. */
    RC_IO(2),

    /** Return code indicating the input XML was not well formed, 3. */
    RC_MALFORMED_XML(3),

    /** Return code indicating input XML was not valid, 4. */
    RC_INVALID_XML(4),

    /** Return code indicating an error validating the XML, 5. */
    RC_INVALID_XS(5),

    /** Return code indicating an error reading the credentials, 6. */
    RC_INVALID_CRED(6),

    /** Return code indicating indicating that signing or signature verification failed, 7. */
    RC_SIG(7),
    
    /** Return code indicating that the JAVA_HOME variable is not set within the shell script, 8. */
    RC_NOHOME(8),
    
    /** Return code indicating that the "java" command is not executable within the shell script, 9. */
    RC_NOJAVA(9),

    /** Return code indicating an unknown error occurred, -1. */
    RC_UNKNOWN(-1);

    /** Return code value. */
    private final int code;

    /**
     * Constructor.
     *
     * @param c return code value
     */
    ReturnCode(final int c) {
        code = c;
    }

    /**
     * Gets the return code value.
     * 
     * @return the return code value
     */
    public int getCode() {
        return code;
    }
}
