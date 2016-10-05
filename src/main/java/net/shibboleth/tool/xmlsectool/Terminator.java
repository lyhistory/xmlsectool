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
 * An unchecked exception that will result in the termination of the
 * command-line application.
 * 
 * Any required error logging should be performed before throwing.
 */
public class Terminator extends RuntimeException {

    /** Serial version UID. */
    private static final long serialVersionUID = 2153781900784665006L;

    /** Exit code to be delivered to the calling shell. */
    private final int exitCode;
    
    /**
     * Constructor.
     *
     * @param code exit code to be delivered to the calling shell.
     */
    public Terminator(final ReturnCode code) {
        exitCode = code.getCode();
    }
    
    /**
     * Get the exit code to be delivered to the calling shell.
     * 
     * @return exit code
     */
    public int getExitCode() {
        return exitCode;
    }
}
