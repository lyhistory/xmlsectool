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
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nonnull;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.Validator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;
import net.shibboleth.utilities.java.support.xml.SchemaBuilder;
import net.shibboleth.utilities.java.support.xml.SchemaBuilder.SchemaLanguage;

/**
 * Validates XML documents based on a schema file, or a collection of schema
 * files contained in a directory.
 */
public class SchemaValidator {
    
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(SchemaValidator.class);

    /**
     * Compiled schema object. Can be reused for multiple document validations.
     */
    private final Schema schema;
    
    /**
     * Constructor.
     * 
     * @param schemaLanguage schema language in use: either XSD or RELAX
     * @param schemaLocation location of the schema description (may be a directory of schema files)
     * @throws SAXException 
     */
    public SchemaValidator(@Nonnull final SchemaLanguage schemaLanguage, @Nonnull final File schemaLocation)
            throws SAXException {
        Constraint.isNotNull(schemaLanguage, "schema language must not be null");
        Constraint.isNotNull(schemaLocation, "schema location must not be null");
        final SchemaBuilder builder = new SchemaBuilder();
        builder.setSchemaLanguage(schemaLanguage);

        // locate the schema sources
        final List<File> schemaFiles = new ArrayList<>();
        getSchemaFiles(schemaLanguage, new File[]{schemaLocation}, schemaFiles);
        for (final File schemaFile : schemaFiles) {
            builder.addSchema(new StreamSource(schemaFile));
        }
        
        // build the schema
        schema = builder.buildSchema();
    }

    /**
     * Provides the file name extension associated with a schema language.
     * 
     * Results include the ".".
     * 
     * @param schemaLanguage schema language
     * @return the file name extension associated with the schema language
     */
    private String schemaFileExtension(@Nonnull final SchemaLanguage schemaLanguage) {
        switch (schemaLanguage) {
            case XML:
                return ".xsd";

            case RELAX:
                return ".rng";

            default:
                throw new ConstraintViolationException("unknown schema language");
        }
    }

    /**
     * Gets all of the schema files in the given set of readable files, directories or subdirectories.
     * 
     * @param lang schema language, must not be null
     * @param schemaFilesOrDirectories files and directories which may contain schema files
     * @param accumulatedSchemaFiles list that accumulates the schema files
     */
    protected void getSchemaFiles(@Nonnull final SchemaLanguage lang,
            final File[] schemaFilesOrDirectories,
            final List<File> accumulatedSchemaFiles) {

        Constraint.isNotNull(lang, "Schema language may not be null");
        
        if (schemaFilesOrDirectories == null || schemaFilesOrDirectories.length == 0) {
            return;
        }

        for (final File handle : schemaFilesOrDirectories) {
            if (handle == null) {
                continue;
            }

            if (!handle.canRead()) {
                log.debug("Ignoring '{}', no read permission", handle.getAbsolutePath());
            }

            if (handle.isFile() && handle.getName().endsWith(schemaFileExtension(lang))) {
                log.debug("Added schema source '{}'", handle.getAbsolutePath());
                accumulatedSchemaFiles.add(handle);
            }

            if (handle.isDirectory()) {
                getSchemaFiles(lang, handle.listFiles(), accumulatedSchemaFiles);
            }
        }
    }

    /**
     * Validate a document against the compiled schema.
     * 
     * @param document document to validate
     * @throws SAXException if the document fails to validate
     * @throws IOException if an I/O error occurs while reading the document
     */
    public void validate(@Nonnull final Source document) throws SAXException, IOException {
        final Validator validator = schema.newValidator();
        validator.validate(document);
    }

}
