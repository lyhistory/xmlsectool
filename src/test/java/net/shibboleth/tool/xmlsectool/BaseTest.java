package net.shibboleth.tool.xmlsectool;

import java.io.File;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.MissingResourceException;

import org.custommonkey.xmlunit.Diff;
import org.custommonkey.xmlunit.XMLUnit;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;

public abstract class BaseTest {

    /** Class being tested. */
    protected final Class<?> testingClass;
    
    /**
     * Base path for class-relative test resource references.
     * 
     * Will <em>not</em> end in a '/'.
     */
    private final String baseClassPath;
    
    /** Package for the class being tested. */
    private final Package testingPackage;
    
    /**
     * Base path for package-relative test resource references.
     * 
     * Will always end in a '/'.
     */
    private final String basePackagePath;
    
    /** Initialized parser pool used to parser data. */
    private BasicParserPool parserPool;

    /** Constructor */
    protected BaseTest(final Class<?> clazz) {
        testingClass = clazz;
        baseClassPath = nameToPath(testingClass.getName());
        testingPackage = testingClass.getPackage();
        basePackagePath = nameToPath(testingPackage.getName()) + "/";
    }
    
    /**
     * Converts the "."-separated name of a class or package into an
     * absolute path.
     * 
     * @param name name to be converted
     * @return path to resources associated with the name
     */
    private String nameToPath(final String name) {
        return "/" + name.replace('.', '/');
    }
        
    /**
     * Makes a resource reference relative to the class being tested.
     * 
     * The convention adopted is that the class-relative name is something
     * like "foo.pem", and that this is expanded to "/a/b/c/Bar-foo.pem".
     * 
     * @param which class-relative resource name
     * @return absolute resource name
     */
    protected String classRelativeResource(final String which) {
        return baseClassPath + "-" + which;
    }
    
    protected String simpleClassRelativeName(final String which) {
        return testingClass.getSimpleName() + "-" + which;
    }
        
    /**
     * Returns a test resource {@link File} with a name related to the class under test.
     * 
     * @param which class-local name of the file
     * @return the named {@link File}, or <code>null</code>
     */
    protected File classRelativeFile(final String which) {
        final String name = classRelativeResource(which);
        final URL url = testingClass.getResource(name);
        Assert.assertNotNull(url, "could not locate class-relative resource " + name);
        try {
            return new File(url.toURI());
        } catch (URISyntaxException e) {
            throw new MissingResourceException(which, testingClass.getName(), "can't locate package-relative file");
        }
    }

    /**
     * Makes a resource reference relative to the package of the class being tested.
     * 
     * The convention adopted is that the package-relative name is something
     * like "foo.pem", and that this is expanded to "/a/b/c/foo.pem".
     * 
     * @param which package-relative resource name
     * @return absolute resource name
     */
    protected String packageRelativeResource(final String which) {
        return basePackagePath + which;
    }

    /**
     * Returns a test resource {@link File} from the package directory.
     * 
     * @param which package-local name of the file
     * @return the named {@link File}, or <code>null</code>
     */
    protected File packageRelativeFile(final String which) {
        final String name = packageRelativeResource(which);
        final URL url = testingClass.getResource(name);
        Assert.assertNotNull(url, "could not locate package resource " + name);
        try {
            return new File(url.toURI());
        } catch (URISyntaxException e) {
            throw new MissingResourceException(which, testingClass.getName(), "can't locate package-relative file");
        }
    }

    /**
     * Returns the local test directory containing a useful collection of schema files.
     * 
     * @return the schema directory
     */
    protected File getSchemaDirectory() {
        final File schemas = packageRelativeFile("schema/xenc-schema.xsd").getParentFile();
        Assert.assertTrue(schemas.exists());
        Assert.assertTrue(schemas.isDirectory());
        return schemas;
    }

    /**
     * Setup test class. Creates and initializes the parser pool.
     * 
     * @throws ComponentInitializationException if there is a problem initializing the parser pool
     */
    @BeforeClass
    public void setUp() throws ComponentInitializationException {
        XMLUnit.setIgnoreWhitespace(true);

        parserPool = new BasicParserPool();
        parserPool.initialize();
    }

    /**
     * Gets an initialized parser pool.
     * 
     * @return initialized parser pool, never null
     */
    public ParserPool getParserPool() {
        return parserPool;
    }
    
    /**
     * Reads in an XML file, parses it, and returns the parsed document. If the given path is relative (i.e., does not
     * start with a '/') it is assumed to be relative to the class, or to /data if the class has not been set.
     * 
     * @param path classpath path to the data file, never null
     * 
     * @return the parsed {@link Document}, never null
     * 
     * @throws XMLParserException thrown if the file does not exist or there is a problem parsing it
     */
    public Document readXMLDocument(final String path) throws XMLParserException {
        String trimmedPath = StringSupport.trimOrNull(path);
        Constraint.isNotNull(trimmedPath, "Path may not be null or empty");

        if (!trimmedPath.startsWith("/")) {
            trimmedPath = classRelativeResource(trimmedPath);
        }

        final InputStream input = BaseTest.class.getResourceAsStream(trimmedPath);
        if (input == null) {
            throw new XMLParserException(trimmedPath + " does not exist or is not readable");
        }

        return parserPool.parse(input);
    }

    /**
     * Checks whether two nodes are identical based on {@link Diff#identical()}.
     * 
     * @param expected the expected node against which the actual node will be tested, never null
     * @param actual the actual node tested against the expected node, never null
     */
    public void assertXMLIdentical(Node expected, Node actual) {
        Constraint.isNotNull(expected, "Expected Node may not be null");
        Constraint.isNotNull(actual, "Actual Node may not be null");

        Diff diff = new Diff(expected.getOwnerDocument(), actual.getOwnerDocument());
        if (!diff.identical()) {
            org.testng.Assert.fail(diff.toString());
        }
    }
}
