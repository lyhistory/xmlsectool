# XSTJ-16: misleading error message on failed schema validation

Test 1 (OK):

    ...xmlsectool.sh --sign --inFile in1.xml --outFile /dev/null \
        --certificate ../rsasign2k.crt --key ../rsasign2k.key \
        --validateSchema --schemaDirectory good

This test should succeed.

Test 2 (invalid XML):

    ...xmlsectool.sh --sign --inFile in1.xml --outFile /dev/null \
        --certificate ../rsasign2k.crt --key ../rsasign2k.key \
        --validateSchema --schemaDirectory bad

Success is an error reporting that the XML document is not schema valid.

Test 3 (invalid schema):

    ...xmlsectool.sh --sign --inFile in1.xml --outFile /dev/null \
        --certificate ../rsasign2k.crt --key ../rsasign2k.key \
        --validateSchema --schemaDirectory bad

Success is an error reporting that the schema document is itself invalid.
