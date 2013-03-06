# XSTJ-27: compatibility with Apache Santuario 1.5.x

## Test 1 (signing with ID reference)

    ...xmlsectool.sh --sign --inFile in1.xml --outFile out1.tmp \
        --certificate ../rsasign2k.crt --key ../rsasign2k.key --referenceIdAttributeName ID

Failure will be an exception "Cannot resolve element with ID uk001480".

Success requires comparing `out1.tmp` created above with `out1.xml` and verifying that they are similar other than
the actual signature value.  In addition, verify that the signature reference is to `"#uk001480"`.

## Test 2 (signing with empty reference)

    ...xmlsectool.sh --sign --inFile in1.xml --outFile out1.tmp \
        --certificate ../rsasign2k.crt --key ../rsasign2k.key

Verify that the signature reference is to "".

## Test 3 (verification with ID reference)

    ...xmlsectool.sh --verifySignature --inFile in3.xml --outFile out3.tmp --certificate ../rsasign2k.crt
    
Failure will be an exception, either "Signature Reference URI #uk001480 was resolved to a node other than the document element" or an indication that the URI doesn't resolve to a node at all.

Success will be obvious, but it is also valuable to re-run with `--verbose` and confirm that we are "`marking ID attribute ID`".

Success is a message confirming verification, and `diff in2.xml out2.tmp` showing no differences.

## Test 4 (verification with empty reference)

    ...xmlsectool.sh --verifySignature --inFile in4.xml --outFile out4.tmp --certificate ../rsasign2k.crt

Success will be obvious, but it is also valuable to re-run with `--verbose` and confirm that "`reference was empty; no ID marking required`".

Note that this also constitutes a test for XSTJ-15.