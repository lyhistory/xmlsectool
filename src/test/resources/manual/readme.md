# Manual Tests

Because `xmlsectool` is a CLI application and not specifically designed for testability,
some regression and feature tests need to be performed manually.

Each JIRA case requiring a manual test is given its own subdirectory here.  Common resources,
such as keys, used by many such tests are provided here.

## RSA Resources

`rsasign2k.key` and `rsasig2k.crt` were created as follows:

    openssl req -newkey rsa:2048 -nodes -new -x509 \
        -keyout rsasign2k.key -out rsasign2k.crt

## ECDSA Resources

`secp384r1.pem` was created as follows:

    openssl ecparam -name secp384r1 -out secp384r1.pem
    
`ecsign384.key` and `ecsign384.crt` were created as follows:

    openssl req -newkey ec:secp384r1.pem -nodes -new -x509 \
        -keyout ecsign384.key -out ecsign384.crt
        
`ecsigner.jks` was created as follows:

	keytool -genkeypair -keyalg ec -keystore ecsigner.jks

The keystore password is `ecsigner`.  The entry is called `mykey`.

`ecsigner.crt` was created as follows:

    keytool -exportcert -keystore ecsigner.jks -file ecsigner.crt \
        -storepass ecsigner -rfc

