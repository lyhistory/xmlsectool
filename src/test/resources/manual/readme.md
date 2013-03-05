# Manual Tests

Because `xmlsectool` is a CLI application and not specifically designed for testability,
some regression and feature tests need to be performed manually.

Each JIRA case requiring a manual test is given its own subdirectory here.  Common resources,
such as keys, used by many such tests are provided here.

`rsasign2k.key` and `rsasig2k.crt` were created as follows:

    openssl req -newkey rsa:2048 -nodes -new -x509
        -keyout rsasign2k.key -out rsasign2k.crt
