# XSTJ-38 blacklist MD5 algorithm during signature verification

Test by attempting to verify the signature on each of the following files, each of which was generated from `original.xml` with a different signature and digest combination:

* `sha256.xml` has digest and signature algorithms using SHA-256; should pass
* `sha256-md5d` has SHA-256 signature but MD5 digest; should fail
* `sha256-md5s` has SHA-256 digest but MD5 signature; should fail

All should pass if the `--clearBlacklist` option is added.
