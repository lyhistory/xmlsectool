# XSTJ-28 provide blacklist ability for SHA-1 during signature verification

Test by attempting to verify the signature on `sha1.xml`.  This should pass.  Then add `--blacklistDigest SHA-1`; the verification should now fail.
