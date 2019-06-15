############################################################################################
### Method 1: run directly from release version
############################################################################################
openssl ecparam -name secp256k1 -outform PEM -out secp256k1.pem
openssl ecparam -inform PEM -in secp256k1.pem -genkey -outform PEM -out ec-private-key.pem
openssl pkcs8 -topk8 -nocrypt -inform PEM -in ec-private-key.pem -out ec-sign.key
openssl req -new -x509 -key ec-sign.key -out ec-sign.crt -days 365

./xmlsectool-2.1.0-SNAPSHOT/xmlsectool.sh --sign --keyInfoKeyName 'Liu Yue' --digest SHA-256 --signatureAlgorithm 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256' --inFile EntryToken.canonicalized.xml --outFile EntryToken.tsml --key ec-sign.key --certificate ec-sign.crt --signaturePosition LAST

############################################################################################
### Method 2: manually build from source
############################################################################################
#to run from source:
mvn exec:java -Dexec.mainClass="net.shibboleth.tool.xmlsectool.XMLSecTool" -Dexec.args="--sign --keyInfoKeyName 'Liu Yue' --digest SHA-256 --signatureAlgorithm 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256' --inFile ./TokenScript/nft/EntryToken.canonicalized.xml --outFile ./TokenScript/nft/EntryToken.tsml --key ./TokenScript/nft/ec-sign.key --certificate ./TokenScript/nft/ec-sign.crt --signaturePosition LAST"
#to release
mvn clean package -DskipTests -Dmaven.javadoc.skip=true -Prelease

####Optional verify
openssl ec -in ec-private-key.pem -text -noout | grep priv -A 3 | tail -n +2 | tr -d '\n[:space:]:' | sed 's/^00//' > priv
openssl ec -in ec-private-key.pem -text -noout | grep pub -A 5 | tail -n +2 | tr -d '\n[:space:]:' | sed 's/^04//' > pub
#keccak-256sum tool https://github.com/vkobel/ethereum-generate-wallet
cat pub | ethereum-generate-wallet/lib/i386/keccak-256sum -x -l | tr -d ' -' | tail -c 41