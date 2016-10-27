# Initialize keys and certificates for rootCA and intermediate CA
java -cp "target/classes/:target/mc-identityregistry-core-latest/WEB-INF/lib/*" net.maritimecloud.identityregistry.utils.CertificateUtil

echo "Exporting root cert to mcidreg-root-cert.pem, please enter password"
keytool -exportcert -alias rootcert -keystore mc-root-keystore.jks -rfc -file mcidreg-root-cert.pem

echo "Exporting intermediate cert to mcidreg-it-cert.pem, please enter password"
keytool -exportcert -alias imcert -keystore mc-it-keystore.jks -rfc -file mcidreg-it-cert.pem

echo "Creating mc-ca-chain.pem containing the intermediate and root certificate"
cat mcidreg-it-cert.pem mcidreg-root-cert.pem > mc-ca-chain.pem
