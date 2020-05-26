echo
echo "Running CRL update"
date
curl -L "https://api.example.com/x509/api/certificates/crl/urn:mrn:mcp:ca:idp1:mcp" > crl/mcp-root-crl.pem
curl -L "https://api.example.com/x509/api/certificates/crl/urn:mrn:mcp:ca:idp1:mcp-idreg" > crl/mcp-idreg-crl.pem

cat crl/mcp-idreg-crl.pem crl/mc-root-crl.pem > crl/combined-crl.pem

service nginx restart

