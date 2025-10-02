#!/bin/bash

# Optimized PKI certificate generation script for Kazakh PKI with IIN/BIN

# Certificate details
CA_SUBJ="/C=KZ/ST=Astana/O=Test CA/CN=Test Root CA/emailAddress=test@example.com"
USER_SUBJ="/C=KZ/ST=Astana/O=Test Organization/CN=Test User/emailAddress=user@example.com/serialNumber=1234567890"
IIN="123456789012"
BIN="012345678912"
P12_PASS="123456"

echo "Generating Root CA..."
openssl genrsa -out ca.key 2048 2>/dev/null
openssl req -new -x509 -days 3650 -key ca.key -sha256 -out ca.crt -subj "$CA_SUBJ"
cp ca.crt ca.pem

echo "Generating user certificate..."
openssl genrsa -out user.key 2048 2>/dev/null

# Create user cert config
cat > user.conf << EOF
[req]
distinguished_name=req_dn
req_extensions=v3_req
prompt=no
[req_dn]
$(echo "$USER_SUBJ" | tr '/' '\n' | grep -v '^$' | sed 's/=/=/')
[v3_req]
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth,emailProtection
subjectAltName=email:user@example.com,otherName:1.2.398.3.3.4.1.1;UTF8:$IIN,otherName:1.2.398.3.3.4.1.2;UTF8:$BIN
EOF

# Generate CSR and sign
openssl req -new -key user.key -out user.csr -config user.conf
openssl x509 -req -in user.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out user.crt -days 365 -extensions v3_req -extfile user.conf -sha256
cp user.crt user.pem

# Create PKCS#12
openssl pkcs12 -export -out user.p12 -inkey user.key -in user.pem -certfile ca.pem -passout pass:$P12_PASS

# Java compatibility fix
keytool -importkeystore -srckeystore user.p12 -srcstoretype PKCS12 -srcstorepass $P12_PASS -destkeystore user.jks -deststoretype JKS -deststorepass $P12_PASS -noprompt 2>/dev/null
keytool -importkeystore -srckeystore user.jks -srcstoretype JKS -srcstorepass $P12_PASS -destkeystore user_fixed.p12 -deststoretype PKCS12 -deststorepass $P12_PASS -noprompt 2>/dev/null
mv user_fixed.p12 user.p12

# Cleanup
rm -f user.conf user.csr ca.srl

echo "Generated files:"
echo "CA: ca.key, ca.crt, ca.pem"
echo "User: user.key, user.crt, user.pem, user.p12 (pass: $P12_PASS)"
echo "IIN: $IIN, BIN: $BIN"