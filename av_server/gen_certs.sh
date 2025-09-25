openssl ecparam -name secp384r1 -genkey -noout -out certs/server.ecdsa.key
openssl req -x509 -new -key certs/server.ecdsa.key -out certs/server.ecdsa.crt -days 3650
