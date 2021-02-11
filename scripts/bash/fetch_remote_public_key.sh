echo | openssl s_client -connect $1 2>&1 | sed --quiet '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -pubkey -noout
