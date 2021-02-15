Through the use of these scripts, the entire IPv4 address space was scanned for public key data. This includes the data presented during SSH and TLS handshakes (on ports 22 and 443 respectively). This public key data was then analyzed for entropy, this resulted in the exposure of many private keys. 


## Public Key Collector
*collector.py* Scans the desired IPv4 address space and collects any public key or certificate presented after a TLS or SSH handshake.

## Certificate Data Extractor and Database Builder
*certificate.py* Parses the data public key and certificate data collected by the *collector.py* script and stores the resulting data in a SQLite3 database.

## Prime Number Verification and Identification
*utility/prime.py* Capable of finding the next prime number after a given integer.

## Device Model Identification
*utility/scrape_tls_host.py* Attempts to identify the device model that presented the TLS certificate.

...WIP, but I don't intend to elaborate further any of the other scripts
