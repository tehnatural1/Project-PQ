Simple overview of some of the scripts:

collector.py
Scans the entire IPv4 address space and collects any public key or certificate presented after a TLS or SSH handshake.

certificate.py
Parses the data public key and certificate data collected by the collector.py script and stores the resulting data in a SQLite3 database.

utility/prime.py
Capable of finding the next prime number after a given integer.

utility/scrape_tls_host.py
Attempts to identify the device model that presented the TLS certificate.

...WIP, but I don't intend to elaborate further any of the other scripts