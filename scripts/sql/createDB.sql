/*
 *  Creates a SQLite3 compatible database used to store public key information
 *  collected from remote network devices.
 *
 *  Schema Overview:
 *  	Uses a basic star schema pinned at the extracted public key from the
 *		host device.
 *
 */

CREATE TABLE publicKeys (
	ipv4_address 		TEXT NOT NULL,		/* 256.256.256.256 */
	fingerprint			TEXT NOT NULL,		/* SHA256 Hex Digest Fingerprint */
	public_key 			TEXT NOT NULL,
	encryption 			TEXT NOT NULL,		/* RSA, EC, DSA */
	bits 				INTEGER,
	PRIMARY KEY (ipv4_address, fingerprint)
);

CREATE TABLE x509info (
	ipv4_address 		TEXT,
	fingerprint 		TEXT NOT NULL,		/* SHA256 Hex Digest Fingerprint */
	issuer 				TEXT NOT NULL,		/* C, CN, ST, L, O, etc. */
	subject 			TEXT NOT NULL,		/* C, CN, ST, L, O, etc. */
	serial 				TEXT NOT NULL,
	notBefore 			TEXT NOT NULL,		/* format: %Y%m%d%H%M%SZ */
	notAfter 			TEXT NOT NULL,		/* format: %Y%m%d%H%M%SZ */
	UNIQUE (ipv4_address, fingerprint),
	FOREIGN KEY (ipv4_address) REFERENCES publicKeys (ipv4_address)
);


/* The numbers used during the calcuation of certifacts are too large for */
/* a SQLite3 Integer type to hold; therefore, they are recorded as text */
CREATE TABLE rsaNumbers (
	ipv4_address 		TEXT,
	n 					TEXT NOT NULL,		/* Modulus */
	e 					TEXT NOT NULL,		/* Exponent */
	FOREIGN KEY (ipv4_address) REFERENCES publicKeys (ipv4_address)
);

CREATE TABLE dsaNumbers (
	ipv4_address 		TEXT,
	y 					TEXT NOT NULL,		/* Integer too small */
	p 					TEXT NOT NULL,		/* Integer too small */
	q 					TEXT NOT NULL,		/* Integer too small */
	g 					TEXT NOT NULL,		/* Integer too small */
	FOREIGN KEY (ipv4_address) REFERENCES publicKeys (ipv4_address)
);

CREATE TABLE ecNumbers (
	ipv4_address 		TEXT,
	curve 				TEXT NOT NULL,
	x 					TEXT NOT NULL,		/* Integer too small */
	y 					TEXT NOT NULL,		/* Integer too small */
	FOREIGN KEY (ipv4_address) REFERENCES publicKeys (ipv4_address)
);


/* Speeding up entropy detection queries */
CREATE INDEX IDX_Fingerprint_pks
ON publicKeys(fingerprint);

CREATE INDEX IDX_Fingerprint_x509
ON x509info(fingerprint);

CREATE INDEX IDX_IPV4_x509info
ON x509info(ipv4_address);

/*
CREATE INDEX IDX_Fingerprint_Issuer_Subject
ON x509info(fingerprint, issuer, subject);
*/