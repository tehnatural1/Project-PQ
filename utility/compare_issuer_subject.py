"""
Compares public keys for those have self-signed as well have a CA signed
counterpart.
"""

import sqlite3

# Locations of TLS database and self-signed file listing
TLS_DB          =   "databases/tls.db"
SELF_SIGNED     =   "analysis/tls/5_or_more_self_signed"


def check_issuer_and_subject_counts(
        conn: sqlite3.connect=None,
        fingerprint: str=None
    ) -> None:
    """
    Finds any cert that is CA signed but also has self-signed versions.

    Args:
        conn (sqlite3.connect): Database connection to which query against.
        fingerprint (str): Public Key fingerprint of which query will be made.

    """
    # Obtain iterative cursor for the database connection
    cur = conn.cursor()

    # Query against the fingerprint
    cur.execute(
        "SELECT * FROM x509info WHERE fingerprint = '%s';" % fingerprint
    )

    # Track fingerprints that are both CA and self-signed
    diff_count = 0
    same_count = 0

    # Iterate over the results
    for _, _, issuer, subject, _, _, _ in cur:

        # Count CA and self-signed
        if (issuer != subject): diff_count += 1
        else:                   same_count += 1

    # Display only the cases where both signed and self signed exist
    if ((same_count > 0) and (diff_count > 0)):
        print(fingerprint, same_count, diff_count)


def read_and_compare():
    """
    Reads generated self-signed file and compares against CA signed certificates
    """
    # Connect the the TLS database
    conn = sqlite3.connect(TLS_DB)

    # Iterate over the content of the generated self-signed files
    for line in open(SELF_SIGNED, 'r').readlines():
        fingerprint = line[:line.find("|")]
        check_issuer_and_subject_counts(conn, fingerprint)

    # Close the connection
    conn.close()


if (__name__ == "__main__"):
    read_and_compare()
