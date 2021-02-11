"""
Scans the certificate database for well known default public keys where the
private key is also known for embeded devices.

The required resources must be downloaded and pointed in the settings below.

The output is displayed in console only, to save to file use linux redirects
    >>> python3 vulnerable_default_keys.py > some_file_location

Reference:
    Private and public key database for the lbb.db.
    https://github.com/devttys0/littleblackbox

    Private and public key PEM and key files from House Of Keys.
    https://github.com/sec-consult/houseofkeys

"""

# Filesystem directory listing access
import os

# Database connection
from sqlite3        import connect

# Package Import - Conversion and extraction of certificate data
from certificate    import Certificate


# File system path for the little black box database
LITTLE_BLACK_BOX_DATABASE   =   "default_keys/lbb/lbb.db"

# File system path for the certificate database
CERTIFICATE_DATABASE        =   "databases/tls.db"

# File system path for the house of keys certificate directory
HOUSE_OF_KEYS_PATH          =   "default_keys/houseofkeys/certificates/"

# Well known identifier of the start of a certificate
BEGIN_CERTIFICATE           =   "-----BEGIN CERTIFICATE-----"


def collect_fingerprints_from_lbb_db(fingerprints: set=None) -> None:
    """
    Connects to the little black box database and converts the certificates to
    compatible fingerprints.

    Args:
        fingerprints (set): A collection of obtained certificates from the
            little black box and the house of keys.

    """
    # Actual database connection
    conn    =   connect(LITTLE_BLACK_BOX_DATABASE)
    cur     =   conn.cursor()

    # Obtain all the certificates contained in the database
    cur.execute("SELECT certificate FROM certificates;")

    # Iterate over the items from the database
    for item in cur:

        # Ignore ssh-rsa keys
        if (not item[0].startswith(BEGIN_CERTIFICATE)): continue

        # Convert the text of the certificate and extract the fingerprint
        fingerprints.add( Certificate.from_string(item[0]).fingerprint )

    conn.close()


def collect_fingerprints_from_hok_fp(fingerprints: set=None) -> None:
    """
    Iterates through the House Of Keys directory and converts the certificates
    in the PEM files to compatible fingerprints.

    Args:
        fingerprints (set): A collection of obtained certificates from the
            little black box and the house of keys.

    """
    # Iterate through the content of the directory
    for f in os.listdir(HOUSE_OF_KEYS_PATH):

        # Only interested in the known certificates
        if (not f.endswith("pem")): continue

        # Extract the PEM certificate as string
        pem = open( os.path.join(HOUSE_OF_KEYS_PATH, f), 'r' ).read()
        pem = pem[pem.rfind(BEGIN_CERTIFICATE):]

        # Convert the PEM certificate to a compatible fingerprint
        fingerprints.add( Certificate.from_string(pem).fingerprint )


def identify_vulnerabe_default_keys(fingerprints: set=None) -> list:
    """
    Scans a list for fingerprints for matches in the certificate database to
    find default keys with known private keys.

    Args:
        fingerprints (list): A list of fingerprints based on the public key.

    Returns:
        (list): Containing all the vulnerable keys in the database

    """
    # Actualy database connection
    conn    =   connect(CERTIFICATE_DATABASE)
    cur     =   conn.cursor()
    total   =   0
    fps     =   []

    # Iterate through the fingerprints
    for fp in fingerprints:

        # Obtain all the fingerprints that match
        cur.execute("SELECT * FROM x509info WHERE fingerprint = '%s';" % fp)

        # Add up all the matches
        count = 0
        for _ in cur:
            total += 1
            count += 1

        # Display fingerprints that existed in the database
        if (count > 0):
            fps.append(fp)
            print(fp, count)

    conn.close()
    print("TOTAL:", total)
    return fps


if (__name__ == "__main__"):

    # Create a set of fingerprints from the two resources
    fingerprints = set()

    # Collect the fingerprints from the Little Black Box database
    collect_fingerprints_from_lbb_db(fingerprints)

    # Collect the fingerprints from the House Of Cards file path
    collect_fingerprints_from_hok_fp(fingerprints)

    # Identify vulnerable devices with those fingerprints in the database
    identify_vulnerabe_default_keys(fingerprints)

