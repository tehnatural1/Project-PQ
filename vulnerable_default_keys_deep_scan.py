"""
Scans the certificate database for well known default public keys where the
private key is also known for embeded devices.

The required resources must be downloaded and pointed in the settings below.

The output is displayed in console only, to save to file use linux redirects
    >>> python3 vulnerable_default_keys_deep_scan.py > some_file_location

Reference:
    Private and public key PEM and key files from House Of Keys.
    https://github.com/sec-consult/houseofkeys

    Private and public key repository of manufacturer default SSH keys.
    https://github.com/rapid7/ssh-badkeys

    Private and public key repository of manufacturer default keys for both
    TLS and SSH.
    https://github.com/BenBE/kompromat

"""

# Displaying the data optimally
import pprint

# Access filesystem
import os

# Connect the TLS and SSH database
from sqlite3        import connect

from certificate    import Certificate, SSHKey

# Identifier for the start of a Certificate
CERT_FLAG   =   "-----BEGIN CERTIFICATE-----"

# TLS and SSH database locations
TLS_DB_PATH = "databases/tls.db"
SSH_DB_PATH = "databases/ssh.db"


def extract_fps_ecs(file_path, fps, ecs):
    """
    Extract the fingerprints and Ellyptic Curve data from a given file.

    Args:
        file_path (str): Full system path to the file.
        fps (dict): Dictionary of all collected fingerprints.
        ecs (dict): Dictionary of all collected Elyptic Curve data.

    """
    try:
        pem = open(file_path, "r").read()

        if (pem.startswith("-----BEGIN PUBLIC KEY-----")):
            pn = SSHKey.from_pem_public_key(pem).public_numbers
            ecs.setdefault(str(pn.x), []).append(file_path)

        elif (CERT_FLAG in pem):
            pem = pem[pem.rfind(CERT_FLAG):].strip()
            cert = Certificate.from_string(pem)
            fps.setdefault(cert.fingerprint, []).append(file_path)

    except Exception as e: print(file_path, str(e))


def extract_rsa_dsa(file_path, rsa, dsa):
    """
    Extract RSA and DSA numbers from a SSH base public Key

    Args:
        file_path (str): Full system path to the file.
        rsa (dict): Dictionary of all collected RSA moduli.
        dsa (dict): Dictionary of all collected DSA data.

    """
    for line in open(file_path, "r").readlines():
        try:
            if line.startswith("ssh-rsa"):
                hex_n = "{:x}".format(SSHKey.from_string(line).public_numbers.n)
                rsa.setdefault(hex_n, []).append(file_path)

            elif line.startswith("ssh-dss"):
                pn = SSHKey.from_string(line).public_numbers

                dsa.setdefault(str(pn.y), []).append(
                    [
                        str(pn.parameter_numbers.p),
                        str(pn.parameter_numbers.q),
                        str(pn.parameter_numbers.g),
                        file_path
                    ]
                )
        except Exception as e: print(file_path, str(e))


def get_public_key_data(system_path, rsa, dsa, fps, ecs):
    """
    Iterates through every folder, subfolder, and file checking for public key
    data. If found, the data is extracted and added to the dictionaries.

    Args:
        file_path (str): Full system path to the file.
        rsa (dict): Dictionary of all collected RSA moduli.
        dsa (dict): Dictionary of all collected DSA data.
        fps (dict): Dictionary of all collected fingerprints.
        ecs (dict): Dictionary of all collected EC data.

    """
    for root, _, files in os.walk(system_path):
        for name in files:
            file_path = os.path.join(root, name)
            if (file_path.endswith((".crt", ".pem"))):
                extract_fps_ecs(file_path, fps, ecs)

            elif (file_path.endswith((".pub", ".info"))):
                extract_rsa_dsa(file_path, rsa, dsa)


def check_fingerprints(cur, fps):
    """
    Checks a dictionary of fingerprints against the data store in the database.

    Args:
        cur (sqlite3.Cursor): A database cursor created from a connection.
        fps (dict): A dictionary containing all the fingerprints to check.

    """
    fp_count    =   0
    dog_pound   =   {}
    for fingerprint, paths in fps.items():
        cur.execute(
            "SELECT * FROM x509info WHERE fingerprint = '%s';" % fingerprint
        )

        for ip, fp, issuer, subject, serial, notB, notA in cur:
            fp_count += 1
            dog_pound.setdefault(" && ".join(paths), 0)
            dog_pound[" && ".join(paths)] += 1

    pprint.pprint(dog_pound)
    print("FINGERPRINT TOTAL:", fp_count)


def check_rsaNumbers(cur, rsa):
    """
    Checks a dictionary of rsa numbers against the data stored in the database.

    Args:
        cur (sqlite3.Cursor): A database cursor created from a connection.
        rsa (dict): A dictionary containing all the rsa numbers to check.

    """
    rsa_count   =   0
    dog_pound   =   {}
    cur.execute("SELECT * FROM rsaNumbers;")
    # debian_weak_keys = 0

    for ip, n, e in cur:
        file_path = rsa.get(n, None)
        if (None != file_path):
            # if ("debian_openssl_weak_keys" in file_path[0]):
            #     debian_weak_keys += 1
            rsa_count += 1
            dog_pound.setdefault(" && ".join(file_path), 0)
            dog_pound[" && ".join(file_path)] += 1

    pprint.pprint(dog_pound)
    print("RSA TOTAL:", rsa_count)
    # print("DEBIAN_WEAK_KEY_TOTAL:", debian_weak_keys)


def check_dsaNumbers(cur, dsa):
    """
    Checks a dictionary of dsa numbers against the data stored in the database.

    Args:
        cur (sqlite3.Cursor): A database cursor created from a connection.
        dsa (dict): A dictionary containing all the dsa numbers to check.

    """
    dsa_count   =   0
    dog_pound   =   {}
    cur.execute("SELECT * FROM dsaNumbers;")
    for ip, y, p, q, g in cur:

        params = dsa.get(y, None)
        if params == None: continue

        for i in params:
            if (p == i[0] and q == i[1] and g == i[2]):
                dog_pound.setdefault(i[3], 0)
                dog_pound[i[3]] += 1
                dsa_count += 1

    pprint.pprint(dog_pound)
    print("DSA TOTAL:", dsa_count)


def check_ecNumbers(cur, ecs):
    """
    Checks a dictionary of ec numbers against the data stored in the database.

    Args:
        cur (sqlite3.Cursor): A database cursor created from a connection.
        ecs (dict): A dictionary containing all the ec numbers to check.

    """
    cur.execute("SELECT * FROM ecNumbers;")
    ecs_count   =   0
    dog_pound   =   {}
    for ip, curve, x, y in cur:
        file_path = ecs.get(str(x), None)
        if (None != file_path):
            ecs_count += 1
            dog_pound.setdefault(" && ".join(file_path), 0)
            dog_pound[" && ".join(file_path)] += 1

    pprint.pprint(dog_pound)
    print("EC TOTAL:", ecs_count)


def check_SSH_db(rsa, dsa, ecs):
    """
    Check the SSH public key database for manufacturer default keys where the
    private key is known.

    Args:
        rsa (dict): Contains all the collected rsa data form the default data.
        dsa (dict): Contains all the collected dsa data form the default data.
        ecs (dict): Contains all the collected ec data form the default data.

    """
    conn    =   connect(SSH_DB_PATH)
    cur     =   conn.cursor()

    check_rsaNumbers(cur, rsa)
    check_dsaNumbers(cur, dsa)
    check_ecNumbers(cur, ecs)

    cur.close()
    conn.close()


def check_TLS_db(fps):
    """
    Check the TLS public key database for manufacturer default keys where the
    private key is known.

    Args:
        rsa (dict): Contains all the collected rsa data form the default data.
        dsa (dict): Contains all the collected dsa data form the default data.
        ecs (dict): Contains all the collected ec data form the default data.

    """
    conn    =   connect(TLS_DB_PATH)
    cur     =   conn.cursor()

    check_fingerprints(cur, fps)

    cur.close()
    conn.close()


if (__name__ == "__main__"):
    """
    Scan each of the Manufacturer Default Key resources for a public in either
    database in which the private key is known.
    """
    rsa = {}
    dsa = {}
    fps = {}
    ecs = {}

    get_public_key_data(
        "default_keys/houseofkeys/private_keys",
        rsa, dsa, fps, ecs
    )
    get_public_key_data(
        "default_keys/houseofkeys/certificates",
        rsa, dsa, fps, ecs
    )
    get_public_key_data(
        "default_keys/ssh-badkeys/authorized",
        rsa, dsa, fps, ecs
    )
    get_public_key_data(
        "default_keys/ssh-badkeys/host",
        rsa, dsa, fps, ecs
    )
    get_public_key_data(
        "default_keys/kompromat/src",
        rsa, dsa, fps, ecs
    )

    #check_TLS_db(fps)
    check_SSH_db(rsa, dsa, ecs)