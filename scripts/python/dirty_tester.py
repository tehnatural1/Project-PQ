"""
Nothing to see here, testing purposes only
"""

import sqlite3

from time import sleep
import re

#DUPLICATE_PATH = "analysis/full_duplication_list"
DUPLICATE_PATH = "analysis/full_duplication_list"
VULNERABLE_MODULI = "results/vulnerable_moduli__2188"

BASE_QUERY = "SELECT issuer, subject, notBefore, notAfter FROM x509info WHERE fingerprint = '{}'"

# conn = sqlite3.connect("databases/tls.db")
conn = sqlite3.connect("databases/ssh.db")


def run_query(fingerprint):
    print("Fingerprint:", fingerprint)

    cur = conn.cursor()
    cur.execute(BASE_QUERY.format(fingerprint))

    websites = set()
    notBefores = set()
    notAfters = set()
    count = 0

    for items in cur:
        _, subject, notBefore, notAfter = items

        count += 1

        if ("" == subject):
            website = "NO SUBJECT FIELD PROVIDED"

        elif ("/CN=" in subject):
            website = subject[subject.rfind("/CN=") + len("/CN="):]

        else:
            website = subject

        websites.add(website)
        notBefores.add(notBefore)
        notAfters.add(notAfter)

    print("Hosts:", count)
    print("Websites:", websites)
    print("Not Before Dates:", notBefores)
    print("Not After Dates:", notAfters)
    print()


# for line in open(DUPLICATE_PATH, 'r').readlines():
#     run_query(line.strip())

# run_query("0472041ec15a3109aeabf22eaa0ed176c2c23389b4c725b38636c61e146f8e2a")

total_with_mod = 0
fingerprints = set()
def modulus_query(modulus):
    global fingerprints, total_with_mod
    print("Modulus:", modulus)

    cur = conn.cursor()

    cur.execute(
        "SELECT x.fingerprint "
        "FROM x509info AS x, rsaNumbers AS r "
        "WHERE r.n = '%s' AND x.ipv4_address = r.ipv4_address;" % (modulus)
    )

    # cur.execute("SELECT ipv4_address FROM rsaNumbers WHERE n = '{}'".format(modulus))

    f = set()

    for items in cur:
        total_with_mod += 1
        fingerprint = items[0]
        if fingerprint not in f:
            print("Fingerprint:", fingerprint)
            f.add(fingerprint)
        fingerprints.add(fingerprint)

    print()


# for line in open(VULNERABLE_MODULI, 'r').readlines():
#     modulus_query(line.strip())

# print("\nTotal matching vulnerable module:", total_with_mod)
# # print("ALL FINGERPRINTS:", fingerprints)





# def get_all(moduli):
    
#     cur = conn.cursor()
#     cur.execute(
#         "SELECT ipv4_address, n "
#         "FROM rsaNumbers;"
#     )

#     for items in cur:
#         ip = items[0]
#         mod = items[1]
#         if (mod in moduli):
#             print(ip)


# moduli = []
# for line in open(VULNERABLE_MODULI, 'r').readlines():
#     moduli.append(line.strip())

# get_all(moduli)




# fps = set()
# def get_query(ip):
#     global fps
#     cur=conn.cursor()
#     cur.execute(
#         "SELECT fingerprint "
#         "FROM publicKeys WHERE ipv4_address = '%s';" % (ip)
#     )

#     for items in cur:
#         fp = items[0]
#         if fp not in fps:
#             fps.add(fp)
#             print(fp)

# for line in open("/home/dustin/school/csi4900/ALL_VULNERABLE_IPS_WITH_MODULUS"):
#     get_query(line.strip())





def test():
    cur = conn.cursor()
    cur.execute("SELECT fingerprint, subject, notBefore, notAfter FROM x509info")

    count = 0
    max_size = 0

    total_size = 0
    total_count = 0

    for items in cur:
        fingerprint, subject, notBefore, notAfter = items
        total_count += 1

        if ("/CN=" not in subject):
            count += 1
        else:
            website = subject[subject.rfind("/CN=") + len("/CN="):].lower()

            if ("\\" in website):
                def decoder(char):
                    try:
                        return char[2:].decode("hex")
                    except:
                        return ""

                website=re.sub("\\\\x[a-f0-9][a-f0-9]", lambda m: decoder(m.group()), website)

            if ("/" in website):
                website = website[:website.find("/")]

            length = len(website)
            total_size += length
            if (length > max_size):

                print("New LONGEST:", website)
                print("Fingerprint:", fingerprint)
                print()
                max_size = length


    print("NO CN Field:", count)
    print("longest website:", max_size)

    print("AVERAGE WEBSITE SIZE:", total_size/total_count)

# test()


def trial():
    cursor = conn.cursor()
    # cursor.execute("SELECT * FROM rsaNumbers;")
    cursor.execute("SELECT * FROM rsaNumbers AS r INNER JOIN publicKeys AS p ON r.ipv4_address = p.ipv4_address;")

    #moduli = open("/home/dustin/school/csi4900/vulnerable_moduli__1366", "r").readlines()
    moduli = open("/home/dustin/raid/csi4900/shodan/results/vulnerable_moduli", "r").readlines()
    count = 0

    vals = {}

    for mod in moduli:
        vals[mod.strip()] = True

    # moduli = [i.strip() for i in moduli]
    #print(moduli)
    print(len(moduli))

    for items in cursor:
        #print(items)

        if vals.get(items[1]):
            count += 1
            print(items[4])

        # if vals.get(n):
        #     count += 1
            # print(count)

    print("TOTAL:", count)

# trial()


def trial2():
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM publicKeys;")

    keys = open("/home/dustin/school/csi4900/ALL_PUBLIC_KEYS_SSH").readlines()

    vals = {}
    for key in keys:
        vals[key.strip()] = True

    print(len(vals))

    count = 0

    for items in cursor:
        if vals.get(items[1]):
            count += 1

    print("TOTAL:", count)


trial2()

