"""
Converts RSA moduli from integer to hex for compatibility with the fastgcd
script from factorable.net
"""

import base64


inp_moduli = open("censys/bq-results-20201105-165109-mjr7xvvcua0i.csv", "r")
hex_moduli = open("censys/hex.moduli", "w+")

# Remove column name
inp_moduli.readline()

for line in inp_moduli:
    try:
        hex_moduli.write( "{}\n".format(base64.b64decode(line).hex()) )

    except Exception as e:
        print("Failed conversion of: {}, err: {}".format(line, e))

inp_moduli.close()
hex_moduli.close()