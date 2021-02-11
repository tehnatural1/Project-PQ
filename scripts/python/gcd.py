"""
Converts RSA moduli from integer to hex for compatibility with the fastgcd
script from factorable.net
"""


int_moduli = open("resources/fastgcd/int.moduli", "r")
hex_moduli = open("resources/fastgcd/hex.moduli", "w+")


for line in int_moduli.readlines():
    try:
        hex_moduli.write("{:x}\n".format(int(line)))

    except Exception as e:
        print("Failed conversion of: {}, err: {}".format(line, e))

int_moduli.close()
hex_moduli.close()

