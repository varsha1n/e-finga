from Crypto.Util import number
import sqlite3
import sys

sys.path.append(r"C:\major\e-finga")

from Trusted_Authority.phase1.oas_registering import oas_registering

# System Initialization Phase - OAS is registering in TA


# Function to generate OAS er's key pair
def generate_key_pair_oas():

    l = 5

    conn = sqlite3.connect("C:\major\e-finga\Trusted_Authority\Trusted_Authority_DB.db")
    c = conn.cursor()

    c.execute("SELECT N,g_small FROM TA WHERE l=?", (l,))

    N, g = c.fetchone()

    conn.commit()
    conn.close()

    serviceprovider_name = "service_ABC"
    # Choose a random number as the private key
    SK_S = number.getRandomRange(1, N)

    # Compute the corresponding public key PK_S=g^SK_S
    PK_S = pow(g, SK_S, N)

    IC_S, BF_RDS = oas_registering(serviceprovider_name, PK_S)
    conn = sqlite3.connect(r"C:\major\e-finga\User\USER.db")
    c = conn.cursor()

    conn = sqlite3.connect(r"C:\major\e-finga\Online_Service_Provider\OAS_DB.db")
    c = conn.cursor()

    c.execute(
        "INSERT INTO OAS_INFO ( serviceprovider_name, PK_S, SK_S, IC_S, BF_RDS) VALUES (?,?,?,?, ?)",
        (serviceprovider_name, PK_S, SK_S, IC_S, BF_RDS),
    )

    conn.commit()
    conn.close()

    return "OAS phase1 completed"


print(generate_key_pair_oas())
