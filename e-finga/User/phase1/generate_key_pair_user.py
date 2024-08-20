from Crypto.Util import number
import sqlite3
import sys

sys.path.append(r"C:\major\e-finga")
from Trusted_Authority.phase1.user_registering import user_registering


def generate_key_pair_user():

    l = 5

    conn = sqlite3.connect("C:\major\e-finga\Trusted_Authority\Trusted_Authority_DB.db")
    c = conn.cursor()

    c.execute("SELECT N,g_small FROM TA WHERE l=?", (l,))

    N, g = c.fetchone()

    conn.commit()
    conn.close()
    user_name = "user1"
    # Choose a random number as the private key
    SK_U = number.getRandomRange(1, N)

    # Compute the corresponding public key PK_S=g^SK_S
    PK_U = pow(g, SK_U, N)

    image_path = r"C:\major\DB1_B_2004\101_2.tif"

    SB, PB, K, IC_S = user_registering(user_name, PK_U, N, image_path)

    conn = sqlite3.connect(r"C:\major\e-finga\User\USER.db")
    c = conn.cursor()

    c.execute(
        "INSERT INTO USER_INFO ( SK_U,PK_U,user_name,SB,PB,K,IC_S) VALUES (?,?,?,?, ?, ?,?)",
        (SK_U, PK_U, user_name, SB, PB, K, IC_S),
    )

    # Commit the transaction and close the connection
    conn.commit()
    conn.close()

    return "User phase1 completed"


generate_key_pair_user()
