import random
import string
import sqlite3
import sys
from Crypto.Util import number

sys.path.append(r"C:\major\e-finga")
from Trusted_Authority.phase1.fingerprint import fingerprint


# System Initialization Phase


def user_registering(user_name, PK_U, N, image_path):

    conn = sqlite3.connect("C:\major\e-finga\Trusted_Authority\Trusted_Authority_DB.db")
    c = conn.cursor()

    # TA distributes Psuedo random idenctification code (IC_S) for every registered OAS
    characters = string.ascii_letters + string.digits
    c.execute("SELECT IC_S FROM OAS WHERE serviceprovider_name=?", ("service_ABC",))
    IC_S = c.fetchone()
    IC_S = IC_S[0]

    K = number.getRandomRange(1, N)

    # Insert data into the user table
    c.execute(
        "INSERT INTO USER (user_name, PK_U, IC_S,K) VALUES (?, ?, ?,?)",
        (user_name, PK_U, IC_S, K),
    )

    c.execute("SELECT SB, PB FROM TA WHERE N = ?", (N,))
    SB, PB = c.fetchone()  # Fetch the first row of the result

    # Commit the transaction and close the connection
    conn.commit()
    conn.close()

    fingerprint(image_path)

    # Execute a SELECT query to search for parameters based on N

    return SB, PB, K, IC_S
