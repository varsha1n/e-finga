import random
import string
import sqlite3
import sys


# System Initialization Phase


def oas_registering(serviceprovider_name, PK_S):

    # TA distributes Psuedo random idenctification code (IC_S) for every registered OAS
    characters = string.ascii_letters + string.digits
    IC_S = "".join(random.choice(characters) for _ in range(8))

    conn = sqlite3.connect("C:\major\e-finga\Trusted_Authority\Trusted_Authority_DB.db")
    c = conn.cursor()

    # Insert data into the OAS table
    c.execute(
        "INSERT INTO OAS (serviceprovider_name, PK_S, IC_S) VALUES (?, ?, ?)",
        (serviceprovider_name, PK_S, IC_S),
    )

    conn.commit()
    conn.close()

    BF_RDS = None

    return IC_S, BF_RDS


# oas_registering()
