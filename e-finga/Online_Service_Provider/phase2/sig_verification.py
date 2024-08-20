import sqlite3
import datetime
from Crypto.Hash import SHA256
from Crypto.Util import number


def e(x, y, N):
    return (x * y) % N


# Define hash function H1
def H1(data):
    data_bytes = data.encode()
    # Hash data using SHA256 and return the result as bytes
    hash_obj = SHA256.new(data_bytes)
    return hash_obj.digest()


def sig_verification():
    with sqlite3.connect(r"C:\major\e-finga\Online_Service_provider\OAS_DB.db") as conn:
        c = conn.cursor()

        c.execute(
            "SELECT ID_U,TS1,SG_U FROM USER_SIG",
            (),
        )
        result = c.fetchone()
        ID_U, TS1, SG_U = result

        c.execute(
            "SELECT PK_S FROM OAS_INFO WHERE serviceprovider_name=?",
            ("service_ABC",),
        )
        PK_S = c.fetchone()
        PK_S = PK_S[0]

    with sqlite3.connect(
        r"C:\major\e-finga\Trusted_Authority\Trusted_AUthority_DB.db"
    ) as conn:
        c = conn.cursor()
        c.execute(
            "SELECT N,g_small FROM TA WHERE l=?",
            (5,),
        )
        N, g = c.fetchone()

    with sqlite3.connect(r"C:\major\e-finga\User\USER.db") as conn:
        c = conn.cursor()

        c.execute(
            "SELECT PK_U FROM USER_INFO WHERE user_name=?",
            ("user1",),
        )
        PK_U = c.fetchone()
        PK_U = PK_U[0]

    hashed_data = H1(ID_U + str(PK_S) + TS1)
    SG_U = int(SG_U)

    # Compute e(g, S_igUi) and e(PKUi, H1(IDUi || PKS || TS1))
    result1 = e(g, SG_U, N)
    result2 = e(PK_U, int.from_bytes(hashed_data, byteorder="big"), N)
    print(result1, result2)

    # Check if the two results are equal
    if result1 == result2:
        print("The equation holds true.")
    else:
        print("The equation does not hold true.")


sig_verification()
