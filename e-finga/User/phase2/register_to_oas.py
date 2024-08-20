import sqlite3
import datetime
from Crypto.Hash import SHA256
from Crypto.Util import number


# Define hash functions H1 and H2
def H1(data):
    data_bytes = data.encode()
    # Hash data using SHA256 and return the result as bytes
    hash_obj = SHA256.new(data_bytes)
    return hash_obj.digest()


def H2(data):
    # Hash data using SHA256 and return the result as bytes
    hash_obj = SHA256.new(data)
    return hash_obj.digest()


def register_to_oas():

    with sqlite3.connect(
        r"C:\major\e-finga\Trusted_Authority\Trusted_Authority_DB.db"
    ) as conn:
        c = conn.cursor()

        c.execute(
            "SELECT N FROM TA WHERE l=?",
            (5,),
        )
        N = c.fetchone()
        N = N[0]

    serviceprovider_name = "service_ABC"
    with sqlite3.connect(r"C:\major\e-finga\Online_Service_provider\OAS_DB.db") as conn:
        c = conn.cursor()

        c.execute(
            "SELECT PK_S FROM OAS_INFO WHERE serviceprovider_name=?",
            (serviceprovider_name,),
        )
        PK_S = c.fetchone()
        PK_S = PK_S[0]

    user_name = "user1"

    with sqlite3.connect(r"C:\major\e-finga\User\USER.db") as conn:
        c = conn.cursor()

        c.execute("SELECT SK_U FROM USER_INFO WHERE user_name=?", (user_name,))
        SK_U = c.fetchone()
        SK_U = SK_U[0]

    ID_U = user_name

    current_time = datetime.datetime.now()

    # Convert the datetime object to a string
    TS1 = current_time.strftime("%Y-%m-%d %H:%M:%S")

    # Concatenate the inputs
    concatenated_data = ID_U + str(PK_S) + TS1

    # Compute H1(IDUi || PKS || TS1)
    hashed_data = H1(concatenated_data)

    # Compute (H1(IDUi || PKS || TS1))^SKUi
    SG_U = pow(int.from_bytes(hashed_data, byteorder="big"), SK_U, N)

    with sqlite3.connect(r"C:\major\e-finga\Online_Service_provider\OAS_DB.db") as conn:
        c = conn.cursor()

        c.execute(
            "INSERT INTO USER_SIG ( ID_U,TS1,SG_U) VALUES (?,?,?)",
            (ID_U, TS1, SG_U),
        )


register_to_oas()
