from Crypto.Util import number
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Util.number import getPrime
import sqlite3

# System Initialization Phase


def gen_parameters(l):
    # Generate two large primes, q1 and q2
    q1 = getPrime(l)
    q2 = getPrime(l)

    # Compute N = q1 * q2
    N = q1 * q2

    # Generate a random integer in Z_N
    g_small = number.getRandomRange(1, N)

    # Find a generator u such that u has the same order as g_small
    while True:
        u = number.getRandomRange(1, N)
        if pow(u, q1, N) != 1 and pow(u, q2, N) != 1:
            break

    # Compute G_capital, GT, and e
    G_capital = N  # Group G_capital
    GT = 1  # Group GT (GT is always 1 in 2DNF)
    e = lambda x, y: (x * y) % N  # Bilinear map e

    # Compute secret bases SB=g_small^q1 and PB=e(g_small,g_small)^q1
    SB = pow(g_small, q1, N)
    PB = pow(e(g_small, g_small), q1, N)

    # Compute h = u^q2
    h = pow(u, q2, N)

    # Choose a secure asymmetric encryption algorithm (ECC)
    E_func = ECC.generate(curve="P-256")

    # Generate a random number as TA's private key
    SK_TA = number.getRandomRange(1, N)

    # Compute TA's public key
    PK_TA = pow(g_small, SK_TA, N)

    # Define hash functions H1 and H2
    def H1(data):
        # Hash data using SHA256 and return the result as bytes
        hash_obj = SHA256.new(data)
        return hash_obj.digest()

    def H2(data):
        # Hash data using SHA256 and return the result as bytes
        hash_obj = SHA256.new(data)
        return hash_obj.digest()

    # TA keeps <q1,SK_TA> secretly
    # TA publishes system parameters <G_capital, GT , e, g_small, h, N, PK_TA, E_func(), H1(), H2()>

    conn = sqlite3.connect("C:\major\e-finga\Trusted_Authority\Trusted_Authority_DB.db")
    c = conn.cursor()

    # Insert data into the OAS table
    c.execute(
        "INSERT INTO TA (l,q1,q2,G_capital, GT, g_small, h, N, SK_TA,PK_TA,SB,PB) VALUES (?, ?, ?,?, ?, ?,?, ?, ?,?, ?, ?)",
        (l, q1, q2, G_capital, GT, g_small, h, N, SK_TA, PK_TA, SB, PB),
    )

    # Commit the transaction and close the connection
    conn.commit()
    conn.close()

    return G_capital, GT, e, g_small, h, N, PK_TA, E_func, H1, H2


gen_parameters(20)
