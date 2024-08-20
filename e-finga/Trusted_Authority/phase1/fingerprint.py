import cv2
import numpy as np
from scipy import ndimage as ndi
from skimage.filters import gabor_kernel
import sqlite3
from Crypto.Hash import SHA256
from Crypto.Util import number
import mmh3
import json


def gabor_feature_extraction(image):
    # Define the parameters for Gabor filter bank
    frequency = 0.6  # Frequency of the Gabor filter
    thetas = [
        0,
        np.pi / 4,
        np.pi / 2,
        3 * np.pi / 4,
    ]  # Orientations of the Gabor filter
    kernels = []

    # Create Gabor filter bank
    for theta in thetas:
        kernel = np.real(gabor_kernel(frequency, theta=theta))
        kernels.append(kernel)

    # Apply Gabor filter bank to the image
    features = []
    for kernel in kernels:
        filtered_image = cv2.filter2D(image, -1, kernel)
        features.append(filtered_image)

    return features


def create_bloom_filter(m, k, reference_data_set):
    bit_array = [False] * m  # Initialize bit array to all False

    for element in reference_data_set:
        element_str = str(element)  # Convert number to string
        for i in range(k):
            index = hash_function(element_str, i) % m
            bit_array[index] = True

    return bit_array


def hash_function(element, seed):
    # Convert element to bytes-like object using str.encode()
    element_bytes = str(element).encode()
    # Use multiple hash functions to generate indices
    return mmh3.hash(element_bytes, seed)


def add_to_bloom_filter(bloom_filter, element, m, p):
    for i in range(p):
        index = hash_function(element, i) % m
        bloom_filter[index] = True


def fingerprint(image_path):
    # Load the image
    image = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)

    # Extract Gabor features
    features = gabor_feature_extraction(image)

    # Generate FingerCode
    finger_code = []

    with sqlite3.connect(
        "C:\major\e-finga\Trusted_Authority\Trusted_Authority_DB.db"
    ) as conn:
        c = conn.cursor()

        c.execute("SELECT K FROM USER WHERE user_name=?", ("user1",))

        K = c.fetchone()  # Fetch the first row of the result

        c.execute("SELECT IC_S FROM OAS WHERE serviceprovider_name=?", ("servie_ABC",))

        IC_S = c.fetchone()

        for feature in features:
            # Compute the mean value of the feature
            mean_value = np.mean(feature)
            # Convert the mean value to an 8-bit integer
            int_value = int(mean_value)
            # Ensure the value is within the range of 0-255
            int_value = max(0, min(int_value, 255))
            # Append the 8-bit integer to the FingerCode
            finger_code.append(int_value)

        # Compute x0^1, x0^2, ..., x0^n
        x_values = []
        for xi in finger_code:
            # Compute H2(ki + cS)
            h2_value = SHA256.new((str(K) + str(IC_S)).encode()).digest()
            # Compute xi + H2(ki + cS)
            x_value = xi + int.from_bytes(h2_value, byteorder="big")
            x_values.append(x_value)

        l = 5  # add propepr code for this at end
        c.execute("SELECT g_small,h,N FROM TA WHERE l=?", (l,))
        g_small, h, N = c.fetchone()

        f_values = []
        for fxi in x_values:
            r = number.getRandomRange(1, N)
            f_value = pow(g_small, fxi, N) * pow(h, r, N)
            f_values.append(f_value)

        c.execute("SELECT PB FROM TA WHERE N=?", (N,))

        PB = c.fetchone()
        PB = int(PB[0])
        fx = pow(PB, sum(x**2 for x in x_values), N)
        f_values.append(fx)

        th = 3
        RD_S = []
        for i in range(th**2):
            RD_S.append(pow(PB, i))

        m = 100  # Size of the bit array
        p = 3  # Number of hash functions

        BF_RDS = create_bloom_filter(m, p, RD_S)

        for element in RD_S:
            add_to_bloom_filter(BF_RDS, element, m, p)

        # Convert the array to a JSON string
        json_value = json.dumps(BF_RDS)

        c.execute("UPDATE OAS SET BF_RDS = ?", (json_value,))

    with sqlite3.connect("C:\major\e-finga\Online_service_Provider\OAS_DB.db") as conn:
        c = conn.cursor()

        # Convert the array to a JSON string
        json_value = json.dumps(BF_RDS)

        c.execute("UPDATE OAS_INFO SET BF_RDS = ?", (json_value,))

    return "Phase1 completed"


# # # # Provide the path to the image
# image_path = r"C:\major\DB1_B_2004\101_2.tif"


# # # Get the fingerprint FingerCode
# print(fingerprint(image_path))
