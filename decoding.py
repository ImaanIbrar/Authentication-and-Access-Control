import base64

# Simulating the encoded values you provided from the form submission
email_encoded = "aW1hYW5pYnJhcjg2QGdtYWlsLmNv"
password_encoded = "cGFzc3dvcmQ="

# Decode the Base64-encoded email and password
try:
    email = base64.b64decode(email_encoded).decode('utf-8')
    password = base64.b64decode(password_encoded).decode('utf-8')
    
    print("Decoded email:", email)
    print("Decoded password:", password)
except Exception as e:
    print("Error decoding:", e)
