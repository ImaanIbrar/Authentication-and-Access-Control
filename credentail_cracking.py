import pyshark
from Decryption_attack import test_all_decryptions
tshark_path = "D:\\Wireshark\\tshark.exe"  # Correct


import pyshark


interface = 'Adapter for loopback traffic capture'

capture = pyshark.LiveCapture(interface=interface,tshark_path=tshark_path, display_filter='http')

print("Starting packet capture... Press Ctrl+C to stop.")
try:
    for packet in capture.sniff_continuously(packet_count=2):
        print(f"Packet captured: {packet}")
except KeyboardInterrupt:
    print("\nCapture stopped.")

#from captured packets
encrypted_email = "lpddqleudu86@jpdlo.frp"
encrypted_password = "sdvvzrug" 
possible_plaintexts = test_all_decryptions(encrypted_email, encrypted_password)


