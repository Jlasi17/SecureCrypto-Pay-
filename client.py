from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from socket import socket, AF_INET, SOCK_STREAM
from Crypto.Hash import SHA256

# Load public key
def load_public_key():
    with open("public.pem", "rb") as f:
        return RSA.import_key(f.read())

# Encrypt function using RSA
def encrypt_data(data, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(data.encode())

# Hash OTP using SHA-256
def hash_otp(otp):
    hasher = SHA256.new()
    hasher.update(otp.encode())
    return hasher.hexdigest()

# Client function
def start_client():
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect(("localhost", 12345))
    print("[Client] Connected to Server...")

    public_key = load_public_key()

    # Input account number and PIN
    account_number = input("[Client] Enter Your Account Number: ")
    pin = input("[Client] Enter Your PIN: ")

    # Encrypt and send account number and PIN
    encrypted_account_number = encrypt_data(account_number, public_key)
    encrypted_pin = encrypt_data(pin, public_key)
    client_socket.send(encrypted_account_number)
    print("[Client] Sent encrypted account number to Server.")
    client_socket.send(encrypted_pin)
    print("[Client] Sent encrypted PIN to Server.")

    # Receive server response
    response = client_socket.recv(1024).decode()
    print(f"[Server Response] {response}")

    if "Validation Successful" in response:
        # Enter transaction details
        recipient_account = input("[Client] Enter Recipient Account Number: ")
        transfer_amount = input("[Client] Enter Amount to Transfer: ")

        # Encrypt and send transaction details
        encrypted_recipient_account = encrypt_data(recipient_account, public_key)
        encrypted_transfer_amount = encrypt_data(transfer_amount, public_key)
        client_socket.send(encrypted_recipient_account)
        print("[Client] Sent encrypted recipient account number to Server.")
        client_socket.send(encrypted_transfer_amount)
        print("[Client] Sent encrypted transfer amount to Server.")

        # Receive OTP prompt
        otp_prompt = client_socket.recv(1024).decode()
        print(f"[Server Response] {otp_prompt}")

        # Enter and send OTP
        otp = input("[Client] Enter the OTP: ")
        hashed_otp = hash_otp(otp)
        client_socket.send(hashed_otp.encode())
        print("[Client] Sent OTP to Server.")

        # Receive transaction result
        transaction_result = client_socket.recv(1024).decode()
        print(f"[Server Response] {transaction_result}")
    else:
        print("[Client] Validation failed.")

    client_socket.close()
    print("[Client] Connection closed.")

if __name__ == "__main__":
    start_client()
