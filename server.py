from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from socket import socket, AF_INET, SOCK_STREAM
import csv
import random
import uuid
import datetime

# Load private key
def load_private_key():
    with open("private.pem", "rb") as f:
        return RSA.import_key(f.read())

# Decrypt function using RSA
def decrypt_data(encrypted_data, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_data).decode()

# Fetch account details from the CSV
def get_account_details(account_number):
    with open("accounts.csv", "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["account_number"] == account_number:
                return row
    return None

# Update account balance in the CSV
def update_account_status(account_number, updated_account_details):
    rows = []
    with open("accounts.csv", "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    for row in rows:
        if row["account_number"] == account_number:
            row.update(updated_account_details)

    with open("accounts.csv", "w", newline='', encoding="utf-8") as f:
        fieldnames = ["account_number", "pin", "amount", "status"]  # Ensure 'status' is included in the fieldnames
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

# Generate a random OTP
def generate_otp():
    return str(random.randint(100000, 999999))  # Generates a 6-digit OTP

# Hash OTP using SHA-256
def hash_otp(otp):
    hasher = SHA256.new()
    hasher.update(otp.encode())
    return hasher.hexdigest()

# Log transaction details to a file
def log_transaction(transaction_id, sender_account, recipient_account, transfer_amount, encrypted_details, hashes):
    with open("transactions.txt", "a") as f:
        f.write(f"Transaction ID: {transaction_id}\n")
        f.write(f"Date & Time: {datetime.datetime.now()}\n")
        f.write(f"Sender Account: {sender_account}\n")
        f.write(f"Recipient Account: {recipient_account}\n")
        f.write(f"Transfer Amount: {transfer_amount}\n")
        f.write(f"Encrypted Details: {encrypted_details}\n")
        f.write(f"Hashes: {hashes}\n")
        f.write("-" * 50 + "\n")

    # Print to server console
    print(f"\n[Server] Transaction ID: {transaction_id}")
    print(f"[Server] Date & Time: {datetime.datetime.now()}")
    print(f"[Server] Sender Account: {sender_account}")
    print(f"[Server] Recipient Account: {recipient_account}")
    print(f"[Server] Transfer Amount: {transfer_amount}")
    print(f"[Server] Encrypted Details: {encrypted_details}")
    print(f"[Server] Hashes: {hashes}")
    print("-" * 50)

# Server function
def start_server():
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.bind(("localhost", 12345))
    server_socket.listen(1)
    print("[Server] Listening on port 12345...")

    client_socket, addr = server_socket.accept()
    print(f"[Server] Connection from {addr}")

    private_key = load_private_key()

    # Receive encrypted account number and PIN
    encrypted_account_number = client_socket.recv(256)
    print("[Server] Received encrypted account number from Client.")
    encrypted_pin = client_socket.recv(256)
    print("[Server] Received encrypted PIN from Client.")

    # Decrypt account number and PIN using RSA
    decrypted_account_number = decrypt_data(encrypted_account_number, private_key)
    decrypted_pin = decrypt_data(encrypted_pin, private_key)

    # Fetch account details from CSV
    account_details = get_account_details(decrypted_account_number)
    if account_details and account_details["pin"] == decrypted_pin:
        print("[Server] Account validation successful.")
        response = f"Validation Successful. Your account balance: {account_details['amount']}".encode()
        client_socket.send(response)

        # Receive encrypted recipient account and amount
        encrypted_recipient_account = client_socket.recv(256)
        print("[Server] Received encrypted recipient account number from Client.")
        encrypted_transfer_amount = client_socket.recv(256)
        print("[Server] Received encrypted transfer amount from Client.")

        recipient_account = decrypt_data(encrypted_recipient_account, private_key)
        transfer_amount = decrypt_data(encrypted_transfer_amount, private_key)

        # Generate random OTP
        otp = generate_otp()
        print(f"[Server] Generated OTP: {otp}")
        hashed_otp = hash_otp(otp)

        # Send OTP to client
        client_socket.send(f"Your OTP: {otp}".encode())
        print("[Server] Sent OTP to Client.")

        # Receive and verify OTP
        received_otp_hash = client_socket.recv(1024).decode()
        print("[Server] Received OTP from Client.")
        if received_otp_hash == hashed_otp:
            transaction_id = str(uuid.uuid4())

            encrypted_details = {
                "encrypted_account_number": encrypted_account_number.hex(),
                "encrypted_recipient_account": encrypted_recipient_account.hex(),
                "encrypted_transfer_amount": encrypted_transfer_amount.hex()
            }
            hashes = {
                "account_hash": SHA256.new(decrypted_account_number.encode()).hexdigest(),
                "pin_hash": SHA256.new(decrypted_pin.encode()).hexdigest(),
                "otp_hash": hashed_otp
            }

            log_transaction(transaction_id, decrypted_account_number, recipient_account, transfer_amount, encrypted_details, hashes)

            # Fetch recipient account details
            recipient_account_details = get_account_details(recipient_account)

            if recipient_account_details:
                sender_balance = float(account_details["amount"])
                transfer_amount = float(transfer_amount)

                if sender_balance >= transfer_amount:
                    # Deduct the amount from sender and add to recipient
                    new_sender_balance = sender_balance - transfer_amount
                    new_recipient_balance = float(recipient_account_details["amount"]) + transfer_amount

                    # Update account balances
                    account_details["amount"] = str(new_sender_balance)
                    recipient_account_details["amount"] = str(new_recipient_balance)

                    update_account_status(decrypted_account_number, account_details)
                    update_account_status(recipient_account, recipient_account_details)

                    client_socket.send(f"OTP Verified. Transfer Successful! New balance: {new_sender_balance},Transaction ID: {transaction_id}".encode())
                else:
                    client_socket.send(b"Insufficient balance for transfer.")
                    client_socket.close()
                    return
            else:
                client_socket.send(b"Recipient account not found.")
                client_socket.close()
                return
        else:
            client_socket.send(b"Invalid OTP. Transaction terminated.")
            client_socket.close()
            return
    else:
        print("[Server] Account validation failed.")
        client_socket.send(b"Validation Failed.")
        client_socket.close()
        return

    client_socket.close()
    print("[Server] Connection closed.")
    return

if __name__ == "__main__":
    start_server()
