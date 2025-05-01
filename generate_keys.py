from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

# Email of the user
user_email = "irenekathini06@gmail.com"
key_folder = "keys"
os.makedirs(key_folder, exist_ok=True)

# Generate private key
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Save private key
private_key_path = os.path.join(key_folder, f"{user_email}_private.pem")
with open(private_key_path, "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Save public key
public_key_path = os.path.join(key_folder, f"{user_email}_public.pem")
with open(public_key_path, "wb") as f:
    f.write(private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("Key pair generated successfully.")
