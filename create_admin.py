import sqlite3
from werkzeug.security import generate_password_hash
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_key_pair(email):
    os.makedirs('keys', exist_ok=True)
    private_key_path = f'keys/{email}_private.pem'
    public_key_path = f'keys/{email}_public.pem'

    # Skip generation if keys already exist
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(public_key_path, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def create_admin_account(fullname, email, password):
    # Validate password
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    if not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not any(c.islower() for c in password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one number")
    if not any(c in '!@#$%^&*(),.?":{}|<>' for c in password):
        raise ValueError("Password must contain at least one special character")

    # Connect to database
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    try:
        # Check if user already exists
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        if c.fetchone():
            raise ValueError("User with this email already exists")

        # Create user with admin privileges
        hashed_password = generate_password_hash(password)
        c.execute('''
            INSERT INTO users (fullname, email, password, is_admin)
            VALUES (?, ?, ?, TRUE)
        ''', (fullname, email, hashed_password))

        # Generate RSA key pair
        generate_key_pair(email)

        conn.commit()
        print(f"✅ Admin account created successfully for {email}")
        print("You can now log in with these credentials:")
        print(f"Email: {email}")
        print(f"Password: {password}")

    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

if __name__ == "__main__":
    print("Creating Admin Account")
    print("=====================")
    
    fullname = input("Enter full name: ")
    email = input("Enter email: ")
    password = input("Enter password: ")
    
    try:
        create_admin_account(fullname, email, password)
    except ValueError as e:
        print(f"❌ Error: {str(e)}")
    except Exception as e:
        print(f"❌ An unexpected error occurred: {str(e)}") 