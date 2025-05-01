import sqlite3
from werkzeug.security import generate_password_hash
import re

def validate_password(password):
    """
    Validate password against security rules:
    - At least 8 characters long
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one number
    - Contains at least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is valid"

DB_NAME = 'users.db'  # or whatever your DB file is
email = 'stephenngari@gmail.com'
new_password = 'Babegal@06'

# Validate the new password
is_valid, message = validate_password(new_password)
if not is_valid:
    print(f"Password validation failed: {message}")
    exit(1)

conn = sqlite3.connect(DB_NAME)
c = conn.cursor()
hashed = generate_password_hash(new_password)
c.execute('UPDATE users SET password = ? WHERE email = ?', (hashed, email))
conn.commit()
conn.close()

print("Password reset for", email)
