import sqlite3
from werkzeug.security import generate_password_hash

DB_NAME = 'users.db'  # Change this if your DB is named differently

def migrate_plaintext_passwords():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute('SELECT * FROM users')
    users = c.fetchall()

    for user in users:
        user_id = user['id']  # Make sure 'id' is your PK column name
        plaintext_pw = user['password']
        
        # Check if it's already hashed (naive check)
        if not plaintext_pw.startswith('pbkdf2:'):
            hashed_pw = generate_password_hash(plaintext_pw)
            c.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_pw, user_id))
            print(f"Updated password for user {user['email']}")

    conn.commit()
    conn.close()
    print("Password migration completed.")

if __name__ == '__main__':
    migrate_plaintext_passwords()
