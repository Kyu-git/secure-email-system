import sqlite3
import os
from werkzeug.security import generate_password_hash

DB_NAME = 'users.db'

def init_db():
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME)
        print("Removed existing database file")
    
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    # Users table
    c.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullname TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Emails table
    c.execute('''
        CREATE TABLE emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            subject TEXT,
            message TEXT,
            attachment TEXT,
            signature TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Rejected Emails table
    c.execute('''
        CREATE TABLE rejected_emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            recipient TEXT,
            subject TEXT,
            message TEXT,
            reason TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create an admin user with hashed password
    admin_password = 'admin123'
    hashed_password = generate_password_hash(admin_password)
    c.execute('''
        INSERT INTO users (fullname, email, password, is_admin)
        VALUES (?, ?, ?, ?)
    ''', ('Admin User', 'admin@example.com', hashed_password, True))

    conn.commit()
    conn.close()
    print("✅ Database created with users, emails, and rejected_emails tables.")
    print("✅ Admin user created with email: admin@example.com and password: admin123")

if __name__ == '__main__':
    init_db() 