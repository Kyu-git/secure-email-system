import sqlite3

DB_NAME = 'users.db'

try:
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    # Check if 'emails' table exists
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='emails'")
    table_exists = c.fetchone()

    if not table_exists:
        # Create the emails table if it doesn't exist
        c.execute('''
            CREATE TABLE emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                subject TEXT,
                message TEXT,
                attachment TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        print("📦 'emails' table created.")

    # Now try to add the signature column
    try:
        c.execute("ALTER TABLE emails ADD COLUMN signature TEXT")
        print("✅ 'signature' column added.")
    except sqlite3.OperationalError as e:
        if 'duplicate column name' in str(e):
            print("⚠️ Column 'signature' already exists.")
        else:
            raise

    conn.commit()
    conn.close()

except Exception as e:
    print("❌ Error:", e)
