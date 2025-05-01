import sqlite3

def update_users():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Update all existing users to be approved
    c.execute('UPDATE users SET is_approved = TRUE')
    
    conn.commit()
    conn.close()
    print("✅ All existing users have been approved.")

if __name__ == '__main__':
    update_users() 