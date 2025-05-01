import sqlite3

def check_and_update_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    try:
        # Check if is_admin column exists
        c.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in c.fetchall()]
        
        if 'is_admin' not in columns:
            print("Adding is_admin column to users table...")
            c.execute("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT FALSE")
            conn.commit()
            print("✅ is_admin column added successfully")
        else:
            print("✅ is_admin column already exists")
            
        # Show all users and their admin status
        print("\nAll users in the system:")
        c.execute("SELECT id, email, fullname, is_admin FROM users")
        users = c.fetchall()
        
        if users:
            print("\n{:<5} {:<30} {:<20} {:<10}".format("ID", "Email", "Name", "Is Admin"))
            print("-" * 65)
            for user in users:
                print("{:<5} {:<30} {:<20} {:<10}".format(
                    user[0], user[1], user[2], "Yes" if user[3] else "No"
                ))
        else:
            print("No users found in the system")
            
    except Exception as e:
        print(f"❌ Error: {str(e)}")
    finally:
        conn.close()

if __name__ == "__main__":
    check_and_update_db() 