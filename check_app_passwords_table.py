import sqlite3
import os

# Check if database exists
db_path = os.path.join('instance', 'gbot.db')
print(f"Database path: {db_path}")
print(f"Database exists: {os.path.exists(db_path)}")

if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check if app_passwords table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='app_passwords'")
    result = cursor.fetchone()
    print(f"app_passwords table exists: {result is not None}")
    
    if result is None:
        print("Creating app_passwords table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS app_passwords (
                user_alias TEXT PRIMARY KEY,
                app_password TEXT NOT NULL,
                domain TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        print("✅ app_passwords table created successfully!")
    else:
        print("✅ app_passwords table already exists")
        
        # Check existing records
        cursor.execute("SELECT COUNT(*) FROM app_passwords")
        count = cursor.fetchone()[0]
        print(f"Number of app passwords stored: {count}")
        
        if count > 0:
            cursor.execute("SELECT user_alias, domain, created_at FROM app_passwords LIMIT 5")
            records = cursor.fetchall()
            print("Sample records:")
            for record in records:
                print(f"  - {record[0]} ({record[1]}) - {record[2]}")
    
    conn.close()
else:
    print("❌ Database file does not exist!")
