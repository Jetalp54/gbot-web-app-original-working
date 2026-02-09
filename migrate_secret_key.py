
import sqlite3
import os

def migrate_db():
    db_path = os.path.join(os.getcwd(), 'instance', 'gbot.db')
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # Check if column exists
        cursor.execute("PRAGMA table_info(aws_generated_password)")
        columns = [info[1] for info in cursor.fetchall()]
        
        if 'secret_key' not in columns:
            print("Adding 'secret_key' column to 'aws_generated_password' table...")
            cursor.execute("ALTER TABLE aws_generated_password ADD COLUMN secret_key VARCHAR(100)")
            conn.commit()
            print("Migration successful: 'secret_key' column added.")
        
        if 'execution_id' not in columns:
            print("Adding 'execution_id' column to 'aws_generated_password' table...")
            cursor.execute("ALTER TABLE aws_generated_password ADD COLUMN execution_id VARCHAR(50)")
            conn.commit()
            print("Migration successful: 'execution_id' column added.")
        else:
            print("Columns already exist or no changes needed.")
            
    except Exception as e:
        print(f"Migration failed: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_db()
