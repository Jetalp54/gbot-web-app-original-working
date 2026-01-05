import os
import psycopg2
from urllib.parse import urlparse

# Define the connection parameters directly or parse from string
# Default production URI based on config.py template
DATABASE_URL = os.environ.get('DATABASE_URL') or 'postgresql://gbot_user:gbot_password@localhost:5432/gbot_db'

def migrate_raw():
    print(f"Connecting to database: {DATABASE_URL}")
    
    try:
        # Parse connection string
        result = urlparse(DATABASE_URL)
        username = result.username
        password = result.password
        database = result.path[1:]
        hostname = result.hostname
        port = result.port or 5432
        
        # Connect using psycopg2 directly
        conn = psycopg2.connect(
            database=database,
            user=username,
            password=password,
            host=hostname,
            port=port
        )
        conn.autocommit = True
        cursor = conn.cursor()
        
        print("Connected! Checking for missing columns...")

        # 1. Add 'name' to 'aws_config' if not exists
        try:
            cursor.execute("SELECT name FROM aws_config LIMIT 1")
            print("'name' column already exists in aws_config.")
        except psycopg2.errors.UndefinedColumn:
            conn.rollback() # Clear error state
            print("Adding 'name' column to 'aws_config'...")
            cursor = conn.cursor() # Get new cursor
            cursor.execute('ALTER TABLE aws_config ADD COLUMN name VARCHAR(255) DEFAULT \'Default Account\'')
            print("Added 'name' column.")
        except Exception as e:
             message = str(e)
             if "does not exist" in message: # Table might not exist?
                 print(f"Error checking aws_config: {e}")
                 # rollback just in case
                 conn.rollback()
             else:
                 print(f"Unexpected error: {e}")

        # 2. Add 'active_aws_config_id' to 'user' if not exists
        try:
            cursor.execute("SELECT active_aws_config_id FROM \"user\" LIMIT 1")
            print("'active_aws_config_id' column already exists in user.")
        except psycopg2.errors.UndefinedColumn:
            conn.rollback() # Clear error state
            print("Adding 'active_aws_config_id' column to 'user'...")
            cursor = conn.cursor()
            cursor.execute('ALTER TABLE "user" ADD COLUMN active_aws_config_id INTEGER REFERENCES aws_config(id)')
            print("Added 'active_aws_config_id' column.")
        except Exception as e:
             print(f"Error checking user table: {e}")
             conn.rollback()

        cursor.close()
        conn.close()
        print("Basic Schema Migration Completed Successfully.")
        print("You can now restart the gbot service.")
        
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")
        # Identify if it's an auth error or DB not found
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    migrate_raw()
