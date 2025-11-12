#!/usr/bin/env python3
"""
Fix PostgreSQL sequence sync issue for whitelisted_ip table
This script should be run on the production server
"""

import os
import psycopg2
from psycopg2 import sql

def fix_postgresql_sequence():
    """Fix the whitelisted_ip sequence in PostgreSQL"""
    
    # Get database connection details from environment
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        print("❌ DATABASE_URL not found in environment")
        return
    
    try:
        # Parse the database URL
        # Format: postgresql://user:password@host:port/database
        if database_url.startswith('postgresql://'):
            # Remove postgresql:// prefix
            db_url = database_url[13:]
            
            # Split into parts
            if '@' in db_url:
                auth_part, host_db_part = db_url.split('@', 1)
                if ':' in auth_part:
                    user, password = auth_part.split(':', 1)
                else:
                    user = auth_part
                    password = ''
                
                if '/' in host_db_part:
                    host_port, database = host_db_part.split('/', 1)
                    if ':' in host_port:
                        host, port = host_port.split(':', 1)
                    else:
                        host = host_port
                        port = '5432'
                else:
                    host = host_db_part
                    port = '5432'
                    database = 'gbot_db'
            else:
                print("❌ Invalid database URL format")
                return
        else:
            print("❌ Not a PostgreSQL URL")
            return
        
        print(f"Connecting to PostgreSQL: {host}:{port}/{database} as {user}")
        
        # Connect to PostgreSQL
        conn = psycopg2.connect(
            host=host,
            port=port,
            database=database,
            user=user,
            password=password
        )
        
        cursor = conn.cursor()
        
        # Check current max ID
        cursor.execute("SELECT MAX(id) FROM whitelisted_ip")
        max_id = cursor.fetchone()[0]
        print(f"Current max ID in whitelisted_ip table: {max_id}")
        
        if max_id is None:
            print("No records found in whitelisted_ip table")
            # Reset sequence to 1
            cursor.execute("SELECT setval('whitelisted_ip_id_seq', 1, false)")
            conn.commit()
            print("✅ Reset sequence to 1")
        else:
            # Check current sequence value
            cursor.execute("SELECT last_value FROM whitelisted_ip_id_seq")
            current_seq = cursor.fetchone()[0]
            print(f"Current sequence value: {current_seq}")
            
            # Fix the sequence to be one higher than max ID
            new_seq_value = max_id + 1
            cursor.execute(f"SELECT setval('whitelisted_ip_id_seq', {new_seq_value})")
            conn.commit()
            print(f"✅ Fixed sequence to: {new_seq_value}")
            
            # Verify the fix
            cursor.execute("SELECT last_value FROM whitelisted_ip_id_seq")
            new_seq = cursor.fetchone()[0]
            print(f"New sequence value: {new_seq}")
        
        # Also clean up any duplicate IPs
        cursor.execute("""
            DELETE FROM whitelisted_ip 
            WHERE id NOT IN (
                SELECT MIN(id) 
                FROM whitelisted_ip 
                GROUP BY ip_address
            )
        """)
        deleted_count = cursor.rowcount
        if deleted_count > 0:
            print(f"✅ Cleaned up {deleted_count} duplicate IP addresses")
            conn.commit()
        
        cursor.close()
        conn.close()
        
        print("✅ PostgreSQL sequence fixed successfully!")
        
    except Exception as e:
        print(f"❌ Error fixing PostgreSQL sequence: {e}")

if __name__ == '__main__':
    fix_postgresql_sequence()
