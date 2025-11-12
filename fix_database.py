#!/usr/bin/env python3
"""
Fix database by adding ever_used column to used_domain table
Works with existing Flask app configuration
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def fix_database():
    """Add ever_used column using Flask app context"""
    try:
        # Import Flask app and database
        from app import app
        from database import db, UsedDomain
        
        with app.app_context():
            print("🔄 Checking database schema...")
            
            # Check if column exists by trying to access it
            try:
                # Try to query the ever_used column
                test_query = db.session.execute(
                    "SELECT ever_used FROM used_domain LIMIT 1"
                ).fetchone()
                print("✅ Column 'ever_used' already exists!")
                return True
                
            except Exception as e:
                if "does not exist" in str(e) or "UndefinedColumn" in str(e):
                    print("📝 Column 'ever_used' doesn't exist. Adding it...")
                    
                    # Add the column using raw SQL
                    db.session.execute(
                        "ALTER TABLE used_domain ADD COLUMN ever_used BOOLEAN DEFAULT FALSE"
                    )
                    
                    # Update existing records: if user_count > 0, set ever_used = TRUE
                    result = db.session.execute(
                        "UPDATE used_domain SET ever_used = TRUE WHERE user_count > 0"
                    )
                    
                    db.session.commit()
                    
                    print(f"✅ Successfully added 'ever_used' column!")
                    print(f"   - Updated {result.rowcount} existing records with ever_used=TRUE")
                    
                    # Show current status
                    stats = db.session.execute("""
                        SELECT 
                            COUNT(*) as total,
                            COUNT(CASE WHEN ever_used = TRUE THEN 1 END) as ever_used,
                            COUNT(CASE WHEN user_count > 0 THEN 1 END) as in_use
                        FROM used_domain
                    """).fetchone()
                    
                    print(f"   - Total domains: {stats[0]}")
                    print(f"   - Ever used domains: {stats[1]}")
                    print(f"   - Currently in use: {stats[2]}")
                    print(f"   - Available domains: {stats[0] - stats[1]}")
                    
                    return True
                else:
                    print(f"❌ Unexpected database error: {e}")
                    return False
                    
    except ImportError as e:
        print(f"❌ Could not import Flask app: {e}")
        print("Make sure you're running this from the correct directory with all dependencies installed.")
        return False
    except Exception as e:
        print(f"❌ Database error: {e}")
        try:
            db.session.rollback()
        except:
            pass
        return False

if __name__ == '__main__':
    print("🔄 Starting database fix...")
    print("This will add the 'ever_used' column to the used_domain table.")
    
    success = fix_database()
    
    if success:
        print("\n🎉 Database fix completed successfully!")
        print("You can now use the three-state domain system:")
        print("   🟢 AVAILABLE - Never been used")
        print("   🟠 USED - Previously used, no current users") 
        print("   🟣 IN USE - Currently has users")
        sys.exit(0)
    else:
        print("\n💥 Database fix failed!")
        print("Please check the error messages above.")
        sys.exit(1)
