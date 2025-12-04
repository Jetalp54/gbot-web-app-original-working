from app import app
from database import db
from sqlalchemy import text

def migrate():
    with app.app_context():
        print("Migrating database...")
        
        # Check if service_account table exists
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        
        if 'service_account' not in tables:
            print("Creating service_account table...")
            # Create the table using SQLAlchemy models
            db.create_all()
            print("Table created successfully.")
        else:
            print("service_account table already exists.")
            
        print("Migration complete.")

if __name__ == "__main__":
    migrate()
