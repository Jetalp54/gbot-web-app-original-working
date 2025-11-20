
from app import app
from database import db

def migrate():
    print("Checking for new tables...")
    with app.app_context():
        # inspect
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        
        if 'aws_generated_password' not in tables:
            print("Creating 'aws_generated_password' table...")
            # Create only the missing tables? db.create_all() checks for existence.
            try:
                db.create_all() 
                print("Database tables updated.")
            except Exception as e:
                print(f"Error creating tables: {e}")
        else:
            print("'aws_generated_password' table already exists.")

if __name__ == "__main__":
    migrate()
