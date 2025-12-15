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
        
        # Add multi-tenant naming columns to aws_config if they don't exist
        if 'aws_config' in tables:
            columns = [col['name'] for col in inspector.get_columns('aws_config')]
            
            new_columns = [
                ('instance_name', "VARCHAR(100) DEFAULT 'default'"),
                ('ecr_repo_name', "VARCHAR(255) DEFAULT 'gbot-app-password-worker'"),
                ('lambda_prefix', "VARCHAR(100) DEFAULT 'gbot-chromium'"),
                ('dynamodb_table', "VARCHAR(255) DEFAULT 'gbot-app-passwords'"),
            ]
            
            for col_name, col_type in new_columns:
                if col_name not in columns:
                    print(f"Adding column {col_name} to aws_config...")
                    try:
                        db.session.execute(text(f'ALTER TABLE aws_config ADD COLUMN {col_name} {col_type}'))
                        db.session.commit()
                        print(f"Column {col_name} added successfully.")
                    except Exception as e:
                        db.session.rollback()
                        print(f"Error adding column {col_name}: {e}")
                else:
                    print(f"Column {col_name} already exists in aws_config.")
        else:
            print("aws_config table doesn't exist yet, creating all tables...")
            db.create_all()
            print("All tables created successfully.")
            
        print("Migration complete.")

if __name__ == "__main__":
    migrate()
