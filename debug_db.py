from app import app, db
from database import User, AwsConfig
from routes.aws_manager import get_current_active_config
from flask import session

def debug():
    with app.app_context():
        print("--- DEBUGGING AWS CONFIG ---")
        
        # 1. Check AWS Configs
        configs = AwsConfig.query.all()
        print(f"Total AwsConfig rows: {len(configs)}")
        for c in configs:
            print(f"  [ID: {c.id}] Name: '{c.name}' | LambdaPrefix: '{c.lambda_prefix}' | Region: '{c.region}'")

        # 2. Check Admin User
        admin = User.query.filter_by(username='admin').first()
        if admin:
            print(f"Admin User Found: ID {admin.id}, ActiveConfigID: {admin.active_aws_config_id}")
        else:
            print("Admin user NOT found!")

        # 3. Simulate get_current_active_config (tough without request context/session)
        # We can't easily mock session here without a request context stack mock
        # But we can check the logic manually:
        
        if admin:
            if admin.active_aws_config_id:
                target = AwsConfig.query.get(admin.active_aws_config_id)
                print(f"Logic Result: Should load config ID {admin.active_aws_config_id} -> {target.name if target else 'None'}")
            else:
                fallback = AwsConfig.query.first()
                print(f"Logic Result: Fallback to first config -> {fallback.name if fallback else 'None'}")

if __name__ == "__main__":
    debug()
