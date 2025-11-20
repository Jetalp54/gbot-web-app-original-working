# Quick Fix for "Unexpected token '<'" Error

## The Problem

The Lambda is working perfectly (CloudWatch shows success), but the web app shows:
```
ERROR: Unexpected token '<', "<html><h"... is not valid JSON
```

This means the Flask endpoint `/api/aws/invoke-lambda` is crashing and returning an HTML error page instead of JSON.

**Root Cause:** The database table `aws_generated_password` doesn't exist yet.

## The Solution

You need to create the database table on your Ubuntu server.

### Step 1: Push Updated Files

Upload these files to your server:
- `routes/aws_manager.py` (updated with better error handling)
- `templates/aws_management.html` (duplicate prevention)
- `database.py` (contains AwsGeneratedPassword model)
- `update_aws_table.py` (migration script)

### Step 2: On Your Ubuntu Server

```bash
# SSH into your server
cd /opt/gbot-web-app-original-working

# Activate virtual environment
source venv/bin/activate

# Run migration to create table
python update_aws_table.py

# You should see:
# "Checking for new tables..."
# "Creating 'aws_generated_password' table..."
# "Database tables updated."

# Restart the app
sudo systemctl restart gbot

# Check status
sudo systemctl status gbot
```

### Step 3: Verify the Fix

1. Open the web app AWS page
2. Paste 1 test user
3. Select "Single Account" mode
4. Click "Invoke Production Lambda"
5. **Expected:** You should see the response in the log, not an HTML error

## What Was Fixed

### 1. Better Error Handling (`routes/aws_manager.py`)

```python
# Now wraps DB save in try-except
if response_data.get('app_password'):
    try:
        save_app_password(email, response_data['app_password'])
        logger.info(f"[INVOKE] ✓ Password saved for {email}")
    except Exception as db_error:
        logger.error(f"[INVOKE] Failed to save password to DB: {db_error}")
        # Continue anyway - return the password even if DB save fails
```

**Benefit:** Even if DB save fails, the password is still returned to the user

### 2. Duplicate Prevention (Already Applied)

- Frontend flag prevents double-clicks
- Backend set prevents duplicate processing

### 3. Auto-Table Creation (Already in Code)

```python
@aws_manager.route('/aws')
def aws_management():
    # Ensure table exists
    try:
        inspector = db.inspect(db.engine)
        if 'aws_generated_password' not in inspector.get_table_names():
            db.create_all()
    except Exception as e:
        logger.error(f"Auto-migration failed: {e}")
```

**But:** This only runs when you visit `/aws` page. The API endpoint might be called before that, causing the error.

## After Migration

Once the table exists, everything will work:

✅ **Single Account Mode:**
- Invoke Lambda → Get password → Display in UI
- Password saved to DB automatically

✅ **Multiple Accounts Mode:**
- Invoke Lambdas in parallel → Get passwords → Display in results field
- All passwords saved to DB
- No duplicates

✅ **CloudWatch Logs:**
- No more duplicate invocations
- Each user invoked exactly once
- Clean success logs

## Testing

After running the migration:

1. **Test Single Account:**
   ```
   jordanwright@domain.com:password123
   ```
   Expected: Password appears in log output

2. **Test Multiple Accounts:**
   ```
   user1@domain.com:pass1
   user2@domain.com:pass2
   user3@domain.com:pass3
   ```
   Expected: 3 passwords in results field

3. **Check Database:**
   ```bash
   sqlite3 /path/to/your/database.db
   SELECT * FROM aws_generated_password;
   ```
   Expected: See saved passwords

## If Migration Fails

If `python update_aws_table.py` fails, create the table manually:

```bash
# For PostgreSQL
psql -U your_db_user -d your_db_name

CREATE TABLE aws_generated_password (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    app_password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

# For SQLite
sqlite3 /path/to/database.db

CREATE TABLE aws_generated_password (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email VARCHAR(255) NOT NULL UNIQUE,
    app_password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

Then restart the app:
```bash
sudo systemctl restart gbot
```

## Summary

The Lambda works ✅  
The backend code is correct ✅  
The error is: **missing database table** ❌  

**Solution:** Run `python update_aws_table.py` on the server and restart the app.

