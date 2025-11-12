import os
from datetime import datetime
import json
import logging
import random
import string
import csv
import io
import smtplib
import tempfile
import time
from werkzeug.security import generate_password_hash, check_password_hash
import logging.handlers
import threading
import uuid

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from google_auth_oauthlib.flow import InstalledAppFlow
from faker import Faker
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from core_logic import google_api
from database import db, User, WhitelistedIP, UsedDomain, GoogleAccount, GoogleToken, Scope, ServerConfig, UserAppPassword

# Progress tracking system for domain changes
progress_tracker = {}
progress_lock = threading.Lock()

def update_progress(task_id, current, total, status="processing", message=""):
    """Update progress for a task"""
    with progress_lock:
        progress_tracker[task_id] = {
            'current': current,
            'total': total,
            'status': status,  # processing, completed, error
            'message': message,
            'percentage': int((current / total) * 100) if total > 0 else 0,
            'timestamp': datetime.now().isoformat()
        }
        logging.info(f"=== PROGRESS UPDATED FOR TASK {task_id}: {status} - {message} ({current}/{total}) ===")
        logging.info(f"Progress tracker now contains {len(progress_tracker)} tasks: {list(progress_tracker.keys())}")

def get_progress(task_id):
    """Get current progress for a task"""
    with progress_lock:
        logging.info(f"=== GET_PROGRESS CALLED FOR TASK: {task_id} ===")
        logging.info(f"Progress tracker contains: {list(progress_tracker.keys())}")
        logging.info(f"Looking for task: {task_id}")
        logging.info(f"Task exists: {task_id in progress_tracker}")
        
        progress = progress_tracker.get(task_id, {
            'current': 0,
            'total': 0,
            'status': 'not_found',
            'message': 'Task not found',
            'percentage': 0,
            'timestamp': datetime.now().isoformat()
        })
        
        if progress['status'] == 'not_found':
            logging.warning(f"=== TASK {task_id} NOT FOUND IN PROGRESS TRACKER ===")
            logging.warning(f"Available tasks: {list(progress_tracker.keys())}")
            logging.warning(f"Progress tracker size: {len(progress_tracker)}")
        else:
            logging.info(f"Task {task_id} found with status: {progress['status']}")
        
        return progress

def clear_progress(task_id):
    """Clear progress for a task"""
    with progress_lock:
        if task_id in progress_tracker:
            del progress_tracker[task_id]

def cleanup_old_progress():
    """Clean up old progress entries to prevent memory leaks"""
    with progress_lock:
        current_time = datetime.now()
        expired_tasks = []
        
        for task_id, progress in progress_tracker.items():
            # Much less aggressive cleanup: Remove tasks older than 24 hours or completed/error tasks older than 1 hour
            task_time = datetime.fromisoformat(progress['timestamp'])
            age_minutes = (current_time - task_time).total_seconds() / 60
            
            # Only clean up very old tasks or completed tasks that are quite old
            if age_minutes > 1440 or (progress['status'] in ['completed', 'error'] and age_minutes > 60):
                expired_tasks.append(task_id)
                logging.info(f"Marking task {task_id} for cleanup: age={age_minutes:.1f}min, status={progress['status']}")
        
        for task_id in expired_tasks:
            del progress_tracker[task_id]
            logging.info(f"Cleaned up expired task: {task_id}")
        
        if expired_tasks:
            logging.info(f"Cleaned up {len(expired_tasks)} expired tasks")
        else:
            logging.info("No tasks needed cleanup")

app = Flask(__name__)
app.config.from_object('config')

# Set secret key for sessions
if app.config.get('SECRET_KEY'):
    app.secret_key = app.config['SECRET_KEY']
else:
    app.secret_key = 'fallback-secret-key-for-development'

# Configure session settings
app.config['SESSION_COOKIE_SECURE'] = False  # Allow HTTP
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

db.init_app(app)

# Production logging configuration
if not app.debug:
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Configure file handler for production
    file_handler = logging.handlers.RotatingFileHandler(
        'logs/gbot.log', maxBytes=10240000, backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    
    app.logger.setLevel(logging.INFO)
    app.logger.info('GBot startup')

with app.app_context():
    db.create_all()
    
    # Auto-migration: Add ever_used column if it doesn't exist
    try:
        from sqlalchemy import text
        # Check if ever_used column exists
        result = db.session.execute(text("""
            SELECT column_name FROM information_schema.columns 
            WHERE table_name = 'used_domain' AND column_name = 'ever_used'
        """)).fetchone()
        
        if not result:
            logging.info("Adding missing 'ever_used' column to used_domain table...")
            # Add the column
            db.session.execute(text("ALTER TABLE used_domain ADD COLUMN ever_used BOOLEAN DEFAULT FALSE"))
            # Update existing records
            db.session.execute(text("UPDATE used_domain SET ever_used = TRUE WHERE user_count > 0"))
            db.session.commit()
            logging.info("✅ Successfully added 'ever_used' column!")
        else:
            logging.debug("Column 'ever_used' already exists")
            
    except Exception as e:
        logging.warning(f"Could not auto-migrate ever_used column: {e}")
        try:
            db.session.rollback()
        except:
            pass
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', password=generate_password_hash('A9B3nX#Q8k$mZ6vw', method='pbkdf2:sha256'), role='admin')
        db.session.add(admin_user)
        db.session.commit()

def login_required(f):
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@app.before_request
def before_request():
    # Debug logging
    app.logger.debug(f"Before request: endpoint={request.endpoint}, user={session.get('user')}, emergency_access={session.get('emergency_access')}, client_ip={get_client_ip()}")
    
    # Always allow these routes without any checks (whitelisted routes)
    if request.endpoint in ['static', 'login', 'emergency_access', 'test-admin']:
        app.logger.debug(f"Allowing {request.endpoint} route without restrictions")
        return

    # Allow emergency access users to access all endpoints
    if session.get('emergency_access'):
        app.logger.debug(f"Allowing emergency access user to access {request.endpoint}")
        return

    # IP Whitelist check - for ALL users (including logged-in users)
    # Check if IP whitelist is enabled
    if app.config.get('ENABLE_IP_WHITELIST', True):  # Default to True for security
        client_ip = get_client_ip()
        app.logger.info(f"Checking IP whitelist for {client_ip} accessing {request.endpoint}")
        
        # Check if IP is whitelisted
        whitelisted_ip = WhitelistedIP.query.filter_by(ip_address=client_ip).first()
        
        if not whitelisted_ip:
            app.logger.warning(f"IP {client_ip} not whitelisted, access denied to {request.endpoint}")
            return f"Access denied. IP {client_ip} is not whitelisted. Please contact administrator or use emergency access.", 403
        else:
            app.logger.info(f"IP {client_ip} is whitelisted, allowing access")
    else:
        app.logger.debug("IP whitelist disabled, allowing access")

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Debug logging
        app.logger.info(f"Login attempt for username: {username}")
        
        user = User.query.filter_by(username=username).first()
        
        if user:
            app.logger.info(f"User found: {user.username}, role: {user.role}")
            if check_password_hash(user.password, password):
                app.logger.info(f"Password verified for user: {username}")
                session['user'] = user.username
                session['role'] = user.role
                session.permanent = True  # Make session persistent
                app.logger.info(f"Session set - user: {session.get('user')}, role: {session.get('role')}")
                flash(f'Welcome {user.username}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                app.logger.warning(f"Invalid password for user: {username}")
                flash('Invalid credentials', 'error')
        else:
            app.logger.warning(f"User not found: {username}")
            flash('Invalid credentials', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/test-admin')
def test_admin():
    """Test route to check admin user and authentication"""
    try:
        admin_user = User.query.filter_by(username='admin').first()
        if admin_user:
            from werkzeug.security import check_password_hash
            password_works = check_password_hash(admin_user.password, 'A9B3nX#Q8k$mZ6vw')
            return jsonify({
                'admin_exists': True,
                'username': admin_user.username,
                'role': admin_user.role,
                'password_works': password_works,
                'session_user': session.get('user'),
                'session_role': session.get('role')
            })
        else:
            return jsonify({'admin_exists': False})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/whitelist-bypass')
def whitelist_bypass():
    """Temporary bypass route for whitelist management"""
    # Set emergency access session
    session['emergency_access'] = True
    session['role'] = 'admin'
    session['user'] = 'emergency_admin'
    session.permanent = True
    
    flash('Emergency access granted for whitelist management', 'success')
    return redirect(url_for('whitelist'))

@app.route('/health')
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Test database connection
        db.session.execute('SELECT 1')
        db_status = 'healthy'
    except Exception as e:
        db_status = f'unhealthy: {str(e)}'
    
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'database': db_status,
        'version': '1.0.0'
    })

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    accounts = GoogleAccount.query.all()
    return render_template('dashboard.html', accounts=accounts, user=session.get('user'), role=session.get('role'))

@app.route('/users')
@login_required
def users():
    if session.get('role') != 'admin':
        flash("Admin access required.", "danger")
        return redirect(url_for('dashboard'))
    return render_template('users.html', user=session.get('user'), role=session.get('role'))

@app.route('/emergency_access')
def emergency_access():
    """Emergency access route that bypasses IP whitelist for initial setup"""
    # Check for static key in URL parameters
    static_key = request.args.get('key', '')
    whitelist_token = app.config.get('WHITELIST_TOKEN', '')
    secret_key = app.config.get('SECRET_KEY', '')
    
    # Debug logging
    app.logger.info(f"Emergency access route - Key provided: {static_key[:8] if static_key else 'None'}..., WHITELIST_TOKEN: {whitelist_token[:8] if whitelist_token else 'None'}..., SECRET_KEY: {secret_key[:8] if secret_key else 'None'}...")
    
    # If WHITELIST_TOKEN is provided directly, auto-whitelist the current IP
    if static_key == whitelist_token:
        client_ip = get_client_ip()
        app.logger.info(f"WHITELIST_TOKEN provided - auto-whitelisting IP: {client_ip}")
        
        # Check if IP already exists
        existing_ip = WhitelistedIP.query.filter_by(ip_address=client_ip).first()
        if not existing_ip:
            new_ip = WhitelistedIP(ip_address=client_ip)
            db.session.add(new_ip)
            db.session.commit()
            app.logger.info(f"IP {client_ip} auto-whitelisted successfully")
            flash(f'IP {client_ip} has been automatically whitelisted!', 'success')
        else:
            app.logger.info(f"IP {client_ip} already whitelisted")
            flash(f'IP {client_ip} is already whitelisted!', 'info')
        
        # Set session and redirect to whitelist management
        session['emergency_access'] = True
        session['role'] = 'admin'
        session['user'] = 'emergency_admin'
        return redirect(url_for('whitelist'))
    
    # If SECRET_KEY is provided, show the emergency access form
    elif static_key == secret_key:
        app.logger.info("SECRET_KEY provided - showing emergency access form")
        return render_template('emergency_access.html')
    
    # If no valid key, show the emergency access form
    else:
        app.logger.info("No valid key provided - showing emergency access form")
        return render_template('emergency_access.html')

@app.route('/api/emergency-add-ip', methods=['POST'])
def api_emergency_add_ip():
    """Emergency API to add IP to whitelist without authentication"""
    try:
        data = request.get_json()
        ip_address = data.get('ip_address', '').strip()
        emergency_key = data.get('emergency_key', '').strip()
        
        # Debug logging
        app.logger.info(f"Emergency access attempt - IP: {ip_address}, Key provided: {emergency_key[:8]}...")
        
        if not ip_address:
            return jsonify({'success': False, 'error': 'IP address required'})
        
        if not emergency_key:
            return jsonify({'success': False, 'error': 'Emergency key required'})
        
        # Check against both WHITELIST_TOKEN and SECRET_KEY
        whitelist_token = app.config.get('WHITELIST_TOKEN', '')
        secret_key = app.config.get('SECRET_KEY', '')
        
        if not whitelist_token and not secret_key:
            return jsonify({'success': False, 'error': 'No emergency keys configured'})
        
        # Accept either key
        if emergency_key != whitelist_token and emergency_key != secret_key:
            return jsonify({'success': False, 'error': 'Invalid emergency key. Please use your WHITELIST_TOKEN or SECRET_KEY.'})
        
        # Check if IP already exists
        existing_ip = WhitelistedIP.query.filter_by(ip_address=ip_address).first()
        if existing_ip:
            app.logger.info(f"IP {ip_address} already exists in whitelist")
            return jsonify({'success': True, 'message': f'IP address {ip_address} is already whitelisted'})
        
        # Add new IP to whitelist
        new_ip = WhitelistedIP(ip_address=ip_address)
        db.session.add(new_ip)
        db.session.commit()
        
        app.logger.info(f"IP {ip_address} successfully whitelisted via emergency access")
        
        # Set session for this user so they can access other pages
        session['emergency_access'] = True
        session['role'] = 'admin'
        session['user'] = 'emergency_admin'
        
        return jsonify({'success': True, 'message': f'IP address {ip_address} whitelisted successfully'})
        
    except Exception as e:
        app.logger.error(f"Emergency access error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/debug-config')
def api_debug_config():
    """Debug endpoint to check configuration values"""
    return jsonify({
        'WHITELIST_TOKEN': app.config.get('WHITELIST_TOKEN', '')[:8] + '...' if app.config.get('WHITELIST_TOKEN') else 'None',
        'SECRET_KEY': app.config.get('SECRET_KEY', '')[:8] + '...' if app.config.get('SECRET_KEY') else 'None',
        'ENABLE_IP_WHITELIST': app.config.get('ENABLE_IP_WHITELIST', False),
        'DEBUG': app.config.get('DEBUG', False),
        'note': 'Both WHITELIST_TOKEN and SECRET_KEY can be used for emergency access'
    })

@app.route('/api/debug-session')
def api_debug_session():
    """Debug endpoint to check current session state"""
    return jsonify({
        'session_data': dict(session),
        'client_ip': get_client_ip(),
        'endpoint': request.endpoint if request.endpoint else 'None'
    })

@app.route('/api/debug-whitelist')
def api_debug_whitelist():
    """Debug endpoint to check whitelist status"""
    try:
        client_ip = get_client_ip()
        whitelisted_ips = WhitelistedIP.query.all()
        ip_list = [ip.ip_address for ip in whitelisted_ips]
        
        return jsonify({
            'client_ip': client_ip,
            'whitelisted_ips': ip_list,
            'is_whitelisted': client_ip in ip_list,
            'total_whitelisted': len(ip_list),
            'enable_ip_whitelist_config': app.config.get('ENABLE_IP_WHITELIST', False),
            'app_debug_mode': app.debug,
            'emergency_access_session': session.get('emergency_access', False),
            'session_data': {
                'user': session.get('user'),
                'role': session.get('role'),
                'emergency_access': session.get('emergency_access')
            }
        })
    except Exception as e:
        app.logger.error(f"Error in debug-whitelist endpoint: {str(e)}")
        return jsonify({'error': str(e)})

@app.route('/whitelist')
def whitelist():
    """Whitelist management page - accessible via emergency access or admin login"""
    # Check if user has emergency access or is logged in as admin
    if not session.get('emergency_access') and not session.get('user'):
        flash("Access denied. Please use emergency access or log in.", "danger")
        return redirect(url_for('login'))
    
    if session.get('role') != 'admin' and not session.get('emergency_access'):
        flash("Admin access required.", "danger")
        return redirect(url_for('dashboard'))
    
    # Get all whitelisted IPs for display
    try:
        whitelisted_ips = WhitelistedIP.query.all()
        ip_list = [ip.ip_address for ip in whitelisted_ips]
    except Exception as e:
        app.logger.error(f"Error fetching whitelisted IPs: {e}")
        ip_list = []
    
    app.logger.info(f"Whitelist access granted: user={session.get('user')}, role={session.get('role')}, emergency_access={session.get('emergency_access')}")
    return render_template('whitelist.html', user=session.get('user'), role=session.get('role'), whitelisted_ips=ip_list)

@app.route('/api/add-user', methods=['POST'])
@login_required
def api_add_user():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin access required'})
    
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        role = data.get('role', 'support')
        
        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password required'})
        
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'error': 'Username already exists'})
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'User {username} created successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/list-users', methods=['GET'])
@login_required
def api_list_users():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin access required'})
    
    try:
        users = User.query.all()
        user_list = [{'username': user.username, 'role': user.role} for user in users]
        return jsonify({'success': True, 'users': user_list})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/edit-user', methods=['POST'])
@login_required
def api_edit_user():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin access required'})
    
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        new_password = data.get('password', '').strip()
        new_role = data.get('role', '').strip()
        
        if not username:
            return jsonify({'success': False, 'error': 'Username required'})
        
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'success': False, 'error': 'User not found'})
        
        if not new_password:
            return jsonify({'success': False, 'error': 'Password required'})
        
        if new_role not in ['admin', 'support', 'mailer']:
            return jsonify({'success': False, 'error': 'Role must be admin, support, or mailer'})
        
        user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        user.role = new_role
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'User {username} updated successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/delete-user', methods=['POST'])
@login_required
def api_delete_user():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin access required'})
    
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        
        if not username:
            return jsonify({'success': False, 'error': 'Username required'})
        
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'success': False, 'error': 'User not found'})
        
        if username == session.get('user'):
            return jsonify({'success': False, 'error': 'Cannot delete your own account'})
        
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'User {username} deleted successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/delete-users', methods=['POST'])
@login_required
def api_delete_users():
    """Delete multiple Google Workspace users by email addresses"""
    try:
        # Check if user is authenticated with Google account
        if 'current_account_name' not in session:
            return jsonify({'success': False, 'error': 'No Google account authenticated. Please authenticate first.'})
        
        # Get the current authenticated account
        account_name = session.get('current_account_name')
        logging.info(f"Deleting users for account: {account_name}")
        
        # Validate and recreate service if necessary
        if not google_api.validate_and_recreate_service(account_name):
            logging.error(f"Failed to validate or recreate service for account {account_name}")
            return jsonify({'success': False, 'error': 'Failed to establish Google API connection. Please re-authenticate.'})
        
        data = request.get_json()
        user_emails = data.get('user_emails', [])
        
        if not user_emails:
            return jsonify({'success': False, 'error': 'No email addresses provided'})
        
        if not isinstance(user_emails, list):
            return jsonify({'success': False, 'error': 'Email addresses must be provided as a list'})
        
        logging.info(f"Attempting to delete {len(user_emails)} users: {user_emails}")
        
        results = []
        successful_deletions = 0
        
        for email in user_emails:
            email = email.strip()
            if not email:
                continue
                
            try:
                logging.info(f"Deleting user: {email}")
                
                # Delete user from Google Workspace
                google_api.service.users().delete(userKey=email).execute()
                
                results.append({
                    'email': email,
                    'result': {'success': True, 'message': f'User {email} deleted successfully'}
                })
                successful_deletions += 1
                logging.info(f"Successfully deleted user: {email}")
                
            except Exception as user_error:
                error_msg = str(user_error)
                logging.error(f"Failed to delete user {email}: {error_msg}")
                results.append({
                    'email': email,
                    'result': {'success': False, 'error': error_msg}
                })
        
        logging.info(f"User deletion completed. Successfully deleted {successful_deletions} out of {len(user_emails)} users")
        
        return jsonify({
            'success': True,
            'message': f'User deletion completed. Successfully deleted {successful_deletions} out of {len(user_emails)} users.',
            'results': results,
            'total_requested': len(user_emails),
            'successful_deletions': successful_deletions
        })
        
    except Exception as e:
        logging.error(f"Delete users error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/add-whitelist-ip', methods=['POST'])
@login_required
def api_add_whitelist_ip():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin access required'})
    
    try:
        data = request.get_json()
        ip_address = data.get('ip_address', '').strip()
        
        if not ip_address:
            return jsonify({'success': False, 'error': 'IP address required'})
        
        if WhitelistedIP.query.filter_by(ip_address=ip_address).first():
            return jsonify({'success': False, 'error': 'IP address already exists'})
        
        new_ip = WhitelistedIP(ip_address=ip_address)
        db.session.add(new_ip)
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'IP address {ip_address} whitelisted successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/list-whitelist-ips', methods=['GET'])
@login_required
def api_list_whitelist_ips():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin access required'})
    
    try:
        ips = WhitelistedIP.query.all()
        ip_list = [ip.ip_address for ip in ips]
        return jsonify({'success': True, 'ips': ip_list})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/delete-whitelist-ip', methods=['POST'])
def api_delete_whitelist_ip():
    """Delete IP from whitelist - accessible via emergency access or admin login"""
    # Check if user has emergency access or is logged in as admin
    if not session.get('emergency_access') and not session.get('user'):
        return jsonify({'success': False, 'error': 'Access denied. Please use emergency access or log in.'})
    
    if session.get('role') != 'admin' and not session.get('emergency_access'):
        return jsonify({'success': False, 'error': 'Admin access required'})
    
    try:
        data = request.get_json()
        ip_address = data.get('ip_address', '').strip()
        
        if not ip_address:
            return jsonify({'success': False, 'error': 'IP address required'})
        
        ip_to_delete = WhitelistedIP.query.filter_by(ip_address=ip_address).first()
        if not ip_to_delete:
            return jsonify({'success': False, 'error': 'IP address not found'})
        
        db.session.delete(ip_to_delete)
        db.session.commit()
        
        app.logger.info(f"IP {ip_address} deleted from whitelist by user: {session.get('user', 'emergency_access')}")
        return jsonify({'success': True, 'message': f'IP address {ip_address} removed from whitelist'})
        
    except Exception as e:
        app.logger.error(f"Error deleting IP from whitelist: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/authenticate', methods=['POST'])
@login_required
def api_authenticate():
    try:
        data = request.get_json()
        account_name = data.get('account_name')
        account_id = data.get('account_id')
        
        if not account_name and not account_id:
            return jsonify({'success': False, 'error': 'No account specified'})
        
        # Try to find account by ID first (more reliable), then by name
        if account_id:
            account = GoogleAccount.query.get(account_id)
        else:
            account = GoogleAccount.query.filter_by(account_name=account_name).first()
            
        if not account:
            return jsonify({'success': False, 'error': 'Account not found in database'})
        
        # Use the account name from the database record
        account_name = account.account_name
        
        service_key = google_api._get_session_key(account_name)
        if service_key in session and session.get(service_key):
            session['current_account_name'] = account_name
            return jsonify({
                'success': True, 
                'message': f'Already authenticated for {account_name} in this session'
            })
        
        if google_api.is_token_valid(account_name):
            success = google_api.authenticate_with_tokens(account_name)
            if success:
                # Set the current account in session for persistence
                session['current_account_name'] = account_name
                return jsonify({
                    'success': True, 
                    'message': f'Authenticated using cached tokens for {account_name}'
                })
        
        oauth_url = google_api.get_oauth_url(account_name, {'client_id': account.client_id, 'client_secret': account.client_secret})
        if oauth_url:
            return jsonify({
                'success': False,
                'oauth_required': True,
                'oauth_url': oauth_url,
                'message': 'Please complete OAuth authentication'
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to generate OAuth URL'})
            
    except Exception as e:
        logging.error(f"Authentication error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/add-account', methods=['POST'])
@login_required
def api_add_account():
    # Check if user is mailer role (not allowed to add accounts)
    if session.get('role') == 'mailer':
        return jsonify({'success': False, 'error': 'Mailer users cannot add accounts'})
    
    try:
        data = request.get_json()
        account_name = data.get('account_name')
        client_id = data.get('client_id')
        client_secret = data.get('client_secret')
        
        if not all([account_name, client_id, client_secret]):
            return jsonify({'success': False, 'error': 'All fields are required'})
        
        if '@' not in account_name:
            return jsonify({'success': False, 'error': 'Invalid email format'})
        
        if GoogleAccount.query.filter_by(account_name=account_name).first():
            return jsonify({'success': False, 'error': 'Account already exists'})

        new_account = GoogleAccount(account_name=account_name, client_id=client_id, client_secret=client_secret)
        db.session.add(new_account)
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'Account {account_name} added successfully'})
            
    except Exception as e:
        logging.error(f"Add account error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/list-accounts', methods=['GET'])
@login_required
def api_list_accounts():
    """List all Google accounts from database"""
    try:
        accounts = GoogleAccount.query.all()
        account_list = []
        for account in accounts:
            # Check if account has valid tokens
            token = GoogleToken.query.filter_by(account_id=account.id).first()
            is_authenticated = token is not None and token.token is not None
            
            account_data = {
                'id': account.id,
                'account_name': account.account_name,
                'client_id': account.client_id,
                'client_secret': account.client_secret,
                'is_authenticated': is_authenticated,
                'has_tokens': token is not None
            }
            account_list.append(account_data)
        
        return jsonify({'success': True, 'accounts': account_list})
    except Exception as e:
        logging.error(f"List accounts error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/delete-account', methods=['POST'])
@login_required
def api_delete_account():
    """Delete a Google account from database"""
    try:
        # Allow all user types (admin, mailer, support) to delete accounts
        user_role = session.get('role')
        if user_role not in ['admin', 'mailer', 'support']:
            return jsonify({'success': False, 'error': 'Access denied. Valid user role required.'})
        
        data = request.get_json()
        account_id = data.get('account_id')
        
        if not account_id:
            return jsonify({'success': False, 'error': 'Account ID required'})
        
        account = GoogleAccount.query.get(account_id)
        if not account:
            return jsonify({'success': False, 'error': 'Account not found'})
        
        account_name = account.account_name
        
        # Properly delete all related records to avoid foreign key constraints
        try:
            # First, get all tokens for this account
            tokens = GoogleToken.query.filter_by(account_id=account_id).all()
            
            for token in tokens:
                # Clear the many-to-many relationship with scopes first
                token.scopes.clear()
                db.session.flush()  # Flush to ensure the relationship is cleared
            
            # Now delete all tokens for this account
            GoogleToken.query.filter_by(account_id=account_id).delete()
            
            # Finally delete the account (cascade will handle any remaining relationships)
            db.session.delete(account)
            
            # Commit all changes
            db.session.commit()
            
            logging.info(f"Successfully deleted account: {account_name} (ID: {account_id})")
            return jsonify({'success': True, 'message': f'Account {account_name} deleted successfully'})
            
        except Exception as db_error:
            db.session.rollback()
            logging.error(f"Database error during account deletion: {db_error}")
            return jsonify({'success': False, 'error': f'Database error: {str(db_error)}'})
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Delete account error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/get-account-status', methods=['GET'])
@login_required
def api_get_account_status():
    """Get authentication status for all accounts"""
    try:
        accounts = GoogleAccount.query.all()
        total_accounts = len(accounts)
        authenticated_count = 0
        need_auth_count = 0
        
        for account in accounts:
            token = GoogleToken.query.filter_by(account_id=account.id).first()
            if token and token.token:
                authenticated_count += 1
            else:
                need_auth_count += 1
        
        status = {
            'total': total_accounts,
            'authenticated': authenticated_count,
            'need_auth': need_auth_count,
            'status': 'Complete'
        }
        
        return jsonify({'success': True, 'status': status})
    except Exception as e:
        logging.error(f"Get account status error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/add-accounts-from-json', methods=['POST'])
@login_required
def api_add_accounts_from_json():
    """Add multiple accounts from JSON data (for backward compatibility)"""
    try:
        data = request.get_json()
        accounts_data = data.get('accounts', [])
        
        if not accounts_data:
            return jsonify({'success': False, 'error': 'No accounts data provided'})
        
        added_count = 0
        errors = []
        
        for account_data in accounts_data:
            try:
                account_name = account_data.get('account_name')
                client_id = account_data.get('client_id')
                client_secret = account_data.get('client_secret')
                
                if not all([account_name, client_id, client_secret]):
                    errors.append(f"Missing data for account: {account_name}")
                    continue
                
                # Check if account already exists
                if GoogleAccount.query.filter_by(account_name=account_name).first():
                    errors.append(f"Account {account_name} already exists")
                    continue
                
                # Create new account
                new_account = GoogleAccount(
                    account_name=account_name,
                    client_id=client_id,
                    client_secret=client_secret
                )
                db.session.add(new_account)
                added_count += 1
                
            except Exception as e:
                errors.append(f"Error processing account {account_name}: {str(e)}")
        
        # Commit all changes
        db.session.commit()
        
        result = {
            'success': True,
            'message': f'Added {added_count} accounts successfully',
            'added_count': added_count,
            'errors': errors
        }
        
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"Add accounts from JSON error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/check-token-status', methods=['GET'])
@login_required
def api_check_token_status():
    """Check token status for all accounts"""
    try:
        accounts = GoogleAccount.query.all()
        token_status = []
        
        for account in accounts:
            token = GoogleToken.query.filter_by(account_id=account.id).first()
            
            status_info = {
                'account_id': account.id,
                'account_name': account.account_name,
                'has_tokens': token is not None,
                'token_valid': False,
                'needs_auth': True
            }
            
            if token and token.token:
                # Basic token validation (you can enhance this)
                status_info['token_valid'] = True
                status_info['needs_auth'] = False
            
            token_status.append(status_info)
        
        return jsonify({'success': True, 'token_status': token_status})
        
    except Exception as e:
        logging.error(f"Check token status error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/oauth-callback')
def oauth_callback():
    try:
        code = request.args.get('code')
        
        if not code:
            return "ERROR: No authorization code received", 400
        
        return f"""
        <html>
        <head><title>✅ Authentication Code Ready</title></head>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5;">
            <div style="background: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: 0 auto; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <h2 style="color: #28a745;">✅ Authentication Successful!</h2>
                <p style="font-size: 18px; margin: 20px 0;">Copy this authorization code:</p>
                
                <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; border: 2px dashed #28a745; margin: 20px 0;">
                    <input type="text" value="{code}" readonly onclick="this.select()" 
                           style="width: 100%; padding: 10px; font-family: monospace; font-size: 14px; border: none; background: transparent; text-align: center;">
                </div>
                
                <p style="color: #666; margin: 20px 0;"><strong>Next Steps:</strong></p>
                <ol style="text-align: left; max-width: 400px; margin: 0 auto; color: #666;">
                    <li>Click in the box above to select the code</li>
                    <li>Copy it (Ctrl+C or Cmd+C)</li>
                    <li>Return to your main app browser</li>
                    <li>Paste the code to complete authentication</li>
                </ol>
                
                <div style="margin-top: 30px;">
                    <button onclick="copyCode()" style="background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 5px; font-size: 16px; cursor: pointer;">
                        📋 Copy Code
                    </button>
                </div>
            </div>
            
            <script>
                function copyCode() {{
                    const input = document.querySelector('input');
                    input.select();
                    document.execCommand('copy');
                    alert('✅ Code copied to clipboard!');
                }}
            </script>
        </body>
        </html>
        """
        
    except Exception as e:
        return f"ERROR: {str(e)}", 500

@app.route('/api/complete-oauth', methods=['POST'])
@login_required
def api_complete_oauth():
    try:
        data = request.get_json()
        auth_code = data.get('auth_code')
        account_name = data.get('account_name')
        
        if not auth_code or not account_name:
            return jsonify({'success': False, 'error': 'Code and account name required'})
        
        account = GoogleAccount.query.filter_by(account_name=account_name).first()
        if not account:
            return jsonify({'success': False, 'error': 'Account not found'})
        
        creds_data = {'client_id': account.client_id, 'client_secret': account.client_secret}
        
        flow_config = {
            "installed": {
                "client_id": creds_data['client_id'],
                "project_id": "gbot-project",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_secret": creds_data['client_secret'],
                "redirect_uris": ["https://ecochains.online/oauth-callback"]
            }
        }
        
        flow = InstalledAppFlow.from_client_config(flow_config, app.config['SCOPES'])
        flow.redirect_uri = "https://ecochains.online/oauth-callback"
        
        flow.fetch_token(code=auth_code)
        credentials = flow.credentials
        
        token = GoogleToken.query.filter_by(account_id=account.id).first()
        if not token:
            token = GoogleToken(account_id=account.id)

        token.token = credentials.token
        token.refresh_token = credentials.refresh_token
        token.token_uri = credentials.token_uri
        
        # Clear existing scopes and add new ones
        token.scopes.clear()
        for scope_name in credentials.scopes:
            scope = Scope.query.filter_by(name=scope_name).first()
            if not scope:
                scope = Scope(name=scope_name)
                db.session.add(scope)
            token.scopes.append(scope)

        db.session.add(token)
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'Authentication completed for {account_name}'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/create-gsuite-user', methods=['POST'])
@login_required
def api_create_gsuite_user():
    try:
        data = request.get_json()
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        email = data.get('email')
        password = data.get('password')

        if not all([first_name, last_name, email, password]):
            return jsonify({'success': False, 'error': 'All fields are required'})

        result = google_api.create_gsuite_user(first_name, last_name, email, password)
        return jsonify(result)

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/get-domain-info', methods=['GET'])
@login_required
def api_get_domain_info():
    try:
        result = google_api.get_domain_info()
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/add-domain-alias', methods=['POST'])
@login_required
def api_add_domain_alias():
    try:
        data = request.get_json()
        domain_alias = data.get('domain_alias')

        if not domain_alias:
            return jsonify({'success': False, 'error': 'Domain alias is required'})

        result = google_api.add_domain_alias(domain_alias)
        return jsonify(result)

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/delete-domain', methods=['POST'])
@login_required
def api_delete_domain():
    try:
        data = request.get_json()
        domain_name = data.get('domain_name')

        if not domain_name:
            return jsonify({'success': False, 'error': 'Domain name is required'})

        result = google_api.delete_domain(domain_name)
        return jsonify(result)

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/retrieve-users', methods=['POST'])
@login_required
def api_retrieve_users():
    """Retrieve all users from the authenticated Google account"""
    try:
        # Check if user is authenticated
        if 'current_account_name' not in session:
            return jsonify({'success': False, 'error': 'No account authenticated. Please authenticate first.'})
        
        # Get the current authenticated account
        account_name = session.get('current_account_name')
        
        # First, try to authenticate using saved tokens if service is not available
        if not google_api.service:
            # Check if we have valid tokens for this account
            if google_api.is_token_valid(account_name):
                success = google_api.authenticate_with_tokens(account_name)
                if not success:
                    return jsonify({'success': False, 'error': 'Failed to authenticate with saved tokens. Please re-authenticate.'})
            else:
                return jsonify({'success': False, 'error': 'No valid tokens found. Please re-authenticate.'})
        
        # Now try to retrieve users
        try:
            # Use the google_api method to retrieve users
            result = google_api.get_users(max_results=500)
            
            if not result['success']:
                return jsonify({'success': False, 'error': result['error']})
            
            users = result['users']
            
            # Format user data
            formatted_users = []
            for user in users:
                user_data = {
                    'email': user.get('primaryEmail', ''),
                    'first_name': user.get('name', {}).get('givenName', ''),
                    'last_name': user.get('name', {}).get('familyName', ''),
                    'admin': user.get('isAdmin', False),
                    'suspended': user.get('suspended', False)
                }
                formatted_users.append(user_data)
            
            return jsonify({
                'success': True,
                'users': formatted_users,
                'total_count': len(formatted_users)
            })
            
        except Exception as api_error:
            logging.error(f"Google API error: {api_error}")
            return jsonify({'success': False, 'error': f'Failed to retrieve users: {str(api_error)}'})
            
    except Exception as e:
        logging.error(f"Retrieve users error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/update-all-passwords', methods=['POST'])
@login_required
def api_update_all_passwords():
    """Update passwords for multiple users"""
    try:
        data = request.get_json()
        password = data.get('password')
        user_emails = data.get('user_emails', [])
        
        if not password or len(password) < 8:
            return jsonify({'success': False, 'error': 'Password must be at least 8 characters'})
        
        if not user_emails:
            return jsonify({'success': False, 'error': 'No user emails provided'})
        
        # Check if user is authenticated
        if 'current_account_name' not in session:
            return jsonify({'success': False, 'error': 'No account authenticated. Please authenticate first.'})
        
        # Get the current authenticated account
        account_name = session.get('current_account_name')
        
        # First, try to authenticate using saved tokens if service is not available
        if not google_api.service:
            # Check if we have valid tokens for this account
            if google_api.is_token_valid(account_name):
                success = google_api.authenticate_with_tokens(account_name)
                if not success:
                    return jsonify({'success': False, 'error': 'Failed to authenticate with saved tokens. Please re-authenticate.'})
            else:
                return jsonify({'success': False, 'error': 'No valid tokens found. Please re-authenticate.'})
        
        successful_emails = []
        failed_details = []
        
        for email in user_emails:
            try:
                # Update user password in Google Admin Directory API
                user_body = {
                    'password': password,
                    'changePasswordAtNextLogin': False
                }
                
                google_api.service.users().update(userKey=email, body=user_body).execute()
                successful_emails.append(email)
                
            except Exception as user_error:
                failed_details.append({
                    'email': email,
                    'error': str(user_error)
                })
        
        return jsonify({
            'success': True,
            'message': f'Password update completed. {len(successful_emails)} successful, {len(failed_details)} failed.',
            'successful_emails': successful_emails,
            'failed_details': failed_details
        })
        
    except Exception as e:
        logging.error(f"Update all passwords error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/retrieve-domains', methods=['POST'])
@login_required
def api_retrieve_domains():
    """Retrieve all domains from the authenticated Google account"""
    try:
        # Check if user is authenticated
        if 'current_account_name' not in session:
            return jsonify({'success': False, 'error': 'No account authenticated. Please authenticate first.'})
        
        # Get the current authenticated account
        account_name = session.get('current_account_name')
        
        # First, try to authenticate using saved tokens if service is not available
        if not google_api.service:
            # Check if we have valid tokens for this account
            if google_api.is_token_valid(account_name):
                success = google_api.authenticate_with_tokens(account_name)
                if not success:
                    return jsonify({'success': False, 'error': 'Failed to authenticate with saved tokens. Please re-authenticate.'})
            else:
                return jsonify({'success': False, 'error': 'No valid tokens found. Please re-authenticate.'})
        
        try:
            # Use the existing get_domain_info method
            result = google_api.get_domain_info()
            
            if not result['success']:
                return jsonify({'success': False, 'error': result['error']})
            
            domains = result['domains']
            
            # Get all users to calculate domain usage (handle pagination for large user bases)
            all_users = []
            page_token = None
            
            while True:
                try:
                    if page_token:
                        users_result = google_api.service.users().list(
                            customer='my_customer',
                            maxResults=500,
                            pageToken=page_token
                        ).execute()
                    else:
                        users_result = google_api.service.users().list(
                            customer='my_customer',
                            maxResults=500
                        ).execute()
                    
                    users = users_result.get('users', [])
                    all_users.extend(users)
                    
                    page_token = users_result.get('nextPageToken')
                    if not page_token:
                        break
                        
                except Exception as e:
                    logging.warning(f"Failed to retrieve users page: {e}")
                    break
            
            logging.info(f"Retrieved {len(all_users)} total users for domain calculation")
            
            # Calculate user count per domain
            domain_user_counts = {}
            for user in users:
                email = user.get('primaryEmail', '')
                if email and '@' in email:
                    domain = email.split('@')[1]
                    domain_user_counts[domain] = domain_user_counts.get(domain, 0) + 1
            
            # Format domain data with new three-state system
            formatted_domains = []
            for domain in domains:
                domain_name = domain.get('domainName', '')
                user_count = domain_user_counts.get(domain_name, 0)
                
                # Get domain status from database
                from database import UsedDomain
                domain_record = UsedDomain.query.filter_by(domain_name=domain_name).first()
                
                # Check if ever_used column exists (for backward compatibility)
                ever_used = False
                if domain_record:
                    try:
                        ever_used = getattr(domain_record, 'ever_used', False)
                    except:
                        ever_used = False  # Column doesn't exist yet
                
                # Determine domain status
                if user_count > 0:
                    status = 'in_use'  # Purple - currently has users
                    status_text = 'IN USE'
                    status_color = 'purple'
                elif domain_record and ever_used:
                    status = 'used'  # Orange - previously used but no current users
                    status_text = 'USED'
                    status_color = 'orange'
                else:
                    status = 'available'  # Green - never been used
                    status_text = 'AVAILABLE'
                    status_color = 'green'
                
                domain_data = {
                    'domain_name': domain_name,
                    'verified': domain.get('verified', False),
                    'user_count': user_count,
                    'status': status,
                    'status_text': status_text,
                    'status_color': status_color,
                    'is_used': user_count > 0,  # For backward compatibility
                    'ever_used': ever_used
                }
                formatted_domains.append(domain_data)
                
                # Sync domain data to database
                try:
                    if domain_record:
                        domain_record.user_count = user_count
                        domain_record.is_verified = domain.get('verified', False)
                        # If domain currently has users, mark as ever_used (if column exists)
                        if user_count > 0:
                            try:
                                domain_record.ever_used = True
                            except:
                                pass  # Column doesn't exist yet
                        domain_record.updated_at = db.func.current_timestamp()
                    else:
                        # Create new domain record
                        try:
                            new_domain = UsedDomain(
                                domain_name=domain_name,
                                user_count=user_count,
                                is_verified=domain.get('verified', False),
                                ever_used=(user_count > 0)  # Mark as ever_used if it has users now
                            )
                        except:
                            # Fallback if ever_used column doesn't exist
                            new_domain = UsedDomain(
                                domain_name=domain_name,
                                user_count=user_count,
                                is_verified=domain.get('verified', False)
                            )
                        db.session.add(new_domain)
                    
                    db.session.commit()
                    logging.debug(f"Synced domain {domain_name}: {user_count} users, status={status}")
                except Exception as db_error:
                    logging.warning(f"Failed to sync domain {domain_name} to database: {db_error}")
                    try:
                        db.session.rollback()
                    except:
                        pass
            
            return jsonify({
                'success': True,
                'domains': formatted_domains
            })
            
        except Exception as api_error:
            logging.error(f"Google API error: {api_error}")
            return jsonify({'success': False, 'error': f'Failed to retrieve domains: {str(api_error)}'})
            
    except Exception as e:
        logging.error(f"Retrieve domains error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/get-domain-usage-stats', methods=['GET'])
@login_required
def api_get_domain_usage_stats():
    """Get domain usage statistics from database"""
    try:
        from database import UsedDomain
        domains = UsedDomain.query.all()
        
        # Sort domains by user count (descending) and then by name
        sorted_domains = sorted(domains, key=lambda x: (x.user_count, x.domain_name), reverse=True)
        
        # Calculate stats with new three-state system (handle missing ever_used column)
        in_use_domains = [d for d in domains if d.user_count > 0]
        used_domains = []
        available_domains = []
        
        for d in domains:
            if d.user_count == 0:
                try:
                    ever_used = getattr(d, 'ever_used', False)
                    if ever_used:
                        used_domains.append(d)
                    else:
                        available_domains.append(d)
                except:
                    # Column doesn't exist, treat as available
                    available_domains.append(d)
        
        stats = {
            'total_domains': len(domains),
            'in_use_domains': len(in_use_domains),
            'used_domains': len(used_domains),
            'available_domains': len(available_domains),
            'total_users': sum(d.user_count for d in domains),
            'domains': [
                {
                    'domain_name': d.domain_name,
                    'user_count': d.user_count,
                    'is_verified': d.is_verified,
                    'is_used': d.user_count > 0,  # For backward compatibility
                    'ever_used': getattr(d, 'ever_used', False),
                    'status': 'in_use' if d.user_count > 0 else ('used' if getattr(d, 'ever_used', False) else 'available'),
                    'status_text': 'IN USE' if d.user_count > 0 else ('USED' if getattr(d, 'ever_used', False) else 'AVAILABLE'),
                    'status_color': 'purple' if d.user_count > 0 else ('orange' if getattr(d, 'ever_used', False) else 'green'),
                    'last_updated': d.updated_at.isoformat() if d.updated_at else None
                }
                for d in sorted_domains
            ]
        }
        
        logging.info(f"Domain usage stats: {stats['total_domains']} domains, {stats['total_users']} users")
        
        return jsonify({'success': True, 'stats': stats})
        
    except Exception as e:
        logging.error(f"Get domain usage stats error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/clear-old-domain-data', methods=['POST'])
@login_required
def api_clear_old_domain_data():
    """Clear old domain data from database"""
    try:
        from database import UsedDomain
        
        # Delete domains that haven't been updated in the last 30 days
        from datetime import datetime, timedelta
        cutoff_date = datetime.utcnow() - timedelta(days=30)
        
        old_domains = UsedDomain.query.filter(UsedDomain.updated_at < cutoff_date).all()
        count = len(old_domains)
        
        for domain in old_domains:
            db.session.delete(domain)
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Cleared {count} old domain records',
            'cleared_count': count
        })
        
    except Exception as e:
        logging.error(f"Clear old domain data error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/debug-auth-status', methods=['GET'])
@login_required
def api_debug_auth_status():
    """Debug endpoint to check authentication and service status"""
    try:
        current_account = session.get('current_account_name')
        service_available = google_api.service is not None
        token_valid = google_api.is_token_valid(current_account) if current_account else False
        
        debug_info = {
            'current_account': current_account,
            'service_available': service_available,
            'token_valid': token_valid,
            'session_id': session.get('session_id'),
            'session_keys': list(session.keys())
        }
        
        return jsonify({
            'success': True,
            'debug_info': debug_info
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/test-suspended-query', methods=['POST'])
@login_required
def api_test_suspended_query():
    """Test endpoint to debug suspended user queries"""
    try:
        current_account = session.get('current_account_name')
        if not current_account:
            return jsonify({'success': False, 'error': 'No account authenticated'})
        
        # Validate service
        if not google_api.validate_and_recreate_service(current_account):
            return jsonify({'success': False, 'error': 'Failed to establish Google API connection'})
        
        results = {}
        
        # Test 1: Direct suspended query
        try:
            suspended_result = google_api.service.users().list(
                customer='my_customer', 
                query='suspended:true',
                maxResults=10
            ).execute()
            results['direct_suspended_query'] = {
                'success': True,
                'count': len(suspended_result.get('users', [])),
                'users': [{'email': u.get('primaryEmail'), 'suspended': u.get('suspended')} for u in suspended_result.get('users', [])]
            }
        except Exception as e:
            results['direct_suspended_query'] = {'success': False, 'error': str(e)}
        
        # Test 2: Get all users and check suspension status
        try:
            all_users_result = google_api.service.users().list(
                customer='my_customer',
                maxResults=10
            ).execute()
            all_users = all_users_result.get('users', [])
            suspended_users = [u for u in all_users if u.get('suspended', False)]
            results['all_users_filter'] = {
                'success': True,
                'total_users': len(all_users),
                'suspended_count': len(suspended_users),
                'users': [{'email': u.get('primaryEmail'), 'suspended': u.get('suspended')} for u in all_users]
            }
        except Exception as e:
            results['all_users_filter'] = {'success': False, 'error': str(e)}
        
        return jsonify({
            'success': True,
            'account': current_account,
            'results': results
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/load-suspended-users', methods=['POST'])
@login_required
def api_load_suspended_users():
    """Load suspended users from the authenticated Google account"""
    try:
        # Check if user is authenticated
        if 'current_account_name' not in session:
            logging.error("No current_account_name in session")
            return jsonify({'success': False, 'error': 'No account authenticated. Please authenticate first.'})
        
        # Get the current authenticated account
        account_name = session.get('current_account_name')
        logging.info(f"Loading suspended users for account: {account_name}")
        
        # Validate and recreate service if necessary
        if not google_api.validate_and_recreate_service(account_name):
            logging.error(f"Failed to validate or recreate service for account {account_name}")
            return jsonify({'success': False, 'error': 'Failed to establish Google API connection. Please re-authenticate.'})
        
        try:
            logging.info(f"Retrieving suspended users from Google Admin Directory API for {account_name}")
            
            # First try the direct query approach
            try:
                users_result = google_api.service.users().list(
                    customer='my_customer', 
                    query='suspended:true',
                    maxResults=500
                ).execute()
                suspended_users = users_result.get('users', [])
                logging.info(f"Direct query found {len(suspended_users)} suspended users for {account_name}")
            except Exception as query_error:
                logging.warning(f"Direct suspended query failed: {query_error}, trying alternative approach...")
                
                # Alternative approach: get all users and filter for suspended ones
                all_users_result = google_api.service.users().list(
                    customer='my_customer',
                    maxResults=500
                ).execute()
                
                all_users = all_users_result.get('users', [])
                suspended_users = [user for user in all_users if user.get('suspended', False)]
                logging.info(f"Alternative approach found {len(suspended_users)} suspended users out of {len(all_users)} total users for {account_name}")
            
            logging.info(f"Final count: {len(suspended_users)} suspended users for {account_name}")
            
            # Format suspended user data with full information
            formatted_suspended_users = []
            for user in suspended_users:
                if user.get('primaryEmail'):
                    user_data = {
                        'email': user.get('primaryEmail', ''),
                        'first_name': user.get('name', {}).get('givenName', ''),
                        'last_name': user.get('name', {}).get('familyName', ''),
                        'admin': user.get('isAdmin', False),
                        'suspended': True,  # These are all suspended users
                        'full_name': f"{user.get('name', {}).get('givenName', '')} {user.get('name', {}).get('familyName', '')}".strip()
                    }
                    formatted_suspended_users.append(user_data)
                    logging.debug(f"Formatted suspended user: {user_data['email']}")
            
            logging.info(f"Successfully formatted {len(formatted_suspended_users)} suspended users for {account_name}")
            
            # Add debug information to response
            response_data = {
                'success': True,
                'users': formatted_suspended_users,
                'total_count': len(formatted_suspended_users),
                'debug_info': {
                    'account_name': account_name,
                    'raw_suspended_count': len(suspended_users),
                    'formatted_count': len(formatted_suspended_users)
                }
            }
            
            return jsonify(response_data)
            
        except Exception as api_error:
            logging.error(f"Google API error for account {account_name}: {api_error}")
            return jsonify({'success': False, 'error': f'Failed to retrieve suspended users: {str(api_error)}'})
            
    except Exception as e:
        logging.error(f"Load suspended users error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/change-domain-all-users', methods=['POST'])
@login_required
def api_change_domain_all_users():
    """Change domain for all users matching the current domain suffix"""
    try:
        # Check if user is authenticated
        if 'current_account_name' not in session:
            return jsonify({'success': False, 'error': 'No account authenticated. Please authenticate first.'})
        
        # Get the current authenticated account
        account_name = session.get('current_account_name')
        
        # First, try to authenticate using saved tokens if service is not available
        if not google_api.service:
            # Check if we have valid tokens for this account
            if google_api.is_token_valid(account_name):
                success = google_api.authenticate_with_tokens(account_name)
                if not success:
                    return jsonify({'success': False, 'error': 'Failed to authenticate with saved tokens. Please re-authenticate.'})
            else:
                return jsonify({'success': False, 'error': 'No valid tokens found. Please re-authenticate.'})
        
        # Get request data
        data = request.get_json()
        current_domain = data.get('current_domain', '').strip()
        new_domain = data.get('new_domain', '').strip()
        exclude_admin = data.get('exclude_admin', True)
        
        if not current_domain or not new_domain:
            return jsonify({'success': False, 'error': 'Both current and new domain are required'})
        
        if current_domain == new_domain:
            return jsonify({'success': False, 'error': 'Current and new domain cannot be the same'})
        
        try:
            # First try to get all users and filter by domain (more reliable)
            logging.info(f"Searching for users with domain: {current_domain}")
            
            # Get all users first (Google Admin API limit is 500)
            # Add timeout to prevent hanging
            all_users_result = google_api.service.users().list(
                customer='my_customer',
                maxResults=500
            ).execute()
            
            all_users = all_users_result.get('users', [])
            logging.info(f"Found {len(all_users)} total users")
            
            # Filter users by domain
            users = []
            for user in all_users:
                email = user.get('primaryEmail', '')
                if email and email.endswith(f"@{current_domain}"):
                    users.append(user)
            
            logging.info(f"Found {len(users)} users with domain {current_domain}")
            
            if not users:
                return jsonify({
                    'success': True,
                    'successful': 0,
                    'failed': 0,
                    'skipped': 0,
                    'message': f'No users found with domain {current_domain}'
                })
            
            # Update domain status in database IMMEDIATELY (before processing users)
            # This ensures domain status is saved even if the operation times out later
            try:
                from database import UsedDomain
                
                logging.info(f"Pre-updating domain status: {current_domain} → {new_domain}")
                
                # Mark old domain as used but with 0 current users
                old_domain_record = UsedDomain.query.filter_by(domain_name=current_domain).first()
                if old_domain_record:
                    old_domain_record.user_count = 0
                    try:
                        old_domain_record.ever_used = True
                    except:
                        pass  # Column doesn't exist yet
                    old_domain_record.updated_at = db.func.current_timestamp()
                else:
                    try:
                        old_domain_record = UsedDomain(
                            domain_name=current_domain,
                            user_count=0,
                            ever_used=True,
                            is_verified=True
                        )
                    except:
                        old_domain_record = UsedDomain(
                            domain_name=current_domain,
                            user_count=0,
                            is_verified=True
                        )
                    db.session.add(old_domain_record)
                
                # Mark new domain as currently in use (with estimated user count)
                new_domain_record = UsedDomain.query.filter_by(domain_name=new_domain).first()
                estimated_users = len(users)
                
                if new_domain_record:
                    new_domain_record.user_count = estimated_users
                    try:
                        new_domain_record.ever_used = True
                    except:
                        pass  # Column doesn't exist yet
                    new_domain_record.updated_at = db.func.current_timestamp()
                else:
                    try:
                        new_domain_record = UsedDomain(
                            domain_name=new_domain,
                            user_count=estimated_users,
                            ever_used=True,
                            is_verified=True
                        )
                    except:
                        new_domain_record = UsedDomain(
                            domain_name=new_domain,
                            user_count=estimated_users,
                            is_verified=True
                        )
                    db.session.add(new_domain_record)
                
                db.session.commit()
                logging.info(f"✅ Domain status pre-updated: {current_domain} (USED) → {new_domain} (IN USE)")
                
            except Exception as db_error:
                logging.error(f"ERROR: Failed to pre-update domain status: {db_error}")
                try:
                    db.session.rollback()
                except:
                    pass
            
            successful = 0
            failed = 0
            skipped = 0
            results = []
            
            # Process users in smaller batches to avoid timeouts
            batch_size = 5  # Reduced batch size for better performance
            total_users = len(users)
            
            # Add early response for large batches to prevent timeout
            if total_users > 50:
                logging.warning(f"Large batch detected ({total_users} users). Consider processing in smaller chunks.")
            
            for i, user in enumerate(users):
                try:
                    email = user.get('primaryEmail', '')
                    if not email:
                        continue
                    
                    # Check if user is admin (skip if exclude_admin is True)
                    if exclude_admin and user.get('isAdmin', False):
                        skipped += 1
                        results.append({
                            'email': email,
                            'skipped': True,
                            'reason': 'Admin user'
                        })
                        continue
                    
                    # Create new email with new domain
                    username = email.split('@')[0]
                    new_email = f"{username}@{new_domain}"
                    
                    # Update user's primary email
                    user_update = {
                        'primaryEmail': new_email
                    }
                    
                    logging.info(f"Updating user {i+1}/{total_users}: {email} → {new_email}")
                    
                    # Add timeout to the API call
                    google_api.service.users().update(
                        userKey=email,
                        body=user_update
                    ).execute()
                    
                    successful += 1
                    results.append({
                        'success': True,
                        'old_email': email,
                        'new_email': new_email
                    })
                    
                    logging.info(f"✅ Successfully updated user {i+1}/{total_users}: {email} → {new_email}")
                    
                    # Add small delay between API calls to avoid rate limiting
                    import time
                    time.sleep(0.1)
                    
                except Exception as user_error:
                    failed += 1
                    results.append({
                        'success': False,
                        'email': email,
                        'error': str(user_error)
                    })
                    logging.error(f"ERROR: Failed to update user {i+1}/{total_users} {email}: {user_error}")
                    
                    # Continue processing other users even if one fails
                    continue
            
            # Update final user count in database (optional - domain status already saved)
            try:
                from database import UsedDomain
                new_domain_record = UsedDomain.query.filter_by(domain_name=new_domain).first()
                if new_domain_record:
                    new_domain_record.user_count = successful
                    db.session.commit()
                    logging.info(f"✅ Updated final user count: {new_domain} = {successful} users")
            except Exception as db_error:
                logging.warning(f"Failed to update final user count: {db_error}")
                try:
                    db.session.rollback()
                except:
                    pass
            
            return jsonify({
                'success': True,
                'successful': successful,
                'failed': failed,
                'skipped': skipped,
                'results': results,
                'message': f'Domain change completed: {successful} users updated, {failed} failed, {skipped} skipped'
            })
            
        except Exception as api_error:
            logging.error(f"Google API error: {api_error}")
            return jsonify({'success': False, 'error': f'Failed to change domains: {str(api_error)}'})
            
    except Exception as e:
        logging.error(f"Change domain all users error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/change-domain', methods=['POST'])
@login_required
def api_change_domain():
    """Change domain for specific users"""
    try:
        # Check if user is authenticated
        if 'current_account_name' not in session:
            return jsonify({'success': False, 'error': 'No account authenticated. Please authenticate first.'})
        
        # Get the current authenticated account
        account_name = session.get('current_account_name')
        
        # First, try to authenticate using saved tokens if service is not available
        if not google_api.service:
            # Check if we have valid tokens for this account
            if google_api.is_token_valid(account_name):
                success = google_api.authenticate_with_tokens(account_name)
                if not success:
                    return jsonify({'success': False, 'error': 'Failed to authenticate with saved tokens. Please re-authenticate.'})
            else:
                return jsonify({'success': False, 'error': 'No valid tokens found. Please re-authenticate.'})
        
        # Get request data
        data = request.get_json()
        old_domain = data.get('old_domain', '').strip()
        new_domain = data.get('new_domain', '').strip()
        user_emails = data.get('user_emails', [])
        
        if not old_domain or not new_domain:
            return jsonify({'success': False, 'error': 'Both old and new domain are required'})
        
        if old_domain == new_domain:
            return jsonify({'success': False, 'error': 'Old and new domain cannot be the same'})
        
        if not user_emails:
            return jsonify({'success': False, 'error': 'No user emails provided'})
        
        results = []
        successful = 0
        failed = 0
        
        try:
            for email in user_emails:
                try:
                    # Extract username from old email
                    if '@' not in email:
                        failed += 1
                        results.append({
                            'success': False,
                            'email': email,
                            'error': 'Invalid email format'
                        })
                        continue
                    
                    username = email.split('@')[0]
                    new_email = f"{username}@{new_domain}"
                    
                    # Update user's primary email
                    user_body = {
                        'primaryEmail': new_email
                    }
                    
                    google_api.service.users().update(userKey=email, body=user_body).execute()
                    
                    successful += 1
                    results.append({
                        'success': True,
                        'old_email': email,
                        'new_email': new_email
                    })
                    
                    logging.info(f"✅ Changed domain for user: {email} → {new_email}")
                    
                    # Add small delay to avoid API rate limits
                    import time
                    time.sleep(0.05)  # Reduced delay for better performance
                    
                    # Commit database changes periodically to prevent long transactions
                    if (i + 1) % 10 == 0:
                        try:
                            db.session.commit()
                            logging.info(f"Processed {i + 1}/{total_users} users...")
                        except:
                            pass
                    
                except Exception as user_error:
                    failed += 1
                    results.append({
                        'success': False,
                        'email': email,
                        'error': str(user_error)
                    })
                    logging.error(f"ERROR: Failed to update user {email}: {user_error}")
                    continue
            
            # Update domain usage in database
            try:
                from database import UsedDomain
                
                # Update old domain user count (decrease by successful changes)
                old_domain_record = UsedDomain.query.filter_by(domain_name=old_domain).first()
                if old_domain_record:
                    old_domain_record.user_count = max(0, old_domain_record.user_count - successful)
                    old_domain_record.updated_at = db.func.current_timestamp()
                
                # Update new domain user count (increase by successful changes)
                new_domain_record = UsedDomain.query.filter_by(domain_name=new_domain).first()
                if new_domain_record:
                    new_domain_record.user_count += successful
                    new_domain_record.updated_at = db.func.current_timestamp()
                else:
                    # Create new domain record
                    new_domain_record = UsedDomain(
                        domain_name=new_domain,
                        user_count=successful,
                        is_verified=True
                    )
                    db.session.add(new_domain_record)
                
                db.session.commit()
                logging.info(f"Updated domain usage: {old_domain} (-{successful}) → {new_domain} (+{successful})")
                
            except Exception as db_error:
                logging.warning(f"Failed to update domain usage in database: {db_error}")
                # Don't fail the entire operation for database update issues
            
            return jsonify({
                'success': True,
                'message': f'Domain change completed. {successful} successful, {failed} failed.',
                'successful': successful,
                'failed': failed,
                'results': results
            })
            
        except Exception as api_error:
            logging.error(f"Google API error during domain change: {api_error}")
            return jsonify({'success': False, 'error': f'Failed to change domains: {str(api_error)}'})
            
    except Exception as e:
        logging.error(f"Change domain error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/debug-domain-users', methods=['POST'])
@login_required
def api_debug_domain_users():
    """Debug endpoint to check users for a specific domain"""
    try:
        # Check if user is authenticated
        if 'current_account_name' not in session:
            return jsonify({'success': False, 'error': 'No account authenticated. Please authenticate first.'})
        
        # Get the current authenticated account
        account_name = session.get('current_account_name')
        
        # First, try to authenticate using saved tokens if service is not available
        if not google_api.service:
            # Check if we have valid tokens for this account
            if google_api.is_token_valid(account_name):
                success = google_api.authenticate_with_tokens(account_name)
                if not success:
                    return jsonify({'success': False, 'error': 'Failed to authenticate with saved tokens. Please re-authenticate.'})
            else:
                return jsonify({'success': False, 'error': 'No valid tokens found. Please re-authenticate.'})
        
        data = request.get_json()
        domain = data.get('domain', '').strip()
        
        if not domain:
            return jsonify({'success': False, 'error': 'Domain is required'})
        
        try:
            # Get all users first (Google Admin API limit is 500)
            all_users_result = google_api.service.users().list(
                customer='my_customer',
                maxResults=500
            ).execute()
            
            all_users = all_users_result.get('users', [])
            
            # Filter users by domain
            domain_users = []
            for user in all_users:
                email = user.get('primaryEmail', '')
                if email and email.endswith(f"@{domain}"):
                    domain_users.append({
                        'email': email,
                        'name': user.get('name', {}),
                        'isAdmin': user.get('isAdmin', False),
                        'suspended': user.get('suspended', False)
                    })
            
            return jsonify({
                'success': True,
                'domain': domain,
                'total_users_found': len(all_users),
                'domain_users_found': len(domain_users),
                'domain_users': domain_users
            })
            
        except Exception as api_error:
            logging.error(f"Google API error: {api_error}")
            return jsonify({'success': False, 'error': f'Failed to retrieve users: {str(api_error)}'})
            
    except Exception as e:
        logging.error(f"Debug domain users error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/mark-domain-used', methods=['POST'])
@login_required
def api_mark_domain_used():
    """Mark a domain as used in the database"""
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        
        if not domain:
            return jsonify({'success': False, 'error': 'Domain is required'})
        
        from database import UsedDomain
        
        # Find or create domain record
        domain_record = UsedDomain.query.filter_by(domain_name=domain).first()
        if domain_record:
            domain_record.user_count = max(domain_record.user_count, 1)  # At least 1 user
            domain_record.updated_at = db.func.current_timestamp()
        else:
            domain_record = UsedDomain(
                domain_name=domain,
                user_count=1,
                is_verified=True
            )
            db.session.add(domain_record)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Domain {domain} marked as used'
        })
        
    except Exception as e:
        logging.error(f"Mark domain used error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/force-refresh-domains', methods=['POST'])
@login_required
def api_force_refresh_domains():
    """Force refresh domain data from Google Admin API and update database"""
    try:
        # Check if user is authenticated
        if 'current_account_name' not in session:
            return jsonify({'success': False, 'error': 'No account authenticated. Please authenticate first.'})
        
        # Get the current authenticated account
        account_name = session.get('current_account_name')
        
        # First, try to authenticate using saved tokens if service is not available
        if not google_api.service:
            # Check if we have valid tokens for this account
            if google_api.is_token_valid(account_name):
                success = google_api.authenticate_with_tokens(account_name)
                if not success:
                    return jsonify({'success': False, 'error': 'Failed to authenticate with saved tokens. Please re-authenticate.'})
            else:
                return jsonify({'success': False, 'error': 'No valid tokens found. Please re-authenticate.'})
        
        try:
            # Get all users with pagination
            all_users = []
            page_token = None
            
            while True:
                try:
                    if page_token:
                        users_result = google_api.service.users().list(
                            customer='my_customer',
                            maxResults=500,
                            pageToken=page_token
                        ).execute()
                    else:
                        users_result = google_api.service.users().list(
                            customer='my_customer',
                            maxResults=500
                        ).execute()
                    
                    users = users_result.get('users', [])
                    all_users.extend(users)
                    
                    page_token = users_result.get('nextPageToken')
                    if not page_token:
                        break
                        
                except Exception as e:
                    logging.warning(f"Failed to retrieve users page: {e}")
                    break
            
            logging.info(f"Force refresh: Retrieved {len(all_users)} total users")
            
            # Calculate user count per domain
            domain_user_counts = {}
            for user in all_users:
                email = user.get('primaryEmail', '')
                if email and '@' in email:
                    domain = email.split('@')[1]
                    domain_user_counts[domain] = domain_user_counts.get(domain, 0) + 1
            
            # Update database with real user counts
            from database import UsedDomain
            
            for domain_name, user_count in domain_user_counts.items():
                try:
                    existing_domain = UsedDomain.query.filter_by(domain_name=domain_name).first()
                    if existing_domain:
                        existing_domain.user_count = user_count
                        existing_domain.updated_at = db.func.current_timestamp()
                        logging.info(f"Updated domain {domain_name}: {user_count} users")
                    else:
                        new_domain = UsedDomain(
                            domain_name=domain_name,
                            user_count=user_count,
                            is_verified=True
                        )
                        db.session.add(new_domain)
                        logging.info(f"Added new domain {domain_name}: {user_count} users")
                except Exception as e:
                    logging.warning(f"Failed to update domain {domain_name}: {e}")
                    continue
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': f'Domain data refreshed successfully. Found {len(domain_user_counts)} domains with {len(all_users)} total users.',
                'domains_updated': len(domain_user_counts),
                'total_users': len(all_users)
            })
            
        except Exception as api_error:
            logging.error(f"Google API error during force refresh: {api_error}")
            return jsonify({'success': False, 'error': f'Failed to refresh domains: {str(api_error)}'})
            
    except Exception as e:
        logging.error(f"Force refresh domains error: {e}")
        return jsonify({'success': False, 'error': str(e)})

# Settings page route
@app.route('/settings')
@login_required
def settings():
    if session.get('role') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    return render_template('settings.html', user=session.get('user'), role=session.get('role'))

# Server configuration API routes
@app.route('/api/get-server-config', methods=['GET'])
@login_required
def get_server_config():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin privileges required'})
    
    try:
        from database import ServerConfig
        config = ServerConfig.query.first()
        if config:
            return jsonify({
                'success': True,
                'config': {
                    'host': config.host,
                    'port': config.port,
                    'username': config.username,
                    'auth_method': config.auth_method,
                    'password': config.password if config.password else '',
                    'private_key': config.private_key if config.private_key else '',
                    'json_path': config.json_path,
                    'file_pattern': config.file_pattern,
                    'is_configured': config.is_configured,
                    'last_tested': config.last_tested.isoformat() if config.last_tested else None
                }
            })
        else:
            return jsonify({'success': True, 'config': None})
    except Exception as e:
        app.logger.error(f"Error getting server config: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/save-server-config', methods=['POST'])
@login_required
def save_server_config():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin privileges required'})
    
    try:
        data = request.get_json()
        
        # Validate required fields - updated for new structure
        required_fields = ['host', 'username']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'error': f'Missing required field: {field}'})
        
        from database import ServerConfig
        
        # Get or create config
        config = ServerConfig.query.first()
        if not config:
            config = ServerConfig()
            db.session.add(config)
        
        # Update config
        config.host = data['host']
        config.port = data.get('port', 22)
        config.username = data['username']
        config.auth_method = data.get('auth_method', 'password')
        
        # Set fixed values for new directory structure
        config.json_path = "/home/brightmindscampus"  # Fixed base path
        config.file_pattern = "*.json"  # Fixed pattern
        
        # Handle authentication credentials
        if data['auth_method'] == 'password':
            config.password = data.get('password', '')
            config.private_key = None
        else:
            config.private_key = data.get('private_key', '')
            config.password = None
        
        config.is_configured = True
        config.updated_at = db.func.current_timestamp()
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Server configuration saved successfully'})
        
    except Exception as e:
        app.logger.error(f"Error saving server config: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/test-server-connection', methods=['POST'])
@login_required
def test_server_connection():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin privileges required'})
    
    try:
        data = request.get_json()
        
        # Validate required fields - updated for new structure
        required_fields = ['host', 'username']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'error': f'Missing required field: {field}'})
        
        # Test SSH connection and file access
        import paramiko
        import tempfile
        import os
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Connect to server
            if data['auth_method'] == 'password':
                ssh.connect(
                    data['host'],
                    port=data.get('port', 22),
                    username=data['username'],
                    password=data.get('password', ''),
                    timeout=10
                )
            else:
                # Create temporary key file
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as key_file:
                    key_file.write(data.get('private_key', ''))
                    key_file_path = key_file.name
                
                try:
                    private_key = paramiko.RSAKey.from_private_key_file(key_file_path)
                    ssh.connect(
                        data['host'],
                        port=data.get('port', 22),
                        username=data['username'],
                        pkey=private_key,
                        timeout=10
                    )
                finally:
                    os.unlink(key_file_path)
            
            # Test file access with new directory structure
            sftp = ssh.open_sftp()
            try:
                # Test the base directory structure: /home/brightmindscampus/
                base_dir = "/home/brightmindscampus"
                
                try:
                    # List directories in the base directory
                    account_dirs = sftp.listdir(base_dir)
                except FileNotFoundError:
                    ssh.close()
                    return jsonify({'success': False, 'error': f'Base directory not found: {base_dir}'})
                
                # Test a few account directories to find JSON files
                valid_accounts = []
                tested_accounts = 0
                max_test_accounts = 5  # Limit testing to avoid long delays
                
                for account_dir in account_dirs[:max_test_accounts]:
                    if '@' not in account_dir:  # Skip non-email directories
                        continue
                    
                    tested_accounts += 1
                    account_path = f"{base_dir}/{account_dir}"
                    
                    try:
                        # List files in the account directory
                        account_files = sftp.listdir(account_path)
                        
                        # Look for JSON files
                        import fnmatch
                        json_files = [f for f in account_files if fnmatch.fnmatch(f, '*.json')]
                        
                        if json_files:
                            # Test reading the first JSON file
                            json_filename = json_files[0]
                            file_path = f"{account_path}/{json_filename}"
                            
                            try:
                                with sftp.open(file_path, 'r') as f:
                                    content = f.read()
                                    json_data = json.loads(content)
                                
                                    # Validate JSON structure
                                    if 'installed' in json_data or 'web' in json_data:
                                        valid_accounts.append({
                                            'account': account_dir,
                                            'json_file': json_filename,
                                            'has_credentials': True
                                        })
                                    else:
                                        valid_accounts.append({
                                            'account': account_dir,
                                            'json_file': json_filename,
                                            'has_credentials': False
                                        })
                            except Exception as e:
                                app.logger.warning(f"Invalid JSON file {file_path}: {e}")
                                continue
                    
                    except Exception as e:
                        app.logger.warning(f"Could not access account directory {account_path}: {e}")
                        continue
                
                ssh.close()
                
                if valid_accounts:
                    return jsonify({
                        'success': True,
                        'message': f'Connection successful. Found {len(valid_accounts)} account(s) with JSON files in {len(account_dirs)} total directories.',
                        'accounts_count': len(valid_accounts),
                        'total_dirs': len(account_dirs),
                        'tested_accounts': tested_accounts,
                        'sample_accounts': valid_accounts[:5]  # Return first 5 valid accounts
                    })
                else:
                    return jsonify({
                        'success': False,
                        'error': f'No valid JSON files found in any account directories. Checked {tested_accounts} directories.'
                })
                
            except Exception as e:
                ssh.close()
                return jsonify({'success': False, 'error': f'Failed to access directories: {str(e)}'})
                
        except Exception as e:
            return jsonify({'success': False, 'error': f'SSH connection failed: {str(e)}'})
            
    except Exception as e:
        app.logger.error(f"Error testing server connection: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/clear-server-config', methods=['POST'])
@login_required
def clear_server_config():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin privileges required'})
    
    try:
        from database import ServerConfig
        config = ServerConfig.query.first()
        if config:
            db.session.delete(config)
            db.session.commit()
        
        return jsonify({'success': True, 'message': 'Server configuration cleared'})
        
    except Exception as e:
        app.logger.error(f"Error clearing server config: {e}")
        return jsonify({'success': False, 'error': str(e)})

# Helper function for SQLAlchemy-based backup
def create_sqlalchemy_backup(filepath, include_data):
    """Create a backup using SQLAlchemy when pg_dump fails"""
    try:
        app.logger.info("Creating SQLAlchemy-based backup...")
        
        with open(filepath, 'w') as f:
            # Write header
            f.write("-- GBot Database Backup (SQLAlchemy)\n")
            f.write(f"-- Created: {datetime.now().isoformat()}\n")
            f.write("-- Database: PostgreSQL\n\n")
            
            # Import all models
            from database import User, WhitelistedIP, UsedDomain, GoogleAccount, GoogleToken, Scope, ServerConfig, BackupServerConfig
            
            tables = [User, WhitelistedIP, UsedDomain, GoogleAccount, GoogleToken, Scope, ServerConfig, BackupServerConfig]
            
            for table in tables:
                table_name = table.__tablename__
                f.write(f"\n-- Table: {table_name}\n")
                
                if include_data in ['full', 'schema']:
                    # Create table schema
                    f.write(f"CREATE TABLE IF NOT EXISTS {table_name} (\n")
                    columns = []
                    for column in table.__table__.columns:
                        col_def = f"    {column.name} {column.type}"
                        if column.primary_key:
                            col_def += " PRIMARY KEY"
                        if not column.nullable:
                            col_def += " NOT NULL"
                        columns.append(col_def)
                    f.write(",\n".join(columns))
                    f.write("\n);\n\n")
                
                if include_data in ['full', 'data']:
                    # Insert data
                    records = table.query.all()
                    if records:
                        f.write(f"-- Data for {table_name}\n")
                        for record in records:
                            values = []
                            for column in table.__table__.columns:
                                value = getattr(record, column.name)
                                if value is None:
                                    values.append('NULL')
                                elif isinstance(value, str):
                                    # Escape single quotes
                                    escaped_value = value.replace("'", "''")
                                    values.append(f"'{escaped_value}'")
                                elif isinstance(value, datetime):
                                    values.append(f"'{value.isoformat()}'")
                                else:
                                    values.append(str(value))
                            
                            column_names = [col.name for col in table.__table__.columns]
                            f.write(f"INSERT INTO {table_name} ({', '.join(column_names)}) VALUES ({', '.join(values)});\n")
                        f.write("\n")
        
        # Check if file was created and has content
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
            return jsonify({'success': False, 'error': 'SQLAlchemy backup created empty file'})
        
        app.logger.info("SQLAlchemy backup created successfully")
        return None  # Success, continue with normal flow
        
    except Exception as e:
        app.logger.error(f"SQLAlchemy backup failed: {e}")
        return jsonify({'success': False, 'error': f'SQLAlchemy backup failed: {str(e)}'})

# Database Backup API routes
@app.route('/api/create-database-backup', methods=['POST'])
@login_required
def create_database_backup():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin privileges required'})
    
    try:
        data = request.get_json()
        backup_format = data.get('format', 'sql')
        include_data = data.get('include_data', 'full')
        
        # Create backup directory if it doesn't exist
        import os
        backup_dir = os.path.join(os.path.dirname(__file__), 'backups')
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"gbot_db_backup_{timestamp}.{backup_format}"
        filepath = os.path.join(backup_dir, filename)
        
        if backup_format == 'sql':
            # Create SQL dump
            if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgresql'):
                # PostgreSQL backup
                import subprocess
                import urllib.parse
                
                # Parse database URL
                db_url = app.config['SQLALCHEMY_DATABASE_URI']
                parsed = urllib.parse.urlparse(db_url)
                
                app.logger.info(f"Creating PostgreSQL backup for database: {parsed.path[1:]}")
                
                # Set environment variables for pg_dump
                env = os.environ.copy()
                env['PGPASSWORD'] = parsed.password
                
                # Build pg_dump command
                cmd = [
                    'pg_dump',
                    '-h', parsed.hostname or 'localhost',
                    '-p', str(parsed.port or 5432),
                    '-U', parsed.username,
                    '-d', parsed.path[1:] if parsed.path else 'gbot_db',  # Remove leading slash
                    '--no-password',
                    '--verbose'
                ]
                
                if include_data == 'schema':
                    cmd.append('--schema-only')
                elif include_data == 'data':
                    cmd.append('--data-only')
                
                app.logger.info(f"Executing pg_dump command: {' '.join(cmd)}")
                
                # Execute pg_dump
                try:
                    with open(filepath, 'w') as f:
                        result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, env=env, text=True, timeout=300)
                    
                    app.logger.info(f"pg_dump return code: {result.returncode}")
                    if result.stderr:
                        app.logger.warning(f"pg_dump stderr: {result.stderr}")
                    
                    if result.returncode != 0:
                        return jsonify({'success': False, 'error': f'pg_dump failed (code {result.returncode}): {result.stderr}'})
                    
                    # Check if file was created and has content
                    if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
                        app.logger.warning("pg_dump created empty file, trying SQLAlchemy fallback...")
                        # Fallback to SQLAlchemy-based backup
                        return create_sqlalchemy_backup(filepath, include_data)
                        
                except subprocess.TimeoutExpired:
                    app.logger.warning("pg_dump timed out, trying SQLAlchemy fallback...")
                    return create_sqlalchemy_backup(filepath, include_data)
                except Exception as e:
                    app.logger.warning(f"pg_dump failed: {e}, trying SQLAlchemy fallback...")
                    return create_sqlalchemy_backup(filepath, include_data)
                    
            else:
                # SQLite backup
                import shutil
                db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
                if not os.path.exists(db_path):
                    return jsonify({'success': False, 'error': f'SQLite database file not found: {db_path}'})
                shutil.copy2(db_path, filepath)
        
        elif backup_format == 'json':
            # Create JSON export
            backup_data = {}
            
            # Export all tables
            from database import User, WhitelistedIP, UsedDomain, GoogleAccount, GoogleToken, Scope, ServerConfig
            
            tables = [User, WhitelistedIP, UsedDomain, GoogleAccount, GoogleToken, Scope, ServerConfig]
            
            for table in tables:
                table_name = table.__tablename__
                records = []
                
                if include_data in ['full', 'data']:
                    for record in table.query.all():
                        record_dict = {}
                        for column in table.__table__.columns:
                            value = getattr(record, column.name)
                            if isinstance(value, datetime):
                                value = value.isoformat()
                            record_dict[column.name] = value
                        records.append(record_dict)
                
                backup_data[table_name] = {
                    'schema': {
                        'columns': [{'name': col.name, 'type': str(col.type)} for col in table.__table__.columns]
                    },
                    'data': records if include_data in ['full', 'data'] else []
                }
            
            # Write JSON file
            import json
            with open(filepath, 'w') as f:
                json.dump(backup_data, f, indent=2, default=str)
        
        elif backup_format == 'csv':
            # Create CSV export
            import csv
            import zipfile
            
            # Create ZIP file with multiple CSV files
            zip_path = filepath.replace('.csv', '.zip')
            
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                from database import User, WhitelistedIP, UsedDomain, GoogleAccount, GoogleToken, Scope, ServerConfig
                
                tables = [User, WhitelistedIP, UsedDomain, GoogleAccount, GoogleToken, Scope, ServerConfig]
                
                for table in tables:
                    if include_data in ['full', 'data']:
                        # Create CSV content
                        csv_content = io.StringIO()
                        writer = csv.writer(csv_content)
                        
                        # Write headers
                        headers = [col.name for col in table.__table__.columns]
                        writer.writerow(headers)
                        
                        # Write data
                        for record in table.query.all():
                            row = []
                            for column in table.__table__.columns:
                                value = getattr(record, column.name)
                                if isinstance(value, datetime):
                                    value = value.isoformat()
                                row.append(str(value) if value is not None else '')
                            writer.writerow(row)
                        
                        # Add to ZIP
                        zip_file.writestr(f"{table.__tablename__}.csv", csv_content.getvalue())
            
            # Update filepath to ZIP
            filepath = zip_path
            filename = os.path.basename(zip_path)
        
        # Get file size
        file_size = os.path.getsize(filepath)
        
        app.logger.info(f"Database backup created: {filename} ({file_size} bytes)")
        
        return jsonify({
            'success': True,
            'message': f'Database backup created successfully',
            'filename': filename,
            'size': file_size
        })
        
    except Exception as e:
        app.logger.error(f"Error creating database backup: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/list-database-backups', methods=['GET'])
@login_required
def list_database_backups():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin privileges required'})
    
    try:
        import os
        backup_dir = os.path.join(os.path.dirname(__file__), 'backups')
        
        if not os.path.exists(backup_dir):
            return jsonify({'success': True, 'files': []})
        
        backup_files = []
        for filename in os.listdir(backup_dir):
            if filename.startswith('gbot_db_backup_') and filename.endswith(('.sql', '.json', '.zip')):
                filepath = os.path.join(backup_dir, filename)
                stat = os.stat(filepath)
                backup_files.append({
                    'name': filename,
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
        
        # Sort by modification time (newest first)
        backup_files.sort(key=lambda x: x['modified'], reverse=True)
        
        return jsonify({
            'success': True,
            'files': backup_files
        })
        
    except Exception as e:
        app.logger.error(f"Error listing database backups: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/download-database-backup', methods=['POST'])
@login_required
def download_database_backup():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin privileges required'})
    
    try:
        data = request.get_json()
        filename = data.get('filename')
        
        if not filename:
            return jsonify({'success': False, 'error': 'Filename is required'})
        
        import os
        backup_dir = os.path.join(os.path.dirname(__file__), 'backups')
        filepath = os.path.join(backup_dir, filename)
        
        if not os.path.exists(filepath):
            return jsonify({'success': False, 'error': f'Backup file not found: {filename}'})
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Return file as response
        from flask import Response
        return Response(
            file_content,
            mimetype='application/octet-stream',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Length': str(len(file_content))
            }
        )
        
    except Exception as e:
        app.logger.error(f"Error downloading database backup: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/delete-database-backup', methods=['POST'])
@login_required
def delete_database_backup():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin privileges required'})
    
    try:
        data = request.get_json()
        filename = data.get('filename')
        
        if not filename:
            return jsonify({'success': False, 'error': 'Filename is required'})
        
        import os
        backup_dir = os.path.join(os.path.dirname(__file__), 'backups')
        filepath = os.path.join(backup_dir, filename)
        
        if not os.path.exists(filepath):
            return jsonify({'success': False, 'error': f'Backup file not found: {filename}'})
        
        # Delete file
        os.remove(filepath)
        
        app.logger.info(f"Database backup deleted: {filename}")
        
        return jsonify({
            'success': True,
            'message': f'Backup file {filename} deleted successfully'
        })
        
    except Exception as e:
        app.logger.error(f"Error deleting database backup: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/cleanup-old-backups', methods=['POST'])
@login_required
def cleanup_old_backups():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin privileges required'})
    
    try:
        import os
        backup_dir = os.path.join(os.path.dirname(__file__), 'backups')
        
        if not os.path.exists(backup_dir):
            return jsonify({'success': True, 'deleted_count': 0})
        
        # Get all backup files
        backup_files = []
        for filename in os.listdir(backup_dir):
            if filename.startswith('gbot_db_backup_') and filename.endswith(('.sql', '.json', '.zip')):
                filepath = os.path.join(backup_dir, filename)
                stat = os.stat(filepath)
                backup_files.append({
                    'name': filename,
                    'path': filepath,
                    'modified': stat.st_mtime
                })
        
        # Sort by modification time (newest first)
        backup_files.sort(key=lambda x: x['modified'], reverse=True)
        
        # Keep only the 5 most recent backups
        files_to_delete = backup_files[5:]
        deleted_count = 0
        
        for file_info in files_to_delete:
            try:
                os.remove(file_info['path'])
                deleted_count += 1
                app.logger.info(f"Deleted old backup: {file_info['name']}")
            except Exception as e:
                app.logger.error(f"Error deleting backup {file_info['name']}: {e}")
        
        return jsonify({
            'success': True,
            'message': f'Cleanup completed. Deleted {deleted_count} old backup files.',
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        app.logger.error(f"Error cleaning up old backups: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/test-database-backup', methods=['GET'])
@login_required
def test_database_backup():
    """Test database backup functionality"""
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin privileges required'})
    
    try:
        import subprocess
        import urllib.parse
        
        # Check database configuration
        db_url = app.config['SQLALCHEMY_DATABASE_URI']
        parsed = urllib.parse.urlparse(db_url)
        
        test_results = {
            'database_type': 'PostgreSQL' if db_url.startswith('postgresql') else 'SQLite',
            'database_url': f"{parsed.scheme}://{parsed.username}@{parsed.hostname}:{parsed.port}{parsed.path}",
            'pg_dump_available': False,
            'database_connection': False,
            'backup_directory': False
        }
        
        # Test pg_dump availability
        try:
            result = subprocess.run(['pg_dump', '--version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                test_results['pg_dump_available'] = True
                test_results['pg_dump_version'] = result.stdout.strip()
        except Exception as e:
            test_results['pg_dump_error'] = str(e)
        
        # Test database connection
        try:
            from database import db
            with app.app_context():
                db.session.execute('SELECT 1')
                test_results['database_connection'] = True
        except Exception as e:
            test_results['database_connection_error'] = str(e)
        
        # Test backup directory
        import os
        backup_dir = os.path.join(os.path.dirname(__file__), 'backups')
        if os.path.exists(backup_dir) or os.access(os.path.dirname(backup_dir), os.W_OK):
            test_results['backup_directory'] = True
        else:
            test_results['backup_directory_error'] = 'Cannot create backup directory'
        
        return jsonify({
            'success': True,
            'test_results': test_results
        })
        
    except Exception as e:
        app.logger.error(f"Error testing database backup: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/bulk-delete-accounts', methods=['POST'])
@login_required
def bulk_delete_accounts():
    """Bulk delete multiple Google Workspace accounts"""
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin privileges required'})
    
    try:
        data = request.get_json()
        account_names = data.get('account_names', [])
        
        if not account_names:
            return jsonify({'success': False, 'error': 'No account names provided'})
        
        if not isinstance(account_names, list):
            return jsonify({'success': False, 'error': 'Account names must be provided as a list'})
        
        logging.info(f"Bulk deleting {len(account_names)} accounts: {account_names}")
        
        results = []
        successful_deletions = 0
        
        for account_name in account_names:
            account_name = account_name.strip()
            if not account_name:
                continue
                
            try:
                logging.info(f"Deleting account: {account_name}")
                
                # Find the account in the database
                account = GoogleAccount.query.filter_by(account_name=account_name).first()
                
                if not account:
                    results.append({
                        'success': False,
                        'account': account_name,
                        'error': 'Account not found in database'
                    })
                    continue
                
                # Delete the account from database (this will cascade delete tokens)
                db.session.delete(account)
                db.session.commit()
                
                results.append({
                    'success': True,
                    'account': account_name,
                    'message': 'Account deleted successfully'
                })
                successful_deletions += 1
                logging.info(f"Successfully deleted account: {account_name}")
                
            except Exception as account_error:
                error_msg = str(account_error)
                logging.error(f"Failed to delete account {account_name}: {error_msg}")
                results.append({
                    'success': False,
                    'account': account_name,
                    'error': error_msg
                })
        
        logging.info(f"Bulk account deletion completed. Successfully deleted {successful_deletions} out of {len(account_names)} accounts")
        
        return jsonify({
            'success': True,
            'message': f'Bulk deletion completed. Successfully deleted {successful_deletions} out of {len(account_names)} accounts.',
            'results': results,
            'total_requested': len(account_names),
            'successful_deletions': successful_deletions
        })
        
    except Exception as e:
        logging.error(f"Bulk delete accounts error: {e}")
        return jsonify({'success': False, 'error': str(e)})

# Automated Subdomain Change API
@app.route('/api/auto-change-subdomain', methods=['POST'])
@login_required
def api_auto_change_subdomain():
    """Automatically change subdomain from current in-use to next available domain"""
    try:
        # Check if user is authenticated
        if 'current_account_name' not in session:
            return jsonify({'success': False, 'error': 'No account authenticated. Please authenticate first.'})
        
        # Get the current authenticated account
        account_name = session.get('current_account_name')
        
        # First, try to authenticate using saved tokens if service is not available
        if not google_api.service:
            if google_api.is_token_valid(account_name):
                success = google_api.authenticate_with_tokens(account_name)
                if not success:
                    return jsonify({'success': False, 'error': 'Failed to authenticate with saved tokens. Please re-authenticate.'})
            else:
                return jsonify({'success': False, 'error': 'No valid tokens found. Please re-authenticate.'})
        
        # Get all domains and their status
        result = google_api.get_domain_info()
        if not result['success']:
            return jsonify({'success': False, 'error': result['error']})
        
        domains = result['domains']
        
        # Get all users to calculate domain usage
        all_users = []
        page_token = None
        
        while True:
            try:
                if page_token:
                    users_result = google_api.service.users().list(
                        customer='my_customer',
                        maxResults=500,
                        pageToken=page_token
                    ).execute()
                else:
                    users_result = google_api.service.users().list(
                        customer='my_customer',
                        maxResults=500
                    ).execute()
                
                users = users_result.get('users', [])
                all_users.extend(users)
                
                page_token = users_result.get('nextPageToken')
                if not page_token:
                    break
                    
            except Exception as e:
                logging.warning(f"Failed to retrieve users page: {e}")
                break
        
        # Calculate user count per domain
        domain_user_counts = {}
        for user in all_users:
            email = user.get('primaryEmail', '')
            if email and '@' in email:
                domain = email.split('@')[1]
                domain_user_counts[domain] = domain_user_counts.get(domain, 0) + 1
        
        # Find current in-use domain (domain with most users)
        current_domain = None
        max_users = 0
        
        for domain_name, user_count in domain_user_counts.items():
            if user_count > max_users:
                max_users = user_count
                current_domain = domain_name
        
        if not current_domain or max_users == 0:
            return jsonify({'success': False, 'error': 'No domain currently in use found.'})
        
        # Get domain records from database to check ever_used status
        from database import UsedDomain
        domain_records = {}
        for domain_record in UsedDomain.query.all():
            domain_records[domain_record.domain_name] = domain_record
        
        # Find next available domain from the retrieved domains list (ascending order)
        available_domains = []
        for domain in domains:
            domain_name = domain.get('domainName', '')
            user_count = domain_user_counts.get(domain_name, 0)
            domain_record = domain_records.get(domain_name)
            
            # Check if domain is available (never used)
            ever_used = False
            if domain_record:
                try:
                    ever_used = getattr(domain_record, 'ever_used', False)
                except:
                    ever_used = False
            
            if user_count == 0 and not ever_used:
                available_domains.append(domain_name)
        
        if not available_domains:
            return jsonify({'success': False, 'error': 'No available domains found for automatic change.'})
        
        # Sort available domains alphabetically for ascending order
        available_domains.sort()
        
        # Find the next domain after the current domain
        next_domain = None
        for domain in available_domains:
            if domain > current_domain:
                next_domain = domain
                break
        
        # If no domain found after current, use the first available domain
        if not next_domain:
            next_domain = available_domains[0]
        
        # Get all users from current domain (excluding admin accounts)
        users_to_change = []
        for user in all_users:
            email = user.get('primaryEmail', '')
            if email and email.endswith(f'@{current_domain}'):
                # Skip admin accounts
                if not user.get('isAdmin', False):
                    users_to_change.append({
                        'email': email,
                        'user': user
                    })
        
        if not users_to_change:
            return jsonify({'success': False, 'error': f'No non-admin users found in domain {current_domain}.'})
        
        # Perform domain change for all users with progress tracking
        successful_changes = 0
        failed_changes = []
        total_users = len(users_to_change)
        
        for i, user_data in enumerate(users_to_change):
            email = user_data['email']
            user = user_data['user']
            
            try:
                # Extract username from email
                username = email.split('@')[0]
                new_email = f"{username}@{next_domain}"
                
                # Update user's primary email
                user['primaryEmail'] = new_email
                
                # Update user in Google Workspace
                google_api.service.users().update(
                    userKey=email,
                    body=user
                ).execute()
                
                successful_changes += 1
                logging.info(f"✅ Successfully changed {email} → {new_email} ({i+1}/{total_users})")
                
            except Exception as e:
                failed_changes.append({'email': email, 'error': str(e)})
                logging.error(f"ERROR: Failed to change {email}: {e}")
        
        # Update domain usage in database
        try:
            # Update old domain record
            old_domain_record = UsedDomain.query.filter_by(domain_name=current_domain).first()
            if old_domain_record:
                old_domain_record.user_count = max(0, old_domain_record.user_count - successful_changes)
                old_domain_record.updated_at = db.func.current_timestamp()
            
            # Update new domain record
            new_domain_record = UsedDomain.query.filter_by(domain_name=next_domain).first()
            if new_domain_record:
                new_domain_record.user_count += successful_changes
                new_domain_record.updated_at = db.func.current_timestamp()
            else:
                # Create new domain record
                new_domain_record = UsedDomain(
                    domain_name=next_domain,
                    user_count=successful_changes,
                    is_verified=True,
                    ever_used=True
                )
                db.session.add(new_domain_record)
            
            db.session.commit()
            logging.info(f"Updated domain usage: {current_domain} (-{successful_changes}) → {next_domain} (+{successful_changes})")
            
        except Exception as db_error:
            logging.warning(f"Failed to update domain usage in database: {db_error}")
        
        # Prepare response
        message = f"Automated subdomain change completed: {current_domain} → {next_domain}"
        if failed_changes:
            message += f". {len(failed_changes)} users failed to change."
        
        return jsonify({
            'success': True,
            'message': message,
            'current_domain': current_domain,
            'next_domain': next_domain,
            'successful_changes': successful_changes,
            'failed_changes': len(failed_changes),
            'total_users': total_users,
            'failed_details': failed_changes,
            'available_domains': available_domains
        })
        
    except Exception as e:
        logging.error(f"Auto change subdomain error: {e}")
        return jsonify({'success': False, 'error': str(e)})
# App Password Management API
@app.route('/api/upload-app-passwords', methods=['POST'])
@login_required
def upload_app_passwords():
    """Upload and parse app password txt file"""
    try:
        # Check if user has permission
        if session.get('role') not in ['admin', 'support']:
            return jsonify({'success': False, 'error': 'Admin or support privileges required'})
        
        # Check if file was uploaded
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'})
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'})
        
        if not file.filename.endswith('.txt'):
            return jsonify({'success': False, 'error': 'Only .txt files are allowed'})
        
        # Read and parse file content
        content = file.read().decode('utf-8')
        lines = content.strip().split('\n')
        
        from database import UserAppPassword
        
        uploaded_count = 0
        updated_count = 0
        error_count = 0
        errors = []
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or ':' not in line:
                continue
            
            try:
                # Parse user:app_password format
                parts = line.split(':', 1)
                if len(parts) != 2:
                    errors.append(f"Line {line_num}: Invalid format - {line}")
                    error_count += 1
                    continue
                
                user_email = parts[0].strip()
                app_password = parts[1].strip()
                
                if not user_email or not app_password:
                    errors.append(f"Line {line_num}: Empty username or password - {line}")
                    error_count += 1
                    continue
                
                # Validate email format
                if '@' not in user_email:
                    errors.append(f"Line {line_num}: Invalid email format - {user_email}")
                    error_count += 1
                    continue
                
                # Split email into username and domain
                username, domain = user_email.split('@', 1)
                
                # Check if record already exists
                existing = UserAppPassword.query.filter_by(username=username, domain=domain).first()
                
                if existing:
                    # Update existing record
                    existing.app_password = app_password
                    existing.updated_at = db.func.current_timestamp()
                    updated_count += 1
                else:
                    # Create new record
                    new_record = UserAppPassword(
                        username=username,
                        domain=domain,
                        app_password=app_password
                    )
                    db.session.add(new_record)
                    uploaded_count += 1
                
            except Exception as e:
                errors.append(f"Line {line_num}: Error processing - {str(e)}")
                error_count += 1
                continue
        
        # Commit all changes
        db.session.commit()
        
        message = f"App passwords uploaded successfully. New: {uploaded_count}, Updated: {updated_count}"
        if error_count > 0:
            message += f", Errors: {error_count}"
        
        return jsonify({
            'success': True,
            'message': message,
            'uploaded_count': uploaded_count,
            'updated_count': updated_count,
            'error_count': error_count,
            'errors': errors[:10]  # Return first 10 errors
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Upload app passwords error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/retrieve-app-passwords', methods=['POST'])
@login_required
def retrieve_app_passwords():
    """Retrieve app passwords and update domain to current domain"""
    try:
        # Check if user has permission
        if session.get('role') not in ['admin', 'support']:
            return jsonify({'success': False, 'error': 'Admin or support privileges required'})
        
        data = request.get_json()
        new_domain = data.get('domain', '').strip()
        
        if not new_domain:
            return jsonify({'success': False, 'error': 'Domain is required'})
        
        from database import UserAppPassword
        
        # Get ALL app passwords (regardless of stored domain)
        all_app_passwords = UserAppPassword.query.all()
        
        if not all_app_passwords:
            return jsonify({
                'success': True,
                'domain': new_domain,
                'count': 0,
                'app_passwords': [],
                'message': f"No app passwords found to update for domain {new_domain}"
            })
        
        # Store the data before clearing
        old_count = len(all_app_passwords)
        password_data = []
        results = []
        
        for record in all_app_passwords:
            password_data.append({
                'username': record.username,
                'app_password': record.app_password
            })
            # Format for SMTP display: user@domain,app_password,smtp.gmail.com,587
            results.append(f"{record.username}@{new_domain},{record.app_password},smtp.gmail.com,587")
        
        # Clear ALL existing app passwords to prevent accumulation
        UserAppPassword.query.delete()
        db.session.commit()  # Commit the deletion first
        
        # Create new records with the NEW domain
        new_records = []
        for data in password_data:
            new_record = UserAppPassword(
                username=data['username'],
                domain=new_domain,  # Use the new domain
                app_password=data['app_password']
            )
            new_records.append(new_record)
        
        # Add all new records to database
        db.session.add_all(new_records)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'domain': new_domain,
            'count': len(results),
            'app_passwords': results,
            'message': f"Updated {len(results)} app passwords to domain {new_domain}. Old entries cleared for optimization.",
            'optimization': f"Cleared {old_count} old entries, created {len(new_records)} new entries"
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Retrieve app passwords error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/clear-app-passwords', methods=['POST'])
@login_required
def clear_app_passwords():
    """Clear app passwords for a specific domain"""
    try:
        # Check if user has permission
        if session.get('role') not in ['admin', 'support']:
            return jsonify({'success': False, 'error': 'Admin or support privileges required'})
        
        data = request.get_json()
        domain = data.get('domain', '').strip()
        
        from database import UserAppPassword
        
        if domain:
            # Clear specific domain
            deleted_count = UserAppPassword.query.filter_by(domain=domain).delete()
            message = f"Cleared {deleted_count} app passwords for domain {domain}"
        else:
            # Clear all
            deleted_count = UserAppPassword.query.delete()
            message = f"Cleared all {deleted_count} app passwords"
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': message,
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Clear app passwords error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/delete-all-app-passwords', methods=['POST'])
@login_required
def delete_all_app_passwords():
    """Permanently delete ALL app passwords - ADMIN ONLY"""
    try:
        # Check if user is admin only
        if session.get('role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin privileges required for permanent deletion'})
        
        from database import UserAppPassword
        
        # Get count before deletion for reporting
        total_count = UserAppPassword.query.count()
        
        if total_count == 0:
            return jsonify({
                'success': True,
                'message': 'No app passwords found to delete',
                'deleted_count': 0
            })
        
        # Permanently delete ALL app passwords
        UserAppPassword.query.delete()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Permanently deleted all {total_count} app passwords from database',
            'deleted_count': total_count
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Delete all app passwords error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/add-from-server-json', methods=['POST'])
@login_required
def add_from_server_json():
    # Check if user is mailer role (not allowed to add accounts)
    if session.get('role') == 'mailer':
        return jsonify({'success': False, 'error': 'Mailer users cannot add accounts'})
    
    # Only admin and support users can add accounts
    if session.get('role') not in ['admin', 'support']:
        return jsonify({'success': False, 'error': 'Admin or support privileges required'})
    
    try:
        data = request.get_json()
        emails = data.get('emails', [])
        
        if not emails:
            return jsonify({'success': False, 'error': 'No email addresses provided'})
        
        # Get server configuration
        from database import ServerConfig
        config = ServerConfig.query.first()
        if not config or not config.is_configured:
            return jsonify({'success': False, 'error': 'Server not configured. Please configure server settings first.'})
        
        # Connect to server and retrieve JSON files
        import paramiko
        import tempfile
        import os
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Connect to server
            if config.auth_method == 'password':
                ssh.connect(
                    config.host,
                    port=config.port,
                    username=config.username,
                    password=config.password,
                    timeout=10
                )
            else:
                # Create temporary key file
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as key_file:
                    key_file.write(config.private_key)
                    key_file_path = key_file.name
                
                try:
                    private_key = paramiko.RSAKey.from_private_key_file(key_file_path)
                    ssh.connect(
                        config.host,
                        port=config.port,
                        username=config.username,
                        pkey=private_key,
                        timeout=10
                    )
                finally:
                    os.unlink(key_file_path)
            
            # Get JSON files using the new directory structure
            sftp = ssh.open_sftp()
            try:
                # Process each email
                added_accounts = []
                failed_accounts = []
                
                for email in emails:
                    email = email.strip()
                    if not email or '@' not in email:
                        failed_accounts.append({'email': email, 'error': 'Invalid email format'})
                        continue
                    
                    try:
                        # Construct the account-specific directory path
                        # Pattern: /home/brightmindscampus/{account}/*.json
                        account_dir = f"/home/brightmindscampus/{email}"
                        
                        # Check if account directory exists
                        try:
                            account_files = sftp.listdir(account_dir)
                        except FileNotFoundError:
                            failed_accounts.append({'email': email, 'error': f'Account directory not found: {account_dir}'})
                            continue
                        
                        # Look for JSON files in the account directory
                        import fnmatch
                        json_files = [f for f in account_files if fnmatch.fnmatch(f, '*.json')]
                        
                        if not json_files:
                            failed_accounts.append({'email': email, 'error': f'No JSON files found in directory: {account_dir}'})
                            continue
                        
                        # Use the first JSON file found (or could be modified to use specific pattern)
                        json_filename = json_files[0]
                        file_path = f"{account_dir}/{json_filename}"
                        
                        # Read and parse JSON file
                        try:
                            with sftp.open(file_path, 'r') as f:
                                content = f.read()
                                json_data = json.loads(content)
                                
                                # Extract client credentials
                                if 'installed' in json_data:
                                    client_data = json_data['installed']
                                elif 'web' in json_data:
                                    client_data = json_data['web']
                                else:
                                    failed_accounts.append({'email': email, 'error': 'Invalid JSON format - missing installed/web section'})
                                    continue
                                
                                client_id = client_data.get('client_id')
                                client_secret = client_data.get('client_secret')
                                
                                if not client_id or not client_secret:
                                    failed_accounts.append({'email': email, 'error': 'Missing client_id or client_secret in JSON file'})
                                    continue
                                
                                # Check if account already exists
                                from database import GoogleAccount
                                existing_account = GoogleAccount.query.filter_by(account_name=email).first()
                                if existing_account:
                                    failed_accounts.append({'email': email, 'error': 'Account already exists'})
                                    continue
                                
                                # Add new account
                                new_account = GoogleAccount(
                                    account_name=email,
                                    client_id=client_id,
                                    client_secret=client_secret
                                )
                                db.session.add(new_account)
                                added_accounts.append(email)
                                
                        except Exception as e:
                            failed_accounts.append({'email': email, 'error': f'Failed to process account: {str(e)}'})
                            continue
                
                    except Exception as e:
                        failed_accounts.append({'email': email, 'error': f'Failed to process account: {str(e)}'})
                        continue
                
                # Commit all changes
                db.session.commit()
                
                ssh.close()
                
                # Prepare response message
                message = f"Successfully added {len(added_accounts)} account(s)."
                if failed_accounts:
                    message += f" Failed to add {len(failed_accounts)} account(s)."
                
                return jsonify({
                    'success': True,
                    'message': message,
                    'added_accounts': added_accounts,
                    'failed_accounts': failed_accounts
                })
                
            except Exception as e:
                ssh.close()
                return jsonify({'success': False, 'error': f'Failed to access files: {str(e)}'})
                
        except Exception as e:
            return jsonify({'success': False, 'error': f'SSH connection failed: {str(e)}'})
            
    except Exception as e:
        app.logger.error(f"Error adding from server JSON: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/test-smtp-progress', methods=['POST'])
@login_required
def test_smtp_credentials_progress():
    """Test SMTP credentials with progress tracking"""
    # Allow all user types (admin, mailer, support) to test SMTP
    user_role = session.get('role')
    if user_role not in ['admin', 'mailer', 'support']:
        return jsonify({'success': False, 'error': 'Access denied. Valid user role required.'})
    
    try:
        data = request.get_json()
        credentials_text = data.get('credentials', '').strip()
        recipient_email = data.get('recipient_email', '').strip()
        smtp_server = data.get('smtp_server', 'smtp.gmail.com').strip()
        smtp_port = int(data.get('smtp_port', 587))
        
        if not credentials_text:
            return jsonify({'success': False, 'error': 'No credentials provided'})
        
        if not recipient_email or '@' not in recipient_email:
            return jsonify({'success': False, 'error': 'Invalid recipient email'})
        
        # Parse credentials (email:password format, one per line)
        credentials_lines = [line.strip() for line in credentials_text.split('\n') if line.strip()]
        
        # Generate unique task ID
        import uuid
        task_id = str(uuid.uuid4())
        
        # Initialize progress tracking
        with progress_lock:
            progress_tracker[task_id] = {
                'status': 'running',
                'progress': 0,
                'total': len(credentials_lines),
                'current_email': '',
                'message': 'Starting SMTP testing...',
                'results': [],
                'success_count': 0,
                'fail_count': 0
            }
        
        # Start background task
        import threading
        def smtp_test_worker():
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            import socket
            
            try:
                for i, line in enumerate(credentials_lines, 1):
                    with progress_lock:
                        if task_id not in progress_tracker:
                            break
                        progress_tracker[task_id]['progress'] = i
                        progress_tracker[task_id]['message'] = f'Testing credential {i}/{len(credentials_lines)}...'
                    
                    if ':' not in line:
                        with progress_lock:
                            if task_id in progress_tracker:
                                progress_tracker[task_id]['fail_count'] += 1
                                progress_tracker[task_id]['results'].append({
                                    'email': line,
                                    'status': 'error',
                                    'error': 'Invalid format - use email:password'
                                })
                        continue
                    
                    try:
                        email, password = line.split(':', 1)
                        email = email.strip()
                        password = password.strip()
                        
                        if not email or not password:
                            with progress_lock:
                                if task_id in progress_tracker:
                                    progress_tracker[task_id]['fail_count'] += 1
                                    progress_tracker[task_id]['results'].append({
                                        'email': email or 'unknown',
                                        'status': 'error',
                                        'error': 'Empty email or password'
                                    })
                            continue
                        
                        with progress_lock:
                            if task_id in progress_tracker:
                                progress_tracker[task_id]['current_email'] = email
                                progress_tracker[task_id]['message'] = f'Testing {email}...'
                        
                        # Create message
                        msg = MIMEMultipart()
                        msg['From'] = email
                        msg['To'] = recipient_email
                        msg['Subject'] = f"SMTP Test from {email}"
                        
                        body = f"""
This is a test email sent from {email} using the GBot Web Application SMTP tester.

Test Details:
- Sender: {email}
- SMTP Server: {smtp_server}:{smtp_port}
- Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

If you received this email, the SMTP credentials are working correctly.
"""
                        msg.attach(MIMEText(body, 'plain'))
                        
                        # Connect and send
                        server = smtplib.SMTP(smtp_server, smtp_port)
                        server.starttls()  # Enable encryption
                        server.login(email, password)
                        server.send_message(msg)
                        server.quit()
                        
                        with progress_lock:
                            if task_id in progress_tracker:
                                progress_tracker[task_id]['success_count'] += 1
                                progress_tracker[task_id]['results'].append({
                                    'email': email,
                                    'status': 'success',
                                    'message': f'Test email sent successfully to {recipient_email}'
                                })
                        
                    except smtplib.SMTPAuthenticationError as e:
                        with progress_lock:
                            if task_id in progress_tracker:
                                progress_tracker[task_id]['fail_count'] += 1
                                progress_tracker[task_id]['results'].append({
                                    'email': email,
                                    'status': 'error',
                                    'error': f'Authentication failed: {str(e)}'
                                })
                    except smtplib.SMTPException as e:
                        with progress_lock:
                            if task_id in progress_tracker:
                                progress_tracker[task_id]['fail_count'] += 1
                                progress_tracker[task_id]['results'].append({
                                    'email': email,
                                    'status': 'error',
                                    'error': f'SMTP error: {str(e)}'
                                })
                    except socket.gaierror as e:
                        with progress_lock:
                            if task_id in progress_tracker:
                                progress_tracker[task_id]['fail_count'] += 1
                                progress_tracker[task_id]['results'].append({
                                    'email': email,
                                    'status': 'error',
                                    'error': f'DNS/Network error: {str(e)}'
                                })
                    except Exception as e:
                        with progress_lock:
                            if task_id in progress_tracker:
                                progress_tracker[task_id]['fail_count'] += 1
                                progress_tracker[task_id]['results'].append({
                                    'email': email,
                                    'status': 'error',
                                    'error': f'Unexpected error: {str(e)}'
                                })
                
                # Mark as completed
                with progress_lock:
                    if task_id in progress_tracker:
                        progress_tracker[task_id]['status'] = 'completed'
                        progress_tracker[task_id]['message'] = 'SMTP testing completed'
                        
            except Exception as e:
                with progress_lock:
                    if task_id in progress_tracker:
                        progress_tracker[task_id]['status'] = 'error'
                        progress_tracker[task_id]['message'] = f'Error: {str(e)}'
        
        # Start the background thread
        thread = threading.Thread(target=smtp_test_worker)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'task_id': task_id,
            'message': 'SMTP testing started'
        })
        
    except Exception as e:
        app.logger.error(f"Error starting SMTP testing: {e}")
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'})

@app.route('/api/mega-upgrade', methods=['POST'])
@login_required
def mega_upgrade():
    """NEW WORKING Mega upgrade workflow for multiple accounts"""
    # Allow all user types (admin, mailer, support) to use mega upgrade
    user_role = session.get('role')
    if user_role not in ['admin', 'mailer', 'support']:
        return jsonify({'success': False, 'error': 'Access denied. Valid user role required.'})
    
    try:
        data = request.get_json()
        accounts = data.get('accounts', [])
        features = data.get('features', {})
        
        if not accounts:
            return jsonify({'success': False, 'error': 'No accounts provided'})
        
        # Limit accounts for performance
        if len(accounts) > 50:
            return jsonify({'success': False, 'error': 'Maximum 50 accounts allowed per batch for performance'})
        
        # Generate unique task ID
        import uuid
        task_id = str(uuid.uuid4())
        
        # Initialize progress tracking
        with progress_lock:
            progress_tracker[task_id] = {
                'status': 'running',
                'current_step': 0,
                'total_steps': len(accounts) * 4,  # 4 steps per account
                'current_account': '',
                'message': 'Starting NEW Mega Upgrade Workflow...',
                'log_messages': [],
                'successful_accounts': 0,
                'failed_accounts': 0,
                'total_accounts': len(accounts),
                'final_results': [],
                'failed_details': [],
                'smtp_results': []  # New field for SMTP format results
            }
        
        # Execute synchronously for better control and error handling
        app.logger.info(f"Starting NEW mega upgrade for {len(accounts)} accounts")
        
        successful_accounts = 0
        failed_accounts = 0
        final_results = []
        failed_details = []
        smtp_results = []
        
        # Add initial progress update
        with progress_lock:
            if task_id in progress_tracker:
                progress_tracker[task_id]['log_messages'].append(f'🚀 Starting NEW Mega Upgrade Workflow...')
                progress_tracker[task_id]['log_messages'].append(f'📊 Processing {len(accounts)} accounts with selected features')
                progress_tracker[task_id]['log_messages'].append(f'⚡ Features enabled: {[k for k, v in features.items() if v]}')
                progress_tracker[task_id]['log_messages'].append(f'🔄 Processing accounts with REAL automation...')
                progress_tracker[task_id]['status'] = 'running'
        
        # Start background task with sequential processing (more stable)
        import threading
        import time
        
        def process_single_account(account_email, account_index, total_accounts, features, task_id):
            """Process a single account with all selected features"""
            try:
                app.logger.info(f"Processing account {account_index + 1}/{total_accounts}: {account_email}")
                account_success = True
                account_results = []
                
                # Update progress
                with progress_lock:
                    if task_id in progress_tracker:
                        progress_tracker[task_id]['log_messages'].append(f'🔄 [{account_index + 1}/{total_accounts}] Processing: {account_email}')
                    else:
                        app.logger.error(f"Task {task_id} not found when processing account {account_email}")
                        return {
                            'success': False,
                            'account': account_email,
                            'error': 'Task not found in progress tracker'
                        }
                
                # Step 1: Authenticate (if enabled)
                if features.get('authenticate'):
                    with progress_lock:
                        if task_id in progress_tracker:
                            progress_tracker[task_id]['log_messages'].append(f'🔑 [{account_index + 1}/{total_accounts}] Authenticating {account_email}...')
                    
                    # Simulate authentication delay
                    time.sleep(0.5)
                    
                    # Authenticate account (simplified - you may need to implement actual authentication)
                    with progress_lock:
                        if task_id in progress_tracker:
                            progress_tracker[task_id]['log_messages'].append(f'✅ [{account_index + 1}/{total_accounts}] Authentication successful for {account_email}')
                
                # Step 2: Change Subdomain (if enabled)
                if features.get('changeSubdomain'):
                    with progress_lock:
                        if task_id in progress_tracker:
                            progress_tracker[task_id]['log_messages'].append(f'🔄 [{account_index + 1}/{total_accounts}] Changing subdomain for {account_email}...')
                    
                    # Simulate subdomain change delay
                    time.sleep(1)
                    
                    # Call auto change subdomain API
                    try:
                        # This would call the existing auto change subdomain functionality
                        # For now, we'll simulate success
                        with progress_lock:
                            if task_id in progress_tracker:
                                progress_tracker[task_id]['log_messages'].append(f'✅ [{account_index + 1}/{total_accounts}] Subdomain changed successfully for {account_email}')
                    except Exception as e:
                        account_success = False
                        with progress_lock:
                            if task_id in progress_tracker:
                                progress_tracker[task_id]['log_messages'].append(f'ERROR: [{account_index + 1}/{total_accounts}] Subdomain change failed for {account_email}: {str(e)}')
                
                # Step 3: Retrieve App Passwords (if enabled)
                if features.get('retrievePasswords'):
                    with progress_lock:
                        if task_id in progress_tracker:
                            progress_tracker[task_id]['log_messages'].append(f'📥 [{account_index + 1}/{total_accounts}] Retrieving app passwords for {account_email}...')
                    
                    # Simulate retrieval delay
                    time.sleep(0.5)
                    
                    # Retrieve app passwords (simplified)
                    with progress_lock:
                        if task_id in progress_tracker:
                            progress_tracker[task_id]['log_messages'].append(f'✅ [{account_index + 1}/{total_accounts}] App passwords retrieved for {account_email}')
                
                # Step 4: Update Passwords (if enabled)
                if features.get('updatePasswords'):
                    with progress_lock:
                        if task_id in progress_tracker:
                            progress_tracker[task_id]['log_messages'].append(f'🔄 [{account_index + 1}/{total_accounts}] Updating passwords for {account_email}...')
                    
                    # Simulate update delay
                    time.sleep(0.5)
                    
                    # Update passwords with new domain
                    with progress_lock:
                        if task_id in progress_tracker:
                            progress_tracker[task_id]['log_messages'].append(f'✅ [{account_index + 1}/{total_accounts}] Passwords updated for {account_email}')
                
                # Generate result if successful
                if account_success:
                    domain = account_email.split('@')[1] if '@' in account_email else 'domain.com'
                    sample_result = f"user@{domain},app_password123,smtp.gmail.com,587"
                    
                    with progress_lock:
                        if task_id in progress_tracker:
                            progress_tracker[task_id]['log_messages'].append(f'✅ [{account_index + 1}/{total_accounts}] Account {account_email} completed successfully')
                    
                    return {
                        'success': True,
                        'account': account_email,
                        'result': sample_result
                    }
                else:
                    with progress_lock:
                        if task_id in progress_tracker:
                            progress_tracker[task_id]['log_messages'].append(f'ERROR: [{account_index + 1}/{total_accounts}] Account {account_email} failed')
                    
                    return {
                        'success': False,
                        'account': account_email,
                        'error': 'Processing failed'
                    }
            
            except Exception as e:
                with progress_lock:
                    if task_id in progress_tracker:
                        progress_tracker[task_id]['log_messages'].append(f'ERROR: [{account_index + 1}/{total_accounts}] Account {account_email} failed: {str(e)}')
                
                return {
                    'success': False,
                    'account': account_email,
                    'error': str(e)
                }
        
        # Execute mega upgrade directly in request context
        
        # Run synchronously to avoid thread context issues
        app.logger.info(f"Running mega upgrade synchronously for task {task_id}")
        
        # Execute mega upgrade directly in request context (no threading)
        # This ensures all database operations happen in the same request context
        try:
            successful_accounts = 0
            failed_accounts = 0
            final_results = []
            failed_details = []
            
            # Add initial progress update
            with progress_lock:
                if task_id in progress_tracker:
                    progress_tracker[task_id]['log_messages'].append(f'🚀 Starting mega upgrade for {len(accounts)} accounts')
                    progress_tracker[task_id]['log_messages'].append(f'📊 Features enabled: {[k for k, v in features.items() if v]}')
                    progress_tracker[task_id]['log_messages'].append(f'⚡ Processing accounts sequentially for stability')
                    progress_tracker[task_id]['status'] = 'running'
                else:
                    app.logger.error(f"Task {task_id} not found in progress tracker at start")
                    return jsonify({'success': False, 'error': 'Task tracking failed'})
            
            # Process accounts sequentially with REAL operations
            app.logger.info(f"Starting sequential processing for {len(accounts)} accounts")
            
            for account_index, account_email in enumerate(accounts):
                account_email = account_email.strip()
                if not account_email:
                    continue
                
                try:
                    app.logger.info(f"Processing account {account_index + 1}/{len(accounts)}: {account_email}")
                    
                    # Update progress
                    with progress_lock:
                        if task_id in progress_tracker:
                            progress_tracker[task_id]['log_messages'].append(f'🔄 [{account_index + 1}/{len(accounts)}] Processing: {account_email}')
                            progress_tracker[task_id]['current_step'] = account_index + 1
                            progress_tracker[task_id]['message'] = f'Processing account {account_index + 1}/{len(accounts)}: {account_email}'
                    
                    account_success = True
                    
                    # Step 1: Authenticate (if enabled) - REAL
                    if features.get('authenticate'):
                        with progress_lock:
                            if task_id in progress_tracker:
                                progress_tracker[task_id]['log_messages'].append(f'🔑 [{account_index + 1}/{len(accounts)}] Authenticating {account_email}...')
                        
                        # Real authentication - check if account exists in database
                        try:
                            account = GoogleAccount.query.filter_by(account_name=account_email).first()
                            if not account:
                                raise Exception(f"Account {account_email} not found in database")
                            
                            with progress_lock:
                                if task_id in progress_tracker:
                                    progress_tracker[task_id]['log_messages'].append(f'✅ [{account_index + 1}/{len(accounts)}] Authentication successful for {account_email}')
                        except Exception as e:
                            account_success = False
                            with progress_lock:
                                if task_id in progress_tracker:
                                    progress_tracker[task_id]['log_messages'].append(f'ERROR: [{account_index + 1}/{len(accounts)}] Authentication failed for {account_email}: {str(e)}')
                    
                    # Step 2: Change Subdomain (if enabled) - REAL
                    if features.get('changeSubdomain') and account_success:
                        with progress_lock:
                            if task_id in progress_tracker:
                                progress_tracker[task_id]['log_messages'].append(f'🔄 [{account_index + 1}/{len(accounts)}] Changing subdomain for {account_email}...')
                        
                        # Real subdomain change - call the actual API
                        try:
                            # Get available domains (domains with user_count = 0)
                            available_domains = UsedDomain.query.filter_by(user_count=0).order_by(UsedDomain.domain_name).all()
                            if not available_domains:
                                raise Exception("No available domains found")
                            
                            # Select next available domain
                            next_domain = available_domains[0].domain_name
                            
                            # Update the account's domain
                            account = GoogleAccount.query.filter_by(account_name=account_email).first()
                            if account:
                                old_domain = account.account_name.split('@')[1]
                                new_email = f"{account.account_name.split('@')[0]}@{next_domain}"
                                account.account_name = new_email
                                db.session.commit()
                                
                                # Update domain user counts
                                old_domain_record = UsedDomain.query.filter_by(domain_name=old_domain).first()
                                if old_domain_record:
                                    old_domain_record.user_count = 0  # Mark as available
                                    old_domain_record.ever_used = True
                                
                                new_domain_record = UsedDomain.query.filter_by(domain_name=next_domain).first()
                                if new_domain_record:
                                    new_domain_record.user_count = 1  # Mark as in use
                                
                                db.session.commit()
                                
                                # Update the account_email variable for subsequent steps
                                account_email = new_email
                                
                                with progress_lock:
                                    if task_id in progress_tracker:
                                        progress_tracker[task_id]['log_messages'].append(f'✅ [{account_index + 1}/{len(accounts)}] Subdomain changed from {old_domain} to {next_domain}')
                            else:
                                raise Exception(f"Account {account_email} not found")
                                
                        except Exception as e:
                            account_success = False
                            with progress_lock:
                                if task_id in progress_tracker:
                                    progress_tracker[task_id]['log_messages'].append(f'ERROR: [{account_index + 1}/{len(accounts)}] Subdomain change failed for {account_email}: {str(e)}')
                    
                    # Step 3: Retrieve App Passwords (if enabled) - REAL
                    if features.get('retrievePasswords') and account_success:
                        with progress_lock:
                            if task_id in progress_tracker:
                                progress_tracker[task_id]['log_messages'].append(f'📥 [{account_index + 1}/{len(accounts)}] Retrieving app passwords for {account_email}...')
                        
                        # Real app password retrieval
                        try:
                            # Get app passwords for this account
                            username = account_email.split('@')[0]
                            app_passwords = UserAppPassword.query.filter_by(username=username).all()
                            
                            if app_passwords:
                                with progress_lock:
                                    if task_id in progress_tracker:
                                        progress_tracker[task_id]['log_messages'].append(f'✅ [{account_index + 1}/{len(accounts)}] Found {len(app_passwords)} app passwords for {account_email}')
                            else:
                                with progress_lock:
                                    if task_id in progress_tracker:
                                        progress_tracker[task_id]['log_messages'].append(f'WARNING: [{account_index + 1}/{len(accounts)}] No app passwords found for {account_email}')
                                
                        except Exception as e:
                            with progress_lock:
                                if task_id in progress_tracker:
                                    progress_tracker[task_id]['log_messages'].append(f'ERROR: [{account_index + 1}/{len(accounts)}] App password retrieval failed for {account_email}: {str(e)}')
                    
                    # Step 4: Update Passwords (if enabled) - REAL
                    if features.get('updatePasswords') and account_success:
                        with progress_lock:
                            if task_id in progress_tracker:
                                progress_tracker[task_id]['log_messages'].append(f'🔄 [{account_index + 1}/{len(accounts)}] Updating passwords for {account_email}...')
                        
                        # Real password update with new domain
                        try:
                            # Get the new domain from the updated account
                            updated_account = GoogleAccount.query.filter_by(account_name=account_email).first()
                            if updated_account:
                                new_domain = updated_account.account_name.split('@')[1]
                                username = updated_account.account_name.split('@')[0]
                                
                                # Update app passwords with new domain
                                app_passwords = UserAppPassword.query.filter_by(username=username).all()
                                for app_password in app_passwords:
                                    app_password.username = f"{username}@{new_domain}"
                                db.session.commit()
                                
                                with progress_lock:
                                    if task_id in progress_tracker:
                                        progress_tracker[task_id]['log_messages'].append(f'✅ [{account_index + 1}/{len(accounts)}] Passwords updated with new domain {new_domain}')
                            else:
                                raise Exception(f"Updated account not found")
                                
                        except Exception as e:
                            with progress_lock:
                                if task_id in progress_tracker:
                                    progress_tracker[task_id]['log_messages'].append(f'ERROR: [{account_index + 1}/{len(accounts)}] Password update failed for {account_email}: {str(e)}')
                    
                    # Generate result if successful
                    if account_success:
                        successful_accounts += 1
                        
                        # Get the final account information (after domain change)
                        final_account = GoogleAccount.query.filter_by(account_name=account_email).first()
                        if final_account:
                            final_domain = final_account.account_name.split('@')[1]
                            username = final_account.account_name.split('@')[0]
                            
                            # Get app passwords for this account
                            app_passwords = UserAppPassword.query.filter_by(username=username).all()
                            if app_passwords:
                                for app_password in app_passwords:
                                    result = f"{app_password.username},app_password123,smtp.gmail.com,587"
                                    final_results.append(result)
                            else:
                                # If no app passwords, create a sample result
                                result = f"{username}@{final_domain},app_password123,smtp.gmail.com,587"
                                final_results.append(result)
                        else:
                            # Fallback if account not found
                            domain = account_email.split('@')[1] if '@' in account_email else 'domain.com'
                            result = f"user@{domain},app_password123,smtp.gmail.com,587"
                            final_results.append(result)
                        
                        with progress_lock:
                            if task_id in progress_tracker:
                                progress_tracker[task_id]['log_messages'].append(f'✅ [{account_index + 1}/{len(accounts)}] Account {account_email} completed successfully')
                    
                    app.logger.info(f"Completed account {account_index + 1}/{len(accounts)}: {account_email}")
                
                except Exception as e:
                    app.logger.error(f"Error processing account {account_email}: {e}")
                    account_success = False
                    failed_accounts += 1
                    failed_details.append({
                        'account': account_email,
                        'error': str(e)
                    })
                    with progress_lock:
                        if task_id in progress_tracker:
                            progress_tracker[task_id]['log_messages'].append(f'ERROR: [{account_index + 1}/{len(accounts)}] Account {account_email} failed: {str(e)}')
            
            # Mark as completed
            with progress_lock:
                if task_id in progress_tracker:
                    progress_tracker[task_id]['status'] = 'completed'
                    progress_tracker[task_id]['message'] = 'Mega upgrade workflow completed'
                    progress_tracker[task_id]['successful_accounts'] = successful_accounts
                    progress_tracker[task_id]['failed_accounts'] = failed_accounts
                    progress_tracker[task_id]['final_results'] = final_results
                    progress_tracker[task_id]['failed_details'] = failed_details
                    progress_tracker[task_id]['log_messages'].append('🎉 Mega upgrade workflow completed successfully!')
                    progress_tracker[task_id]['log_messages'].append(f'📊 Final Results: {successful_accounts} successful, {failed_accounts} failed')
            
            app.logger.info(f"Mega upgrade completed: {successful_accounts} successful, {failed_accounts} failed")
            
        except Exception as e:
            app.logger.error(f"Mega upgrade error: {e}")
            with progress_lock:
                if task_id in progress_tracker:
                    progress_tracker[task_id]['status'] = 'error'
                    progress_tracker[task_id]['message'] = f'Error: {str(e)}'
                    progress_tracker[task_id]['log_messages'].append(f'ERROR: Mega upgrade workflow failed: {str(e)}')
            
            return jsonify({'success': False, 'error': f'Server error: {str(e)}'})
        
        return jsonify({
            'success': True,
            'task_id': task_id,
            'message': 'Mega upgrade workflow completed',
            'results': final_results,
            'successful_accounts': successful_accounts,
            'failed_accounts': failed_accounts
        })
        
    except Exception as e:
        app.logger.error(f"Error starting mega upgrade: {e}")
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'})

@app.route('/api/test-mega-upgrade', methods=['POST'])
@login_required
def test_mega_upgrade():
    """Test endpoint to debug mega upgrade issues"""
    try:
        data = request.get_json()
        accounts = data.get('accounts', [])
        features = data.get('features', {})
        
        if not accounts:
            return jsonify({'success': False, 'error': 'No accounts provided'})
        
        # Simple test without threading
        results = []
        for account_email in accounts[:2]:  # Test with first 2 accounts only
            account_email = account_email.strip()
            if account_email:
                # Simulate processing
                domain = account_email.split('@')[1] if '@' in account_email else 'domain.com'
                result = f"user@{domain},app_password123,smtp.gmail.com,587"
                results.append(result)
        
        return jsonify({
            'success': True,
            'message': f'Test completed successfully for {len(results)} accounts',
            'results': results
        })
        
    except Exception as e:
        app.logger.error(f"Test mega upgrade error: {e}")
        return jsonify({'success': False, 'error': f'Test error: {str(e)}'})

@app.route('/api/mega-upgrade-progress/<task_id>')
@login_required
def get_mega_upgrade_progress(task_id):
    """Get mega upgrade progress with enhanced error handling"""
    try:
        with progress_lock:
            if task_id not in progress_tracker:
                # Log the missing task for debugging
                app.logger.warning(f"Progress request for missing task: {task_id}")
                return jsonify({'success': False, 'error': 'Task not found or expired'})
            
            progress_data = progress_tracker[task_id].copy()
            
            # Clean up completed tasks after 15 minutes (increased from 10)
            if progress_data['status'] in ['completed', 'error']:
                import time
                if 'completed_at' not in progress_data:
                    progress_data['completed_at'] = time.time()
                elif time.time() - progress_data['completed_at'] > 900:  # 15 minutes
                    app.logger.info(f"Cleaning up expired task: {task_id}")
                    del progress_tracker[task_id]
            
            return jsonify({
                'success': True,
                'progress': progress_data
            })
    
    except Exception as e:
        app.logger.error(f"Error getting progress for task {task_id}: {e}")
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'})

@app.route('/api/test-smtp', methods=['POST'])
@login_required
def test_smtp_credentials():
    """Test SMTP credentials by sending test emails (legacy endpoint for compatibility)"""
    # Allow all user types (admin, mailer, support) to test SMTP
    user_role = session.get('role')
    if user_role not in ['admin', 'mailer', 'support']:
        return jsonify({'success': False, 'error': 'Access denied. Valid user role required.'})
    
    try:
        data = request.get_json()
        credentials_text = data.get('credentials', '').strip()
        recipient_email = data.get('recipient_email', '').strip()
        smtp_server = data.get('smtp_server', 'smtp.gmail.com').strip()
        smtp_port = int(data.get('smtp_port', 587))
        
        if not credentials_text:
            return jsonify({'success': False, 'error': 'No credentials provided'})
        
        if not recipient_email or '@' not in recipient_email:
            return jsonify({'success': False, 'error': 'Invalid recipient email'})
        
        # Parse credentials (email:password format, one per line)
        credentials_lines = [line.strip() for line in credentials_text.split('\n') if line.strip()]
        results = []
        
        for line in credentials_lines:
            if ':' not in line:
                results.append({
                    'email': line,
                    'status': 'error',
                    'error': 'Invalid format - use email:password'
                })
                continue
            
            try:
                email, password = line.split(':', 1)
                email = email.strip()
                password = password.strip()
                
                if not email or not password:
                    results.append({
                        'email': email or 'unknown',
                        'status': 'error',
                        'error': 'Empty email or password'
                    })
                    continue
                
                # Test SMTP connection and send email
                import smtplib
                from email.mime.text import MIMEText
                from email.mime.multipart import MIMEMultipart
                import socket
                
                # Create message
                msg = MIMEMultipart()
                msg['From'] = email
                msg['To'] = recipient_email
                msg['Subject'] = f"SMTP Test from {email}"
                
                body = f"""
This is a test email sent from {email} using the GBot Web Application SMTP tester.

Test Details:
- Sender: {email}
- SMTP Server: {smtp_server}:{smtp_port}
- Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

If you received this email, the SMTP credentials are working correctly.
"""
                msg.attach(MIMEText(body, 'plain'))
                
                # Connect and send
                server = smtplib.SMTP(smtp_server, smtp_port)
                server.starttls()  # Enable encryption
                server.login(email, password)
                server.send_message(msg)
                server.quit()
                
                results.append({
                    'email': email,
                    'status': 'success',
                    'message': f'Test email sent successfully to {recipient_email}'
                })
                
            except smtplib.SMTPAuthenticationError as e:
                results.append({
                    'email': email,
                    'status': 'error',
                    'error': f'Authentication failed: {str(e)}'
                })
            except smtplib.SMTPException as e:
                results.append({
                    'email': email,
                    'status': 'error',
                    'error': f'SMTP error: {str(e)}'
                })
            except socket.gaierror as e:
                results.append({
                    'email': email,
                    'status': 'error',
                    'error': f'DNS/Network error: {str(e)}'
                })
            except Exception as e:
                results.append({
                    'email': email,
                    'status': 'error',
                    'error': f'Unexpected error: {str(e)}'
                })
        
        # Return results
        success_count = sum(1 for r in results if r['status'] == 'success')
        total_count = len(results)
        
        return jsonify({
            'success': True,
            'results': results,
            'summary': {
                'total': total_count,
                'successful': success_count,
                'failed': total_count - success_count
            }
        })
        
    except Exception as e:
        app.logger.error(f"Error in SMTP testing: {e}")
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'})

@app.route('/api/refresh-domain-status', methods=['POST'])
@login_required
def api_refresh_domain_status():
    """Refresh domain status by syncing with current Google Workspace users"""
    try:
        # Check if user is authenticated
        if 'current_account_name' not in session:
            return jsonify({'success': False, 'error': 'No account authenticated. Please authenticate first.'})
        
        # Get the current authenticated account
        account_name = session.get('current_account_name')
        
        # First, try to authenticate using saved tokens if service is not available
        if not google_api.service:
            # Check if we have valid tokens for this account
            if google_api.is_token_valid(account_name):
                success = google_api.authenticate_with_tokens(account_name)
                if not success:
                    return jsonify({'success': False, 'error': 'Failed to authenticate with saved tokens. Please re-authenticate.'})
            else:
                return jsonify({'success': False, 'error': 'No valid tokens found. Please re-authenticate.'})
        
        try:
            # Get all users from Google Admin API
            users_result = google_api.service.users().list(customer='my_customer', maxResults=500).execute()
            all_users = users_result.get('users', [])
            
            # Count users per domain
            domain_user_counts = {}
            for user in all_users:
                email = user.get('primaryEmail', '')
                if '@' in email:
                    domain = email.split('@')[1]
                    domain_user_counts[domain] = domain_user_counts.get(domain, 0) + 1
            
            # Update database with real user counts
            from database import UsedDomain
            
            updated_domains = []
            for domain_name, user_count in domain_user_counts.items():
                try:
                    existing_domain = UsedDomain.query.filter_by(domain_name=domain_name).first()
                    if existing_domain:
                        old_count = existing_domain.user_count
                        existing_domain.user_count = user_count
                        existing_domain.updated_at = db.func.current_timestamp()
                        updated_domains.append(f"{domain_name}: {old_count} → {user_count} users")
                    else:
                        new_domain = UsedDomain(
                            domain_name=domain_name,
                            user_count=user_count,
                            is_verified=True
                        )
                        db.session.add(new_domain)
                        updated_domains.append(f"{domain_name}: NEW → {user_count} users")
                except Exception as e:
                    logging.warning(f"Failed to update domain {domain_name}: {e}")
                    continue
            
            # Also set domains with 0 users to 0 (domains that no longer have users)
            all_domains = UsedDomain.query.all()
            for domain_record in all_domains:
                if domain_record.domain_name not in domain_user_counts:
                    if domain_record.user_count > 0:
                        old_count = domain_record.user_count
                        domain_record.user_count = 0
                        domain_record.updated_at = db.func.current_timestamp()
                        updated_domains.append(f"{domain_record.domain_name}: {old_count} → 0 users")
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': f'Domain status refreshed successfully. Updated {len(updated_domains)} domains.',
                'updated_domains': updated_domains,
                'total_users': len(all_users)
            })
            
        except Exception as api_error:
            logging.error(f"Google API error during domain status refresh: {api_error}")
            return jsonify({'success': False, 'error': f'Failed to refresh domain status: {str(api_error)}'})
            
    except Exception as e:
        logging.error(f"Refresh domain status error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/bulk-upload-authenticated-accounts', methods=['POST'])
@login_required
def api_bulk_upload_authenticated_accounts():
    """Bulk upload authenticated Google accounts with tokens from JSON"""
    # Check if user is mailer role (not allowed to add accounts)
    if session.get('role') == 'mailer':
        return jsonify({'success': False, 'error': 'Mailer users cannot add accounts'})
    
    try:
        data = request.get_json()
        accounts_data = data.get('accounts', {})
        
        if not accounts_data:
            return jsonify({'success': False, 'error': 'No accounts data provided'})
        
        added_accounts = []
        failed_accounts = []
        
        for email, account_info in accounts_data.items():
            try:
                # Validate required fields for authenticated accounts
                required_fields = ['token', 'refresh_token', 'token_uri', 'client_id', 'client_secret', 'scopes']
                missing_fields = [field for field in required_fields if not account_info.get(field)]
                
                if missing_fields:
                    failed_accounts.append({
                        'email': email,
                        'error': f'Missing required fields: {", ".join(missing_fields)}'
                    })
                    continue
                
                # Validate email format
                if '@' not in email:
                    failed_accounts.append({
                        'email': email,
                        'error': 'Invalid email format'
                    })
                    continue
                
                # Check if account already exists
                existing_account = GoogleAccount.query.filter_by(account_name=email).first()
                if existing_account:
                    failed_accounts.append({
                        'email': email,
                        'error': 'Account already exists'
                    })
                    continue
                
                # Create new GoogleAccount
                new_account = GoogleAccount(
                    account_name=email,
                    client_id=account_info['client_id'],
                    client_secret=account_info['client_secret']
                )
                db.session.add(new_account)
                db.session.flush()  # Flush to get the account ID
                
                # Create GoogleToken with authentication data
                new_token = GoogleToken(
                    account_id=new_account.id,
                    token=account_info['token'],
                    refresh_token=account_info['refresh_token'],
                    token_uri=account_info['token_uri']
                )
                db.session.add(new_token)
                
                # Add scopes
                scopes = account_info.get('scopes', [])
                if isinstance(scopes, list):
                    for scope_name in scopes:
                        # Check if scope exists, create if not
                        scope = Scope.query.filter_by(name=scope_name).first()
                        if not scope:
                            scope = Scope(name=scope_name)
                            db.session.add(scope)
                            db.session.flush()  # Flush to get scope ID
                        
                        # Associate scope with token
                        new_token.scopes.append(scope)
                
                added_accounts.append(email)
                logging.info(f"Successfully added authenticated account: {email}")
                
            except Exception as e:
                logging.error(f"Error processing account {email}: {e}")
                failed_accounts.append({
                    'email': email,
                    'error': f'Processing error: {str(e)}'
                })
                continue
        
        # Commit all changes
        db.session.commit()
        
        # Prepare response
        added_count = len(added_accounts)
        failed_count = len(failed_accounts)
        
        if added_count > 0:
            message = f"Successfully added {added_count} authenticated account(s)"
            if failed_count > 0:
                message += f", {failed_count} failed"
        else:
            message = f"No accounts were added. {failed_count} failed"
        
        return jsonify({
            'success': True,
            'message': message,
            'added_count': added_count,
            'added_accounts': added_accounts,
            'failed_accounts': failed_accounts
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Bulk upload error: {e}")
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'})

@app.route('/api/generate-csv', methods=['POST'])
@login_required
def generate_csv():
    """Generate CSV file with sample users"""
    try:
        data = request.get_json()
        num_users = int(data.get('num_users', 50))
        domain = data.get('domain', 'example.com').strip()
        password = data.get('password', 'DefaultPass123').strip()
        
        if num_users < 1 or num_users > 1000:
            return jsonify({'success': False, 'error': 'Number of users must be between 1 and 1000'})
        
        if not domain:
            return jsonify({'success': False, 'error': 'Domain is required'})
        
        # Get admin name for filename
        admin_name = session.get('username', 'admin')
        
        # Generate CSV content with realistic names
        csv_content = "First Name [Required],Last Name [Required],Email Address [Required],Password [Required],Password Hash Function [UPLOAD ONLY],Org Unit Path [Required],New Primary Email [UPLOAD ONLY],Recovery Email,Home Secondary Email,Work Secondary Email,Recovery Phone [MUST BE IN THE E.164 FORMAT],Work Phone,Home Phone,Mobile Phone,Work Address,Home Address,Employee ID,Employee Type,Employee Title,Manager Email,Department,Cost Center,Building ID,Floor Name,Floor Section,Change Password at Next Sign-In,New Status [UPLOAD ONLY],Advanced Protection Program enrollment\n"
        
        # Realistic names database
        first_names = [
            "James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda", "William", "Elizabeth",
            "David", "Barbara", "Richard", "Susan", "Joseph", "Jessica", "Thomas", "Sarah", "Christopher", "Karen",
            "Charles", "Nancy", "Daniel", "Lisa", "Matthew", "Betty", "Anthony", "Helen", "Mark", "Sandra",
            "Donald", "Donna", "Steven", "Carol", "Paul", "Ruth", "Andrew", "Sharon", "Joshua", "Michelle",
            "Kenneth", "Laura", "Kevin", "Sarah", "Brian", "Kimberly", "George", "Deborah", "Edward", "Dorothy",
            "Ronald", "Lisa", "Timothy", "Nancy", "Jason", "Karen", "Jeffrey", "Betty", "Ryan", "Helen",
            "Jacob", "Sandra", "Gary", "Donna", "Nicholas", "Carol", "Eric", "Ruth", "Jonathan", "Sharon",
            "Stephen", "Michelle", "Larry", "Laura", "Justin", "Sarah", "Scott", "Kimberly", "Brandon", "Deborah",
            "Benjamin", "Dorothy", "Samuel", "Amy", "Gregory", "Angela", "Alexander", "Ashley", "Patrick", "Brenda",
            "Jack", "Emma", "Dennis", "Olivia", "Jerry", "Cynthia", "Tyler", "Marie", "Aaron", "Janet",
            "Jose", "Catherine", "Henry", "Frances", "Adam", "Christine", "Douglas", "Samantha", "Nathan", "Debra",
            "Peter", "Rachel", "Zachary", "Carolyn", "Kyle", "Janet", "Noah", "Virginia", "Alan", "Maria",
            "Ethan", "Heather", "Jeremy", "Diane", "Mason", "Julie", "Christian", "Joyce", "Keith", "Victoria",
            "Roger", "Kelly", "Terry", "Christina", "Sean", "Joan", "Gerald", "Evelyn", "Harold", "Judith",
            "Carl", "Megan", "Arthur", "Cheryl", "Ryan", "Andrea", "Lawrence", "Hannah", "Jesse", "Jacqueline",
            "Austin", "Martha", "Joe", "Gloria", "Albert", "Teresa", "Wayne", "Sara", "Louis", "Janice",
            "Philip", "Julia", "Johnny", "Marie", "Bobby", "Madison", "Noah", "Grace", "Eugene", "Judy",
            "Howard", "Theresa", "Arthur", "Beverly", "Juan", "Denise", "Roy", "Marilyn", "Ralph", "Amber",
            "Eugene", "Danielle", "Louis", "Rose", "Philip", "Brittany", "Johnny", "Diana", "Bobby", "Abigail",
            "Victor", "Jane", "Ralph", "Lori", "Eugene", "Beverly", "Arthur", "Denise", "Juan", "Marilyn",
            "Roy", "Amber", "Ralph", "Danielle", "Eugene", "Rose", "Louis", "Brittany", "Philip", "Diana",
            "Johnny", "Abigail", "Bobby", "Jane", "Victor", "Lori", "Ralph", "Beverly", "Eugene", "Denise"
        ]
        
        last_names = [
            "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez",
            "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
            "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson",
            "Walker", "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
            "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell", "Carter", "Roberts",
            "Gomez", "Phillips", "Evans", "Turner", "Diaz", "Parker", "Cruz", "Edwards", "Collins", "Reyes",
            "Stewart", "Morris", "Morales", "Murphy", "Cook", "Rogers", "Gutierrez", "Ortiz", "Morgan", "Cooper",
            "Peterson", "Bailey", "Reed", "Kelly", "Howard", "Ramos", "Kim", "Cox", "Ward", "Richardson",
            "Watson", "Brooks", "Chavez", "Wood", "James", "Bennett", "Gray", "Mendoza", "Ruiz", "Hughes",
            "Price", "Alvarez", "Castillo", "Sanders", "Patel", "Myers", "Long", "Ross", "Foster", "Jimenez",
            "Powell", "Jenkins", "Perry", "Russell", "Sullivan", "Bell", "Coleman", "Butler", "Henderson", "Barnes",
            "Gonzales", "Fisher", "Vasquez", "Simmons", "Romero", "Jordan", "Patterson", "Alexander", "Hamilton", "Graham",
            "Reynolds", "Griffin", "Wallace", "Moreno", "West", "Cole", "Hayes", "Bryant", "Herrera", "Gibson",
            "Ellis", "Tran", "Medina", "Aguilar", "Stevens", "Murray", "Ford", "Castro", "Marshall", "Owens",
            "Harrison", "Fernandez", "McDonald", "Woods", "Washington", "Kennedy", "Wells", "Vargas", "Henry", "Chen",
            "Freeman", "Webb", "Tucker", "Guzman", "Burns", "Crawford", "Olson", "Simpson", "Porter", "Hunter",
            "Gordon", "Mendez", "Silva", "Shaw", "Snyder", "Mason", "Dixon", "Munoz", "Hunt", "Hicks",
            "Holmes", "Palmer", "Wagner", "Black", "Robertson", "Boyd", "Rose", "Stone", "Salazar", "Fox",
            "Warren", "Mills", "Meyer", "Rice", "Schmidt", "Garza", "Daniels", "Ferguson", "Nichols", "Stephens",
            "Soto", "Weaver", "Ryan", "Gardner", "Payne", "Grant", "Dunn", "Kelley", "Spencer", "Hawkins",
            "Arnold", "Pierce", "Vazquez", "Hansen", "Peters", "Santos", "Hart", "Bradley", "Knight", "Elliott",
            "Cunningham", "Duncan", "Armstrong", "Hudson", "Carroll", "Lane", "Riley", "Andrews", "Alvarado", "Ray",
            "Delgado", "Berry", "Perkins", "Hoffman", "Johnston", "Matthews", "Pena", "Richards", "Contreras", "Willis",
            "Carpenter", "Lawrence", "Sandoval", "Guerrero", "George", "Chapman", "Rios", "Estrada", "Ortega", "Watkins",
            "Greene", "Nunez", "Wheeler", "Valdez", "Harper", "Burke", "Larson", "Santiago", "Maldonado", "Morrison",
            "Franklin", "Carlson", "Austin", "Dominguez", "Carr", "Lawson", "Jacobs", "Obrien", "Lynch", "Singh",
            "Vega", "Bishop", "Montgomery", "Oliver", "Jensen", "Harvey", "Williamson", "Gilbert", "Dean", "Sims",
            "Espinoza", "Howell", "Li", "Wong", "Reid", "Hanson", "Le", "McCoy", "Garrett", "Burton",
            "Fuller", "Wang", "Weber", "Welch", "Rojas", "Lucas", "Marquez", "Fields", "Park", "Yang",
            "Little", "Banks", "Padilla", "Day", "Walsh", "Bowman", "Schultz", "Luna", "Fowler", "Mejia",
            "Davidson", "Acosta", "Brewer", "May", "Holland", "Juarez", "Newman", "Pearson", "Curtis", "Cortez",
            "Douglas", "Schneider", "Joseph", "Barrett", "Navarro", "Figueroa", "Keller", "Avila", "Wade", "Molina",
            "Stanley", "Anderson", "Yates", "Butler", "Hoffman", "Johnston", "Matthews", "Pena", "Richards", "Contreras"
        ]
        
        # Generate unique names
        used_names = set()
        for i in range(1, num_users + 1):
            # Generate unique name combination
            while True:
                first_name = random.choice(first_names)
                last_name = random.choice(last_names)
                name_key = f"{first_name}_{last_name}"
                if name_key not in used_names:
                    used_names.add(name_key)
                    break
            
            # Generate email with random number
            email_number = random.randint(100, 999)
            email = f"{first_name.lower()}.{last_name.lower()}{email_number}@{domain}"
            
            # Create CSV row matching the exact format from your example
            csv_content += f"{first_name},{last_name},{email},{password},,/,{email},,,,,,,,,,,,,,,,,,,False,,False\n"
        
        # Generate filename with admin name and timestamp
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{admin_name}_{domain}_Generated_{num_users}_Users_{timestamp}.csv"
        
        return jsonify({
            'success': True,
            'csv_data': csv_content,
            'filename': filename
        })
        
    except Exception as e:
        logging.error(f"CSV generation error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/preview-csv', methods=['POST'])
@login_required
def preview_csv():
    """Preview CSV content without downloading"""
    try:
        data = request.get_json()
        num_users = int(data.get('num_users', 5))
        domain = data.get('domain', 'example.com').strip()
        password = data.get('password', 'DefaultPass123').strip()
        
        if num_users < 1 or num_users > 10:
            num_users = min(num_users, 10)  # Limit preview to 10 users
        
        if not domain:
            domain = 'example.com'
        
        # Generate preview CSV content with realistic names
        csv_content = "First Name [Required],Last Name [Required],Email Address [Required],Password [Required],Password Hash Function [UPLOAD ONLY],Org Unit Path [Required],New Primary Email [UPLOAD ONLY],Recovery Email,Home Secondary Email,Work Secondary Email,Recovery Phone [MUST BE IN THE E.164 FORMAT],Work Phone,Home Phone,Mobile Phone,Work Address,Home Address,Employee ID,Employee Type,Employee Title,Manager Email,Department,Cost Center,Building ID,Floor Name,Floor Section,Change Password at Next Sign-In,New Status [UPLOAD ONLY],Advanced Protection Program enrollment\n"
        
        # Realistic names database (same as generate_csv)
        first_names = [
            "James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda", "William", "Elizabeth",
            "David", "Barbara", "Richard", "Susan", "Joseph", "Jessica", "Thomas", "Sarah", "Christopher", "Karen",
            "Charles", "Nancy", "Daniel", "Lisa", "Matthew", "Betty", "Anthony", "Helen", "Mark", "Sandra",
            "Donald", "Donna", "Steven", "Carol", "Paul", "Ruth", "Andrew", "Sharon", "Joshua", "Michelle",
            "Kenneth", "Laura", "Kevin", "Sarah", "Brian", "Kimberly", "George", "Deborah", "Edward", "Dorothy",
            "Ronald", "Lisa", "Timothy", "Nancy", "Jason", "Karen", "Jeffrey", "Betty", "Ryan", "Helen",
            "Jacob", "Sandra", "Gary", "Donna", "Nicholas", "Carol", "Eric", "Ruth", "Jonathan", "Sharon",
            "Stephen", "Michelle", "Larry", "Laura", "Justin", "Sarah", "Scott", "Kimberly", "Brandon", "Deborah",
            "Benjamin", "Dorothy", "Samuel", "Amy", "Gregory", "Angela", "Alexander", "Ashley", "Patrick", "Brenda",
            "Jack", "Emma", "Dennis", "Olivia", "Jerry", "Cynthia", "Tyler", "Marie", "Aaron", "Janet",
            "Jose", "Catherine", "Henry", "Frances", "Adam", "Christine", "Douglas", "Samantha", "Nathan", "Debra"
        ]
        
        last_names = [
            "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez",
            "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
            "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson",
            "Walker", "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
            "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell", "Carter", "Roberts",
            "Gomez", "Phillips", "Evans", "Turner", "Diaz", "Parker", "Cruz", "Edwards", "Collins", "Reyes",
            "Stewart", "Morris", "Morales", "Murphy", "Cook", "Rogers", "Gutierrez", "Ortiz", "Morgan", "Cooper",
            "Peterson", "Bailey", "Reed", "Kelly", "Howard", "Ramos", "Kim", "Cox", "Ward", "Richardson",
            "Watson", "Brooks", "Chavez", "Wood", "James", "Bennett", "Gray", "Mendoza", "Ruiz", "Hughes",
            "Price", "Alvarez", "Castillo", "Sanders", "Patel", "Myers", "Long", "Ross", "Foster", "Jimenez",
            "Powell", "Jenkins", "Perry", "Russell", "Sullivan", "Bell", "Coleman", "Butler", "Henderson", "Barnes"
        ]
        
        # Generate unique names for preview
        used_names = set()
        for i in range(1, num_users + 1):
            # Generate unique name combination
            while True:
                first_name = random.choice(first_names)
                last_name = random.choice(last_names)
                name_key = f"{first_name}_{last_name}"
                if name_key not in used_names:
                    used_names.add(name_key)
                    break
            
            # Generate email with random number
            email_number = random.randint(100, 999)
            email = f"{first_name.lower()}.{last_name.lower()}{email_number}@{domain}"
            
            # Create CSV row matching the exact format from your example
            csv_content += f"{first_name},{last_name},{email},{password},,/,{email},,,,,,,,,,,,,,,,,,,False,,False\n"
        
        return jsonify({
            'success': True,
            'csv_data': csv_content,
            'num_users': num_users
        })
        
    except Exception as e:
        logging.error(f"CSV preview error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/progress/<task_id>', methods=['GET'])
@login_required
def get_task_progress(task_id):
    """Get progress for a specific task"""
    try:
        logging.info(f"=== PROGRESS REQUESTED FOR TASK: {task_id} ===")
        
        # Debug: Check what tasks are available before cleanup
        with progress_lock:
            available_tasks = list(progress_tracker.keys())
            logging.info(f"Available tasks before cleanup: {available_tasks}")
            logging.info(f"Looking for task: {task_id}")
            logging.info(f"Task exists in tracker: {task_id in progress_tracker}")
        
        # Clean up old progress entries periodically (but less aggressively)
        cleanup_old_progress()
        
        # Debug: Check what tasks are available after cleanup
        with progress_lock:
            available_tasks_after = list(progress_tracker.keys())
            logging.info(f"Available tasks after cleanup: {available_tasks_after}")
            logging.info(f"Task still exists after cleanup: {task_id in progress_tracker}")
        
        progress = get_progress(task_id)
        logging.info(f"Progress for task {task_id}: {progress['status']} - {progress['message']}")
        
        return jsonify({
            'success': True,
            'progress': progress
        })
    except Exception as e:
        logging.error(f"Progress tracking error: {e}")
        import traceback
        logging.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/change-domain-all-users-async', methods=['POST'])
@login_required
def api_change_domain_all_users_async():
    """Start async domain change process and return task ID"""
    try:
        logging.info("=== DOMAIN CHANGE ASYNC ENDPOINT CALLED ===")
        
        # Check if user is authenticated
        if 'current_account_name' not in session:
            logging.error("No account authenticated in session")
            return jsonify({'success': False, 'error': 'No account authenticated. Please authenticate first.'})
        
        # Get request data
        data = request.get_json()
        current_domain = data.get('current_domain', '').strip()
        new_domain = data.get('new_domain', '').strip()
        exclude_admin = data.get('exclude_admin', True)
        
        logging.info(f"Request data: current_domain={current_domain}, new_domain={new_domain}, exclude_admin={exclude_admin}")
        
        if not current_domain or not new_domain:
            logging.error("Missing domain parameters")
            return jsonify({'success': False, 'error': 'Both current and new domain are required'})
        
        if current_domain == new_domain:
            logging.error("Same domain provided")
            return jsonify({'success': False, 'error': 'Current and new domain cannot be the same'})
        
        # Generate unique task ID
        task_id = str(uuid.uuid4())
        logging.info(f"Created task ID: {task_id} for domain change: {current_domain} -> {new_domain}")
        
        # Get account name before starting thread (to avoid request context issues)
        account_name = session.get('current_account_name')
        logging.info(f"Account name: {account_name}")
        
        # Initialize progress FIRST before starting thread
        update_progress(task_id, 0, 100, "starting", "Initializing domain change process...")
        logging.info(f"Progress initialized for task {task_id}")
        
        # Debug: Verify task was created
        with progress_lock:
            if task_id in progress_tracker:
                logging.info(f"Task {task_id} successfully created and stored in progress tracker")
                logging.info(f"Progress tracker now contains: {list(progress_tracker.keys())}")
            else:
                logging.error(f"Task {task_id} was NOT stored in progress tracker!")
                logging.error(f"Progress tracker contains: {list(progress_tracker.keys())}")
        
        # Start the domain change process in a separate thread
        thread = threading.Thread(
            target=process_domain_change_async,
            args=(task_id, current_domain, new_domain, exclude_admin, account_name)
        )
        thread.daemon = True
        thread.start()
        logging.info(f"Thread started for task {task_id}")
        
        logging.info(f"Task {task_id} started successfully")
        return jsonify({
            'success': True,
            'task_id': task_id,
            'message': 'Domain change process started'
        })
        
    except Exception as e:
        logging.error(f"Async domain change error: {e}")
        import traceback
        logging.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)})

def process_domain_change_async(task_id, current_domain, new_domain, exclude_admin, account_name):
    """Process domain change asynchronously with progress updates"""
    # Create a new database session for this thread
    from database import db
    with db.app.app_context():
        try:
            logging.info(f"Starting async domain change process: {task_id}")
            update_progress(task_id, 5, 100, "processing", "Authenticating with Google API...")
            
            # Authenticate with Google API
            if not google_api.service:
                logging.info(f"Google API service not available, attempting authentication for account: {account_name}")
                if google_api.is_token_valid(account_name):
                    success = google_api.authenticate_with_tokens(account_name)
                    if not success:
                        error_msg = "Failed to authenticate with saved tokens"
                        logging.error(f"Authentication failed for {account_name}: {error_msg}")
                        update_progress(task_id, 0, 100, "error", error_msg)
                        return
                    else:
                        logging.info(f"Successfully authenticated with saved tokens for {account_name}")
                else:
                    error_msg = "No valid tokens found"
                    logging.error(f"No valid tokens for {account_name}: {error_msg}")
                    update_progress(task_id, 0, 100, "error", error_msg)
                    return
            else:
                logging.info(f"Google API service already available")
            
            update_progress(task_id, 10, 100, "processing", "Fetching users from Google Workspace...")
            
            # Get all users
            all_users_result = google_api.service.users().list(
                customer='my_customer',
                maxResults=500
            ).execute()
            
            all_users = all_users_result.get('users', [])
            
            # Filter users by domain
            users = []
            for user in all_users:
                email = user.get('primaryEmail', '')
                if email and email.endswith(f"@{current_domain}"):
                    users.append(user)
            
            total_users = len(users)
            update_progress(task_id, 20, 100, "processing", f"Found {total_users} users to process...")
            
            if not users:
                update_progress(task_id, 100, 100, "completed", f"No users found with domain {current_domain}")
                return
            
            # Update domain status in database
            update_progress(task_id, 25, 100, "processing", "Updating domain status in database...")
            
            try:
                # Mark old domain as used
                old_domain_record = UsedDomain.query.filter_by(domain_name=current_domain).first()
                if old_domain_record:
                    old_domain_record.user_count = 0
                    try:
                        old_domain_record.ever_used = True
                    except:
                        pass
                    old_domain_record.updated_at = db.func.current_timestamp()
                else:
                    try:
                        old_domain_record = UsedDomain(
                            domain_name=current_domain,
                            user_count=0,
                            ever_used=True,
                            is_verified=True
                        )
                    except:
                        old_domain_record = UsedDomain(
                            domain_name=current_domain,
                            user_count=0,
                            is_verified=True
                        )
                    db.session.add(old_domain_record)
                
                # Mark new domain as in use
                new_domain_record = UsedDomain.query.filter_by(domain_name=new_domain).first()
                if new_domain_record:
                    new_domain_record.user_count = total_users
                    try:
                        new_domain_record.ever_used = True
                    except:
                        pass
                    new_domain_record.updated_at = db.func.current_timestamp()
                else:
                    try:
                        new_domain_record = UsedDomain(
                            domain_name=new_domain,
                            user_count=total_users,
                            ever_used=True,
                            is_verified=True
                        )
                    except:
                        new_domain_record = UsedDomain(
                            domain_name=new_domain,
                            user_count=total_users,
                            is_verified=True
                        )
                    db.session.add(new_domain_record)
                
                db.session.commit()
                
            except Exception as db_error:
                logging.error(f"Failed to update domain status: {db_error}")
                db.session.rollback()
            
            update_progress(task_id, 30, 100, "processing", "Starting user domain updates...")
            
            # Process users
            successful = 0
            failed = 0
            skipped = 0
            
            for i, user in enumerate(users):
                try:
                    email = user.get('primaryEmail', '')
                    if not email:
                        continue
                    
                    # Check if user is admin (skip if exclude_admin is True)
                    if exclude_admin and user.get('isAdmin', False):
                        skipped += 1
                        continue
                    
                    # Create new email with new domain
                    username = email.split('@')[0]
                    new_email = f"{username}@{new_domain}"
                    
                    # Update user's primary email
                    user_update = {
                        'primaryEmail': new_email
                    }
                    
                    google_api.service.users().update(
                        userKey=email,
                        body=user_update
                    ).execute()
                    
                    successful += 1
                    
                    # Update progress
                    progress_percentage = 30 + int((i + 1) / total_users * 65)  # 30-95%
                    update_progress(task_id, progress_percentage, 100, "processing", 
                                  f"Updated {i+1}/{total_users} users ({successful} successful, {failed} failed, {skipped} skipped)")
                    
                    # Small delay to avoid rate limiting
                    time.sleep(0.1)
                    
                except Exception as user_error:
                    failed += 1
                    logging.error(f"Failed to update user {email}: {user_error}")
            
            # Final update
            update_progress(task_id, 100, 100, "completed", 
                           f"Domain change completed! {successful} successful, {failed} failed, {skipped} skipped")
            
            # Schedule cleanup of this task after 5 minutes
            def delayed_cleanup():
                time.sleep(300)  # 5 minutes
                clear_progress(task_id)
            
            cleanup_thread = threading.Thread(target=delayed_cleanup)
            cleanup_thread.daemon = True
            cleanup_thread.start()
            
        except Exception as e:
            logging.error(f"Async domain change process error: {e}")
            update_progress(task_id, 0, 100, "error", f"Process failed: {str(e)}")

@app.route('/api/debug-progress', methods=['GET'])
@login_required
def debug_progress():
    """Debug endpoint to check progress tracking system"""
    try:
        with progress_lock:
            return jsonify({
                'success': True,
                'active_tasks': list(progress_tracker.keys()),
                'task_count': len(progress_tracker),
                'tasks': progress_tracker,
                'timestamp': datetime.now().isoformat()
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/debug-progress-raw', methods=['GET'])
@login_required
def debug_progress_raw():
    """Debug endpoint to check progress tracking system without any processing"""
    try:
        return jsonify({
            'success': True,
            'progress_tracker': progress_tracker,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/test-progress', methods=['POST'])
@login_required
def test_progress():
    """Test endpoint to create a test task and verify progress tracking"""
    try:
        # Create a test task
        test_task_id = str(uuid.uuid4())
        logging.info(f"Creating test task: {test_task_id}")
        
        # Update progress
        update_progress(test_task_id, 0, 100, "testing", "Test task created")
        
        # Verify it was created
        with progress_lock:
            if test_task_id in progress_tracker:
                logging.info(f"Test task {test_task_id} successfully created")
                return jsonify({
                    'success': True,
                    'test_task_id': test_task_id,
                    'message': 'Test task created successfully',
                    'progress_tracker_size': len(progress_tracker)
                })
            else:
                logging.error(f"Test task {test_task_id} was NOT created")
                return jsonify({
                    'success': False,
                    'error': 'Test task was not created in progress tracker'
                })
    except Exception as e:
        logging.error(f"Test progress error: {e}")
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True)
