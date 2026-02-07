"""
DigitalOcean Management routes for droplet creation, snapshot management,
and automation execution.
"""
import os
import json
import uuid
import logging
import threading
from datetime import datetime
from flask import Blueprint, request, jsonify, session, render_template
from functools import wraps
from database import db, DigitalOceanConfig, DigitalOceanDroplet, DigitalOceanExecution, AwsGeneratedPassword
from services.digitalocean_service import DigitalOceanService

logger = logging.getLogger(__name__)

digitalocean_manager = Blueprint('digitalocean_manager', __name__)


# Login required decorator
def login_required(f):
    """Decorator to require login"""
    from flask import redirect, url_for
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


def get_current_username():
    """Get current logged-in user's username"""
    username = session.get('user')
    if username:
        return username.split('@')[0].lower()
    return None


@digitalocean_manager.route('/digitalocean')
@login_required
def digitalocean_management():
    """DigitalOcean Management page"""
    return render_template('digitalocean_management.html', user=session.get('user'), role=session.get('role'))


# Configuration Routes
@digitalocean_manager.route('/api/do/test-connection', methods=['POST'])
@login_required
def test_connection():
    """Test DigitalOcean API connection"""
    try:
        data = request.get_json()
        api_token = data.get('api_token', '').strip()
        
        # If no token provided, try to use stored token
        if not api_token:
            config = DigitalOceanConfig.query.first()
            if config and config.api_token:
                api_token = config.api_token
            else:
                return jsonify({'success': False, 'error': 'API token is required'}), 400
        
        service = DigitalOceanService(api_token)
        account = service.get_account()
        
        if account:
            return jsonify({
                'success': True, 
                'message': f"Connected to account: {account.get('email', 'Unknown')}"
            })
        else:
            return jsonify({'success': False, 'error': 'Invalid API token'}), 400
    except Exception as e:
        logger.error(f"Test connection error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@digitalocean_manager.route('/api/do/config', methods=['GET'])
@login_required
def get_config():
    """Get DigitalOcean configuration"""
    try:
        config = DigitalOceanConfig.query.first()
        
        if not config:
            return jsonify({'success': True, 'config': None})
        
        return jsonify({
            'success': True,
            'config': {
                'id': config.id,
                'name': config.name,
                'api_token_masked': f"{config.api_token[:4]}***" if config.api_token else "",
                'default_region': config.default_region,
                'default_size': config.default_size,
                'automation_snapshot_id': config.automation_snapshot_id,
                'ssh_key_id': config.ssh_key_id,
                'auto_destroy_droplets': config.auto_destroy_droplets,
                'is_configured': config.is_configured
            }
        })
    except Exception as e:
        logger.error(f"Get config error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@digitalocean_manager.route('/api/do/config', methods=['POST'])
@login_required
def save_config():
    """Save DigitalOcean configuration"""
    try:
        data = request.get_json()
        api_token = data.get('api_token', '').strip()
        
        config = DigitalOceanConfig.query.first()
        
        # Validate token requirement
        if not config and not api_token:
            # New configuration requires token
            return jsonify({'success': False, 'error': 'API token is required for first-time setup'}), 400
        
        if not config:
            config = DigitalOceanConfig()
            db.session.add(config)
        
        config.name = data.get('name', 'Default DigitalOcean Account').strip()
        
        # Only update token if provided
        if api_token:
            config.api_token = api_token
        
        config.default_region = data.get('default_region', 'nyc3').strip()
        config.default_size = data.get('default_size', 's-1vcpu-1gb').strip()
        config.automation_snapshot_id = data.get('automation_snapshot_id', '').strip() or None
        config.ssh_key_id = data.get('ssh_key_id', '').strip() or None
        config.auto_destroy_droplets = data.get('auto_destroy_droplets', True)
        
        # Handle SSH private key
        ssh_private_key = data.get('ssh_private_key', '').strip()
        if ssh_private_key:
            import tempfile
            import os
            
            # Create temporary file for SSH key
            fd, key_path = tempfile.mkstemp(suffix='.pem', prefix='do_ssh_')
            with os.fdopen(fd, 'w') as f:
                f.write(ssh_private_key)
            
            # Set restrictive permissions
            try:
                os.chmod(key_path, 0o600)
            except:
                pass  # Windows doesn't support chmod
            
            config.ssh_private_key_path = key_path
        
        config.is_configured = True
        
        db.session.commit()
        
        logger.info(f"DigitalOcean config saved: {config.name}")
        return jsonify({'success': True, 'message': 'Configuration saved successfully'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Save config error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# Region and Size Routes
@digitalocean_manager.route('/api/do/regions', methods=['GET'])
@login_required
def list_regions():
    """List available DigitalOcean regions"""
    try:
        config = DigitalOceanConfig.query.first()
        if not config or not config.api_token:
            return jsonify({'success': False, 'error': 'DigitalOcean not configured'}), 400
        
        service = DigitalOceanService(config.api_token)
        regions = service.list_regions()
        
        return jsonify({'success': True, 'regions': regions})
    except Exception as e:
        logger.error(f"List regions error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@digitalocean_manager.route('/api/do/sizes', methods=['GET'])
@login_required
def list_sizes():
    """List available droplet sizes"""
    try:
        config = DigitalOceanConfig.query.first()
        if not config or not config.api_token:
            return jsonify({'success': False, 'error': 'DigitalOcean not configured'}), 400
        
        service = DigitalOceanService(config.api_token)
        sizes = service.list_sizes()
        
        return jsonify({'success': True, 'sizes': sizes})
    except Exception as e:
        logger.error(f"List sizes error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@digitalocean_manager.route('/api/do/regions-sizes', methods=['GET'])
@login_required
def list_regions_and_sizes():
    """List both regions and sizes in a single call for efficiency"""
    try:
        config = DigitalOceanConfig.query.first()
        if not config or not config.api_token:
            return jsonify({'success': False, 'error': 'DigitalOcean not configured'}), 400
        
        service = DigitalOceanService(config.api_token)
        
        # Get both regions and sizes
        regions = service.list_regions()
        sizes = service.list_sizes()
        
        return jsonify({
            'success': True,
            'regions': regions,
            'sizes': sizes
        })
    except Exception as e:
        logger.error(f"List regions/sizes error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# Droplet Routes
@digitalocean_manager.route('/api/do/droplets', methods=['GET'])
@login_required
def list_droplets():
    """List all droplets"""
    try:
        config = DigitalOceanConfig.query.first()
        if not config or not config.api_token:
            return jsonify({'success': False, 'error': 'DigitalOcean not configured'}), 400
       
        service = DigitalOceanService(config.api_token)
        droplets = service.list_droplets()
        
        # Also get droplets from database for tracking info
        db_droplets = {d.droplet_id: d for d in DigitalOceanDroplet.query.all()}
        
        # Merge data
        for droplet in droplets:
            db_droplet = db_droplets.get(droplet['id'])
            if db_droplet:
                droplet['assigned_users_count'] = db_droplet.assigned_users_count
                droplet['execution_task_id'] = db_droplet.execution_task_id
                droplet['auto_destroy'] = db_droplet.auto_destroy
        
        return jsonify({'success': True, 'droplets': droplets})
    except Exception as e:
        logger.error(f"List droplets error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@digitalocean_manager.route('/api/do/droplets/<droplet_id>', methods=['DELETE'])
@login_required
def delete_droplet(droplet_id):
    """Delete a droplet"""
    try:
        config = DigitalOceanConfig.query.first()
        if not config or not config.api_token:
            return jsonify({'success': False, 'error': 'DigitalOcean not configured'}), 400
        
        service = DigitalOceanService(config.api_token)
        success = service.delete_droplet(droplet_id)
        
        if success:
            # Update database
            db_droplet = DigitalOceanDroplet.query.filter_by(droplet_id=droplet_id).first()
            if db_droplet:
                db_droplet.status = 'destroyed'
                db_droplet.destroyed_at = datetime.utcnow()
                db.session.commit()
            
            return jsonify({'success': True, 'message': 'Droplet deleted successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to delete droplet'}), 500
    except Exception as e:
        logger.error(f"Delete droplet error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@digitalocean_manager.route('/api/do/droplets/create', methods=['POST'])
@login_required
def create_droplet():
    """Create a new droplet"""
    try:
        data = request.get_json()
        name = (data.get('name') or '').strip()
        region = (data.get('region') or '').strip()
        size = (data.get('size') or '').strip()
        image = data.get('image')  # Optional
        ssh_key = (data.get('ssh_key') or '').strip()
        
        if not name or not region or not size:
            return jsonify({'success': False, 'error': 'Name, region, and size are required'}), 400
        
        config = DigitalOceanConfig.query.first()
        if not config or not config.api_token:
            return jsonify({'success': False, 'error': 'DigitalOcean not configured. Please configure in Settings first.'}), 400
        
        # Get current username for droplet naming
        username = get_current_username() or 'user'
        
        # Create droplet name with username if not already included
        if username not in name.lower():
            full_name = f"{name}-{username}"
        else:
            full_name = name
            
        # Sanitize name to contain only valid hostname characters (a-z, A-Z, 0-9, . and -)
        import re
        full_name = re.sub(r'[^a-zA-Z0-9.-]', '-', full_name)
        # Remove consecutive hyphens and leading/trailing special chars
        full_name = re.sub(r'-+', '-', full_name).strip('.-')
        
        service = DigitalOceanService(config.api_token)
        
        # Use Ubuntu 22.04 as default image if not specified
        if not image:
            image = 'ubuntu-22-04-x64'
        
        # Create cloud-init script to automatically download and setup from GitHub
        github_repo = "https://github.com/Jetalp54/gbot-web-app-original-working.git"
        cloud_init_script = f"""#!/bin/bash
# Auto-setup from GitHub
apt-get update -y
apt-get install -y git curl

# Clone repository
git clone {github_repo} /tmp/gbot-setup

# Run setup script
if [ -f /tmp/gbot-setup/repo_digitalocean_files/setup_droplet.sh ]; then
    bash /tmp/gbot-setup/repo_digitalocean_files/setup_droplet.sh
    
    # Copy automation script
    if [ -f /tmp/gbot-setup/repo_digitalocean_files/do_automation.py ]; then
        cp /tmp/gbot-setup/repo_digitalocean_files/do_automation.py /opt/automation/
        chmod +x /opt/automation/do_automation.py
    fi
    
    touch /root/.setup_complete
    echo "Setup complete at $(date)" > /root/.setup_complete
fi

rm -rf /tmp/gbot-setup
"""
        
        # Convert SSH key string to list if provided
        ssh_keys_list = None
        if ssh_key:
            # For now, treat it as a raw key that needs to be added
            logger.warning("SSH key provided but needs to be pre-uploaded to DigitalOcean")
            
        # Get root password if provided
        root_password = (data.get('root_password') or '').strip()
        
        # If password provided, add to cloud-init
        if root_password:
            # Add password configuration to cloud-init
            password_script = f"""
# Set root password
echo "root:{root_password}" | chpasswd
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/g' /etc/ssh/sshd_config
systemctl restart sshd
"""
            cloud_init_script += password_script
            logger.info(f"Added root password configuration for droplet {full_name}")
        
        result, error_msg = service.create_droplet(
            name=full_name,
            region=region,
            size=size,
            image=image,
            ssh_keys=ssh_keys_list,
            user_data=cloud_init_script  # Auto-setup via cloud-init
        )
        
        if result and 'id' in result:
            droplet_id = result['id']
            
            # Wait for droplet to be active and get IP
            ip_address = service.wait_for_droplet_active(droplet_id, timeout=300)
            
            if ip_address:
                # Store in database
                db_droplet = DigitalOceanDroplet()
                db_droplet.droplet_id = str(droplet_id)
                db_droplet.droplet_name = full_name
                db_droplet.region = region
                db_droplet.size = size
                db_droplet.ip_address = ip_address
                db_droplet.status = 'active'
                db_droplet.created_by_username = username
                db_droplet.auto_destroy = config.auto_destroy_droplets
                
                db.session.add(db_droplet)
                db.session.commit()
                
                logger.info(f"Droplet created with auto-setup: {full_name} ({droplet_id}) by {username}")
                
                return jsonify({
                    'success': True,
                    'message': 'Droplet created successfully with auto-setup from GitHub',
                    'droplet_id': droplet_id,
                    'name': full_name,
                    'ip_address': ip_address,
                    'note': 'Cloud-init is running setup script. Wait 5-10 minutes before creating snapshot.'
                })
            else:
                return jsonify({'success': False, 'error': 'Droplet created but did not become active'}), 500
        else:
            return jsonify({'success': False, 'error': f"Failed to create droplet: {error_msg}"}), 500
            
    except Exception as e:
        db.session.rollback()
        logger.error(f"Create droplet error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@digitalocean_manager.route('/api/do/droplets/<droplet_id>/snapshot', methods=['POST'])
@login_required
def create_droplet_snapshot(droplet_id):
    """Create a snapshot from a specific droplet"""
    try:
        data = request.get_json()
        snapshot_name = data.get('name', '').strip()
        
        if not snapshot_name:
            return jsonify({'success': False, 'error': 'Snapshot name is required'}), 400
        
        config = DigitalOceanConfig.query.first()
        if not config or not config.api_token:
            return jsonify({'success': False, 'error': 'DigitalOcean not configured'}), 400
        
        service = DigitalOceanService(config.api_token)
        result = service.create_snapshot(droplet_id, snapshot_name)
        
        if result and result.get('action_id'):
            # Snapshot creation is async, return action ID
            action_id = result['action_id']
            logger.info(f"Snapshot creation started: {snapshot_name} (Action ID: {action_id}) from droplet {droplet_id}")
            
            return jsonify({
                'success': True,
                'message': 'Snapshot creation started',
                'snapshot_id': 'Running...', # Placeholder until complete
                'action_id': action_id
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to start snapshot creation'}), 500
            
    except Exception as e:
        logger.error(f"Create snapshot error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# Snapshot Routes
@digitalocean_manager.route('/api/do/snapshots', methods=['GET'])
@login_required
def list_snapshots():
    """List all snapshots"""
    try:
        config = DigitalOceanConfig.query.first()
        if not config or not config.api_token:
            return jsonify({'success': False, 'error': 'DigitalOcean not configured'}), 400
        
        service = DigitalOceanService(config.api_token)
        snapshots = service.list_snapshots()
        
        return jsonify({'success': True, 'snapshots': snapshots})
    except Exception as e:
        logger.error(f"List snapshots error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@digitalocean_manager.route('/api/do/snapshots/create', methods=['POST'])
@login_required
def create_snapshot():
    """Create a snapshot from a droplet"""
    try:
        data = request.get_json()
        droplet_id = data.get('droplet_id')
        snapshot_name = data.get('snapshot_name')
        
        if not droplet_id or not snapshot_name:
            return jsonify({'success': False, 'error': 'Droplet ID and snapshot name are required'}), 400
        
        config = DigitalOceanConfig.query.first()
        if not config or not config.api_token:
            return jsonify({'success': False, 'error': 'DigitalOcean not configured'}), 400
        
        service = DigitalOceanService(config.api_token)
        result = service.create_snapshot(droplet_id, snapshot_name)
        
        if result:
            return jsonify({'success': True, 'message': 'Snapshot creation started', 'action': result})
        else:
            return jsonify({'success': False, 'error': 'Failed to create snapshot'}), 500
    except Exception as e:
        logger.error(f"Create snapshot error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@digitalocean_manager.route('/api/do/snapshots/<snapshot_id>', methods=['DELETE'])
@login_required
def delete_snapshot(snapshot_id):
    """Delete a snapshot"""
    try:
        config = DigitalOceanConfig.query.first()
        if not config or not config.api_token:
            return jsonify({'success': False, 'error': 'DigitalOcean not configured'}), 400
        
        service = DigitalOceanService(config.api_token)
        success = service.delete_snapshot(snapshot_id)
        
        if success:
            return jsonify({'success': True, 'message': 'Snapshot deleted successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to delete snapshot'}), 500
    except Exception as e:
        logger.error(f"Delete snapshot error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# Execution Routes
@digitalocean_manager.route('/api/do/execute', methods=['POST'])
@login_required
def execute_automation():
    """Execute bulk automation on droplets"""
    try:
        data = request.get_json()
        
        # Get users list
        users = data.get('users', [])
        if not users:
            return jsonify({'success': False, 'error': 'No users provided'}), 400
        
        # Get execution parameters
        droplet_count = int(data.get('droplet_count', 1))
        snapshot_id = data.get('snapshot_id', '').strip()
        region = data.get('region', '').strip()
        size = data.get('size', '').strip()
        auto_destroy = data.get('auto_destroy', True)
        
        # Validation
        if droplet_count < 1:
            return jsonify({'success': False, 'error': 'Droplet count must be at least 1'}), 400
        
        if not snapshot_id:
            return jsonify({'success': False, 'error': 'Snapshot ID is required'}), 400
        
        # Get DO config
        config = DigitalOceanConfig.query.first()
        if not config or not config.api_token:
            return jsonify({'success': False, 'error': 'DigitalOcean not configured'}), 400
        
        # Use config defaults if not provided
        if not region:
            region = config.default_region or 'nyc3'
        if not size:
            size = config.default_size or 's-1vcpu-1gb'
        
        # Initialize service and orchestrator
        from services.digitalocean_bulk_executor import BulkExecutionOrchestrator
        service = DigitalOceanService(config.api_token)
        orchestrator = BulkExecutionOrchestrator(config.__dict__, service)
        
        # Create execution ID and DB record immediately
        import time
        execution_id = f"exec_{int(time.time())}"
        
        execution = DigitalOceanExecution()
        execution.task_id = execution_id
        execution.username = get_current_username()
        execution.total_users = len(users)
        execution.status = 'running'
        execution.snapshot_id = snapshot_id
        execution.region = region
        execution.size = size
        execution.started_at = datetime.utcnow()
        
        db.session.add(execution)
        db.session.commit()
        
        # Execute in background thread
        execution_thread = threading.Thread(
            target=_run_bulk_execution_background,
            args=(orchestrator, users, droplet_count, snapshot_id, region, size, auto_destroy, execution_id)
        )
        execution_thread.daemon = True
        execution_thread.start()
        
        return jsonify({
            'success': True,
            'message': 'Bulk execution started',
            'execution_id': execution_id,
            'total_users': len(users),
            'droplet_count': droplet_count
        })
        
    except Exception as e:
        logger.error(f"Execute automation error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


def _run_bulk_execution_background(
    orchestrator,
    users,
    droplet_count,
    snapshot_id,
    region,
    size,
    auto_destroy,
    execution_id
):
    """Background task for bulk execution"""
    # Create a new app context for the thread
    from app import app
    with app.app_context():
        try:
            logger.info(f"THREAD START [{execution_id}]: Starting background execution for {len(users)} users")
            
            # Check if we can see the DB record
            check_exec = DigitalOceanExecution.query.filter_by(task_id=execution_id).first()
            if not check_exec:
                logger.error(f"THREAD ERROR [{execution_id}]: Execution record NOT FOUND in DB at start!")
            else:
                logger.info(f"THREAD DEBUG [{execution_id}]: Found DB record, status={check_exec.status}")

            result = orchestrator.execute_bulk(
                users=users,
                droplet_count=droplet_count,
                snapshot_id=snapshot_id,
                region=region,
                size=size,
                auto_destroy=auto_destroy,
                execution_id=execution_id
            )
            
            logger.info(f"THREAD RESULT [{execution_id}]: Orchestrator finished. Success={result.get('success')}, Error={result.get('error')}")

            # Update results in database
            execution = DigitalOceanExecution.query.filter_by(task_id=execution_id).first()
            if execution:
                execution.droplets_created = result.get('droplets_used', 0)
                execution.success_count = result.get('success_count', 0)
                execution.failure_count = result.get('fail_count', 0)
                execution.results_json = json.dumps(result.get('results', []))
                execution.status = 'completed' if result['success'] else 'failed'
                execution.error_message = result.get('error')
                execution.completed_at = datetime.utcnow()
                
                db.session.commit()
                logger.info(f"THREAD SUCCESS [{execution_id}]: DB updated successfully")
            else:
                logger.error(f"THREAD ERROR [{execution_id}]: Execution record lost during processing!")
            
        except Exception as e:
            logger.error(f"THREAD EXCEPTION [{execution_id}]: {e}", exc_info=True)
            # Try to update status to failed
            try:
                execution = DigitalOceanExecution.query.filter_by(task_id=execution_id).first()
                if execution:
                    execution.status = 'failed'
                    execution.error_message = f"Internal Error: {str(e)}"
                    execution.completed_at = datetime.utcnow()
                    db.session.commit()
                    logger.info(f"THREAD RECOVERY [{execution_id}]: Updated status to failed")
            except Exception as db_e:
                 logger.error(f"THREAD FATAL [{execution_id}]: Could not update DB after exception: {db_e}")


@digitalocean_manager.route('/api/do/execution/<execution_id>/status', methods=['GET'])
@login_required
def get_execution_status(execution_id):
    """Get status of a bulk execution"""
    try:
        execution = DigitalOceanExecution.query.filter_by(task_id=execution_id).first()
        if not execution:
            return jsonify({'success': False, 'error': 'Execution not found'}), 404
            
        return jsonify({
            'success': True,
            'status': execution.status,
            'droplets_created': execution.droplets_created,
            'success_count': execution.success_count,
            'failure_count': execution.failure_count,
            'error_message': execution.error_message,
            'completed': execution.status in ['completed', 'failed']
        })
    except Exception as e:
        logger.error(f"Get execution status error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@digitalocean_manager.route('/api/do/generated-passwords/<execution_id>', methods=['GET'])
@login_required
def get_generated_passwords(execution_id):
    """Fetch generated passwords from specific execution via backup files"""
    try:
        backup_dir = 'do_app_passwords_backup'
        
        if not os.path.exists(backup_dir):
            return jsonify({
                'success': True,
                'passwords': []
            })
        
        # Find all backup files matching this execution
        pattern = f"{execution_id}_*.json"
        backup_files = []
        
        for filename in os.listdir(backup_dir):
            if filename.startswith(f"{execution_id}_") and filename.endswith('.json'):
                backup_files.append(os.path.join(backup_dir, filename))
        
        if not backup_files:
            return jsonify({
                'success': True,
                'passwords': []
            })
        
        # Load passwords from backup files
        passwords = []
        for filepath in backup_files:
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                
                passwords.append({
                    'email': data.get('email'),
                    'app_password': data.get('app_password'),
                    'created_at': data.get('timestamp'),
                    'updated_at': data.get('db_save_timestamp'),
                    'saved_to_db': data.get('saved_to_db', False)
                })
            except Exception as e:
                logger.error(f"Error reading backup file {filepath}: {e}")
                continue
        
        # Sort by email
        passwords.sort(key=lambda x: x['email'])
        
        return jsonify({
            'success': True,
            'execution_id': execution_id,
            'passwords': passwords
        })
        
    except Exception as e:
        logger.error(f"Error fetching passwords for execution {execution_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
