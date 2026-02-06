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
        
        if not api_token:
            return jsonify({'success': False, 'error': 'API token is required'}), 400
        
        service = DigitalOceanService(api_token)
        success, message = service.test_connection()
        
        return jsonify({'success': success, 'message': message})
    except Exception as e:
        logger.error(f"Connection test error: {e}")
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
        
        if not api_token:
            return jsonify({'success': False, 'error': 'API token is required'}), 400
        
        config = DigitalOceanConfig.query.first()
        
        if not config:
            config = DigitalOceanConfig()
            db.session.add(config)
        
        config.name = data.get('name', 'Default DigitalOcean Account').strip()
        config.api_token = api_token
        config.default_region = data.get('default_region', 'nyc3').strip()
        config.default_size = data.get('default_size', 's-1vcpu-1gb').strip()
        config.automation_snapshot_id = data.get('automation_snapshot_id', '').strip() or None
        config.ssh_key_id = data.get('ssh_key_id', '').strip() or None
        config.ssh_private_key_path = data.get('ssh_private_key_path', '').strip() or None
        config.auto_destroy_droplets = data.get('auto_destroy_droplets', True)
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
    """Execute bulk automation on droplets (will implement in a future update)"""
    return jsonify({
        'success': False,
        'error': 'Bulk execution not yet implemented. This will be added in the next update.'
    }), 501
